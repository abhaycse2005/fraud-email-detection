"""Explicitly add this machine's public IPv4 to one Atlas project allowlist.

This utility is separate from Flask startup and never connects to or changes
MongoDB data. It only reads and adds project IP access-list entries.
"""

import ipaddress
import logging
import os
import re
import sys
from pathlib import Path

import requests
from dotenv import load_dotenv
from requests.auth import HTTPDigestAuth


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

ATLAS_API_BASE = "https://cloud.mongodb.com/api/atlas/v2"
ATLAS_API_VERSION = "application/vnd.atlas.2025-02-19+json"
PUBLIC_IP_URL = "https://api.ipify.org"
HTTP_TIMEOUT_SECONDS = 10
PROJECT_ID_RE = re.compile(r"^[a-fA-F0-9]{24}$")
logger = logging.getLogger("atlas_ip_allowlist")


class AllowlistUpdateError(RuntimeError):
    """A safe, user-facing allowlist configuration or update failure."""


def parse_public_ipv4(value):
    """Validate a response as a globally routable IPv4 address."""
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError as error:
        raise AllowlistUpdateError("The public IP service returned an invalid IP address.") from error
    if not isinstance(address, ipaddress.IPv4Address) or not address.is_global:
        raise AllowlistUpdateError("The public IP service did not return a public IPv4 address.")
    return address


def detect_public_ipv4(http=requests):
    """Detect public IPv4; never infer it from a local network interface."""
    try:
        response = http.get(PUBLIC_IP_URL, timeout=HTTP_TIMEOUT_SECONDS)
        response.raise_for_status()
    except requests.Timeout as error:
        raise AllowlistUpdateError("Public IP detection timed out. Check internet connectivity and retry.") from error
    except requests.RequestException as error:
        raise AllowlistUpdateError("Public IP detection failed. Check internet connectivity and retry.") from error
    return parse_public_ipv4(response.text)


def _configuration(environ=None):
    environ = os.environ if environ is None else environ
    names = (
        "MONGODB_ATLAS_PUBLIC_KEY",
        "MONGODB_ATLAS_PRIVATE_KEY",
        "MONGODB_ATLAS_PROJECT_ID",
    )
    values = {name: environ.get(name, "").strip() for name in names}
    missing = [name for name, value in values.items() if not value]
    if missing:
        raise AllowlistUpdateError("Missing required environment variable(s): " + ", ".join(missing))
    if not PROJECT_ID_RE.fullmatch(values["MONGODB_ATLAS_PROJECT_ID"]):
        raise AllowlistUpdateError("MONGODB_ATLAS_PROJECT_ID must be a 24-character Atlas project ID.")
    return values


def _api_request(http, method, url, *, auth, headers, **kwargs):
    try:
        response = getattr(http, method)(
            url, auth=auth, headers=headers, timeout=HTTP_TIMEOUT_SECONDS, **kwargs
        )
        response.raise_for_status()
        return response
    except requests.Timeout as error:
        raise AllowlistUpdateError("Atlas Admin API request timed out. No app startup was attempted.") from error
    except requests.RequestException as error:
        status = getattr(getattr(error, "response", None), "status_code", None)
        if status in (401, 403):
            message = "Atlas rejected the API credentials or project IP access-list permission."
        elif status == 404:
            message = "Atlas project was not found or is unavailable to this API key."
        elif status == 429:
            message = "Atlas Admin API rate limit was reached. Wait and retry."
        else:
            message = "Atlas Admin API request failed. Check network access and project configuration."
        raise AllowlistUpdateError(message) from error


def _get_all_entries(http, url, auth, headers, project_id):
    entries = []
    page_num = 1
    total_count = None
    while total_count is None or len(entries) < total_count:
        response = _api_request(
            http, "get", url, auth=auth, headers=headers,
            params={"itemsPerPage": 500, "pageNum": page_num},
        )
        try:
            payload = response.json()
        except (ValueError, AttributeError) as error:
            raise AllowlistUpdateError("Atlas returned an invalid IP access-list response.") from error
        page_entries = payload.get("results") if isinstance(payload, dict) else None
        if not isinstance(page_entries, list):
            raise AllowlistUpdateError("Atlas returned an invalid IP access-list response.")
        if page_entries and any(
            entry.get("groupId") not in (None, project_id)
            for entry in page_entries if isinstance(entry, dict)
        ):
            raise AllowlistUpdateError("Atlas IP access-list response did not match the configured project.")
        if any(not isinstance(entry, dict) for entry in page_entries):
            raise AllowlistUpdateError("Atlas returned an invalid IP access-list entry.")
        entries.extend(page_entries)
        count = payload.get("totalCount", len(entries))
        if not isinstance(count, int) or count < len(entries):
            total_count = len(entries)
        else:
            total_count = count
        if not page_entries and len(entries) < total_count:
            raise AllowlistUpdateError("Atlas returned an incomplete IP access-list response.")
        page_num += 1
        if page_num > 20:
            raise AllowlistUpdateError("Atlas IP access-list response exceeded the safe page limit.")
    return entries


def _address_is_allowlisted(address, entries):
    for entry in entries:
        value = entry.get("ipAddress") or entry.get("cidrBlock")
        if not value:
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if address in network:
            return True
    return False


def update_allowlist(environ=None, http=requests):
    """Ensure current public IPv4 is present; add and verify only when needed.

    Returns ``(address, added)``. An existing entry is never changed or removed.
    """
    config = _configuration(environ)
    address = detect_public_ipv4(http)
    project_id = config["MONGODB_ATLAS_PROJECT_ID"]
    url = f"{ATLAS_API_BASE}/groups/{project_id}/accessList"
    auth = HTTPDigestAuth(config["MONGODB_ATLAS_PUBLIC_KEY"], config["MONGODB_ATLAS_PRIVATE_KEY"])
    headers = {"Accept": ATLAS_API_VERSION, "Content-Type": "application/json"}

    # Verify the configured project is reachable and inspect its existing list
    # before making any change. The endpoint is project-scoped by project_id.
    entries = _get_all_entries(http, url, auth, headers, project_id)
    if _address_is_allowlisted(address, entries):
        return address, False

    _api_request(
        http, "post", url, auth=auth, headers=headers,
        json=[{"cidrBlock": f"{address}/32", "comment": "Fraud Email Detection app workstation"}],
    )
    verified_entries = _get_all_entries(http, url, auth, headers, project_id)
    if not _address_is_allowlisted(address, verified_entries):
        raise AllowlistUpdateError("Atlas did not confirm the new IP access-list entry. Flask was not started.")
    return address, True


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    try:
        address, added = update_allowlist()
    except AllowlistUpdateError as error:
        logger.error("Atlas IP allowlist update failed: %s", error)
        return 1
    if added:
        logger.info("Added and verified the current public IPv4 in the configured Atlas project.")
    else:
        logger.info("Current public IPv4 is already allowlisted; no change was made.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
