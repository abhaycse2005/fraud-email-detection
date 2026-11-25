import logging
import unittest
from unittest.mock import Mock, patch

import requests

import atlas_ip_allowlist as updater


PROJECT_ID = "0123456789abcdef01234567"
CONFIG = {
    "MONGODB_ATLAS_PUBLIC_KEY": "public-test-key",
    "MONGODB_ATLAS_PRIVATE_KEY": "private-test-secret",
    "MONGODB_ATLAS_PROJECT_ID": PROJECT_ID,
}


class FakeResponse:
    def __init__(self, text="", payload=None, status=200):
        self.text = text
        self.payload = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            error = requests.HTTPError("private API response details")
            error.response = self
            raise error

    def json(self):
        return self.payload


class AtlasAllowlistTests(unittest.TestCase):
    def test_public_ipv4_parser_rejects_invalid_and_non_public_addresses(self):
        self.assertEqual(str(updater.parse_public_ipv4(" 8.8.8.8\n")), "8.8.8.8")
        for value in ("not-an-ip", "192.168.1.3", "2001:4860:4860::8888"):
            with self.subTest(value=value):
                with self.assertRaises(updater.AllowlistUpdateError):
                    updater.parse_public_ipv4(value)

    def test_missing_credentials_name_variables_without_exposing_values(self):
        with self.assertRaises(updater.AllowlistUpdateError) as raised:
            updater.update_allowlist(environ={})
        self.assertIn("MONGODB_ATLAS_PUBLIC_KEY", str(raised.exception))
        self.assertNotIn("private-test-secret", str(raised.exception))

    def test_existing_exact_or_containing_entry_is_not_modified(self):
        http = Mock()
        # Documentation-only TEST-NET IPs aren't globally routable; bypass the
        # detector's parser here so the allowlist membership logic is isolated.
        with patch.object(updater, "detect_public_ipv4", return_value=updater.ipaddress.ip_address("8.8.8.8")):
            http.get.side_effect = [
                FakeResponse(payload={"results": [{"cidrBlock": "8.8.8.0/24", "groupId": PROJECT_ID}], "totalCount": 1})
            ]
            address, added = updater.update_allowlist(CONFIG, http)
        self.assertEqual(str(address), "8.8.8.8")
        self.assertFalse(added)
        http.post.assert_not_called()

    def test_changed_ip_adds_only_single_ip_and_verifies_it(self):
        http = Mock()
        http.get.side_effect = [
            FakeResponse(payload={"results": [], "totalCount": 0}),
            FakeResponse(payload={"results": [{"ipAddress": "8.8.4.4", "groupId": PROJECT_ID}], "totalCount": 1}),
        ]
        with patch.object(updater, "detect_public_ipv4", return_value=updater.ipaddress.ip_address("8.8.4.4")):
            address, added = updater.update_allowlist(CONFIG, http)
        self.assertEqual(str(address), "8.8.4.4")
        self.assertTrue(added)
        self.assertEqual(http.post.call_args.kwargs["json"], [{
            "cidrBlock": "8.8.4.4/32", "comment": "Fraud Email Detection app workstation",
        }])
        self.assertEqual(http.post.call_args.kwargs["timeout"], updater.HTTP_TIMEOUT_SECONDS)

    def test_ip_detection_timeout_fails_safely(self):
        http = Mock()
        http.get.side_effect = requests.Timeout("private timeout")
        with self.assertRaisesRegex(updater.AllowlistUpdateError, "timed out"):
            updater.detect_public_ipv4(http)

    def test_atlas_api_forbidden_error_is_sanitized_and_does_not_post(self):
        http = Mock()
        forbidden = FakeResponse(status=403)
        http.get.side_effect = [forbidden]
        with self.assertLogs("atlas_ip_allowlist", level=logging.ERROR) as captured:
            with self.assertRaises(updater.AllowlistUpdateError) as raised:
                with patch.object(updater, "detect_public_ipv4", return_value=updater.ipaddress.ip_address("8.8.8.8")):
                    updater.update_allowlist(CONFIG, http)
            updater.logger.error("%s", raised.exception)
        output = " ".join(captured.output) + str(raised.exception)
        self.assertIn("permission", output)
        self.assertNotIn("private-test-secret", output)
        self.assertNotIn("private API response details", output)
        http.post.assert_not_called()

    def test_atlas_api_timeout_is_clear_and_safe(self):
        http = Mock()
        http.get.side_effect = requests.Timeout("private API secret detail")
        with self.assertRaisesRegex(updater.AllowlistUpdateError, "timed out") as raised:
            updater._api_request(
                http, "get", "https://cloud.mongodb.com/test",
                auth=Mock(), headers={},
            )
        self.assertNotIn("private API secret detail", str(raised.exception))

    def test_project_response_mismatch_fails_before_modification(self):
        http = Mock()
        http.get.return_value = FakeResponse(payload={
            "results": [{"ipAddress": "8.8.8.8", "groupId": "ffffffffffffffffffffffff"}],
            "totalCount": 1,
        })
        with patch.object(updater, "detect_public_ipv4", return_value=updater.ipaddress.ip_address("1.1.1.1")):
            with self.assertRaisesRegex(updater.AllowlistUpdateError, "did not match"):
                updater.update_allowlist(CONFIG, http)
        http.post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
