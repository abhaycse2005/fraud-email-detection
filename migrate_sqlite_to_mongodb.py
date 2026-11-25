"""Copy the legacy SQLite records to Atlas without changing the SQLite file.

Run explicitly after configuring a valid MONGODB_URI. The app itself does not
read SQLite; this one-time utility opens the existing file read-only.
"""

import json
import os
import sqlite3
from datetime import datetime, timezone

from bson import ObjectId
from pymongo.errors import DuplicateKeyError

import database as db


SQLITE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fraud_detection.db")


def _mongo_datetime(value):
    if not value:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return value
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def migrate():
    if not os.path.isfile(SQLITE_PATH):
        raise RuntimeError("The existing SQLite database file was not found; no data was changed.")

    # Establish and verify the Mongo destination before reading or writing records.
    db.init_db()
    db.detections_collection.create_index("legacy_sqlite_id", unique=True, sparse=True)

    source = sqlite3.connect(f"file:{SQLITE_PATH}?mode=ro", uri=True)
    source.row_factory = sqlite3.Row
    try:
        tables = {row[0] for row in source.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        user_rows = source.execute("SELECT * FROM users").fetchall() if "users" in tables else []
        detection_rows = source.execute("SELECT * FROM detections").fetchall() if "detections" in tables else []
        gmail_rows = source.execute("SELECT * FROM gmail_connections").fetchall() if "gmail_connections" in tables else []

        user_id_map = {}
        for row in user_rows:
            user = dict(row)
            legacy_id = str(user.pop("id"))
            existing = db.users_collection.find_one({"email": user["email"].strip().lower()})
            if existing:
                mongo_id = existing["_id"]
            else:
                user["email"] = user["email"].strip().lower()
                user["created_at"] = _mongo_datetime(user.get("created_at"))
                user["_id"] = ObjectId()
                try:
                    db.users_collection.insert_one(user)
                    mongo_id = user["_id"]
                except DuplicateKeyError:
                    existing = db.users_collection.find_one({"email": user["email"]})
                    if not existing:
                        raise
                    mongo_id = existing["_id"]
            user_id_map[legacy_id] = str(mongo_id)

        copied_detections = 0
        for row in detection_rows:
            detection = dict(row)
            legacy_id = str(detection.pop("id"))
            detection["legacy_sqlite_id"] = legacy_id
            detection["user_id"] = user_id_map.get(str(detection.get("user_id")),
                                                   str(detection.get("user_id", "")))
            detection["created_at"] = _mongo_datetime(detection.get("created_at"))
            if isinstance(detection.get("signals"), str):
                try:
                    detection["signals"] = json.loads(detection["signals"])
                except json.JSONDecodeError:
                    detection["signals"] = []
            external_id = detection.get("external_message_id")
            if external_id and db.detections_collection.find_one(
                {"user_id": detection["user_id"], "external_message_id": external_id},
                {"_id": 1},
            ):
                # A Gmail message already imported by the app is already preserved.
                continue
            db.detections_collection.update_one(
                {"legacy_sqlite_id": legacy_id},
                {"$setOnInsert": detection},
                upsert=True,
            )
            copied_detections += 1

        copied_gmail = 0
        for row in gmail_rows:
            connection = dict(row)
            old_user_id = str(connection.pop("user_id"))
            user_id = user_id_map.get(old_user_id, old_user_id)
            document = {
                "user_id": user_id,
                "email": connection.get("email", ""),
                "token_ciphertext": connection.get("token_ciphertext", ""),
                "connected_at": _mongo_datetime(connection.get("connected_at")),
                "last_scan_epoch": connection.get("last_scan_epoch"),
            }
            db.gmail_connections_collection.update_one(
                {"user_id": user_id}, {"$setOnInsert": document}, upsert=True,
            )
            copied_gmail += 1

        print(
            "Migration finished. "
            f"Users checked: {len(user_rows)}; detections checked: {copied_detections}; "
            f"Gmail connections checked: {copied_gmail}. SQLite source was left unchanged."
        )
    finally:
        source.close()


if __name__ == "__main__":
    try:
        migrate()
    except db.DatabaseConnectionError as error:
        raise SystemExit(f"Migration stopped: {error}") from None
    except Exception as error:
        raise SystemExit(
            f"Migration stopped ({error.__class__.__name__}). SQLite source was not modified; "
            "rerun after correcting the Atlas issue."
        ) from None
