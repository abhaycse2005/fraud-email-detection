import os
import re
import unittest
from datetime import datetime, timezone
from io import BytesIO
from unittest.mock import MagicMock, Mock, patch

import app as flask_app
import database
from pymongo.errors import ConfigurationError, DuplicateKeyError, ServerSelectionTimeoutError
from bson import ObjectId


class Cursor:
    def __init__(self, rows):
        self.rows = list(rows)

    def sort(self, field, direction):
        self.rows.sort(key=lambda row: row.get(field), reverse=direction < 0)
        return self

    def limit(self, count):
        self.rows = self.rows[:count]
        return self

    def __iter__(self):
        return iter(self.rows)


def matches(document, query):
    for key, expected in query.items():
        actual = document.get(key)
        if isinstance(expected, dict):
            if "$in" in expected and actual not in expected["$in"]:
                return False
            if "$exists" in expected and ((key in document) != expected["$exists"]):
                return False
        elif actual != expected:
            return False
    return True


class FakeMongoDetections:
    """In-memory Mongo collection that records query filters for assertions."""

    def __init__(self, documents):
        self.documents = [doc.copy() for doc in documents]
        self.find_queries = []
        self.count_queries = []
        self.aggregate_queries = []

    def find(self, query=None, projection=None):
        query = query or {}
        self.find_queries.append(query)
        return Cursor([doc.copy() for doc in self.documents if matches(doc, query)])

    def count_documents(self, query):
        self.count_queries.append(query)
        return sum(matches(doc, query) for doc in self.documents)

    def aggregate(self, pipeline):
        self.aggregate_queries.append(pipeline)
        return []


SAMPLE_DETECTIONS = [
    {"_id": "a1", "user_id": "user-a", "sender_email": "a@example.test",
     "subject": "A safe", "content": "private A", "prediction": "Safe",
     "risk_level": "Low", "risk_score": 1, "signals": [], "confidence": 90,
     "created_at": "2026-10-01T10:00:00Z"},
    {"_id": "a2", "user_id": "user-a", "sender_email": "a@example.test",
     "subject": "A fraud", "content": "private A2", "prediction": "Fraudulent",
     "risk_level": "High", "risk_score": 90, "signals": ["link"], "confidence": 95,
     "threat_category": "Phishing Links", "created_at": "2026-10-02T10:00:00Z"},
    {"_id": "b1", "user_id": "user-b", "sender_email": "b@example.test",
     "subject": "B suspicious", "content": "private B", "prediction": "Suspicious",
     "risk_level": "Medium", "risk_score": 50, "signals": [], "confidence": 75,
     "threat_category": "Sender Spoofing", "created_at": "2026-10-03T10:00:00Z"},
]


def csrf_headers(client):
    page = client.get("/login").get_data(as_text=True)
    token = re.search(r'<meta name="csrf-token" content="([^"]+)"', page).group(1)
    return {"X-CSRF-Token": token}


class MongoOnlyInitializationTests(unittest.TestCase):
    def test_deferred_count_is_persisted_separately_from_actual_failures(self):
        collection = Mock()
        with patch.object(database, "gmail_connections_collection", collection):
            database.update_gmail_scan_status(
                "user-a", "error", scanned=3, failed=3, deferred=201,
                error_category="gemini_provider_unavailable", http_status=503,
            )

        values = collection.update_one.call_args.args[1]["$set"]
        self.assertEqual(values["last_scan_failed_count"], 3)
        self.assertEqual(values["last_scan_deferred_count"], 201)
        self.assertEqual(values["last_scan_http_status"], 503)

    def test_dotenv_path_is_explicit_and_resolved_from_project_directory(self):
        self.assertTrue(database.ENV_PATH.endswith(os.path.join("fraud-email-detection", ".env")))
        self.assertTrue(os.path.isabs(database.ENV_PATH))

    def test_live_gmail_progress_does_not_move_the_durable_page_cursor(self):
        collection = Mock()
        with patch.object(database, "gmail_connections_collection", collection):
            database.update_gmail_scan_progress(
                "user-a", page_token="resume-page", processed=25,
                total=201, historical=True,
            )
            database.update_gmail_scan_live_progress(
                "user-a", processed=28, total=201, historical=True, failed=2,
                successful=26, deferred=2,
            )

        durable_update = collection.update_one.call_args_list[0]
        live_update = collection.update_one.call_args_list[1]
        self.assertEqual(durable_update.args[0], {"user_id": "user-a"})
        self.assertEqual(durable_update.args[1]["$set"]["historical_page_token"], "resume-page")
        self.assertEqual(durable_update.args[1]["$set"]["scan_progress_checkpoint_count"], 25)
        self.assertEqual(live_update.args[0], {"user_id": "user-a"})
        self.assertEqual(live_update.args[1]["$set"]["scan_progress_count"], 28)
        self.assertEqual(live_update.args[1]["$set"]["scan_progress_failed_count"], 2)
        self.assertEqual(live_update.args[1]["$set"]["scan_progress_success_count"], 26)
        self.assertEqual(live_update.args[1]["$set"]["scan_progress_deferred_count"], 2)
        self.assertNotIn("historical_page_token", live_update.args[1]["$set"])
        self.assertNotIn("scan_progress_checkpoint_count", live_update.args[1]["$set"])

    def test_missing_uri_fails_without_sqlite_fallback(self):
        with patch.object(database, "MONGODB_URI", ""), patch.object(database, "client", None):
            with self.assertRaisesRegex(database.DatabaseConnectionError, "MONGODB_URI is missing"):
                database.init_db()
        self.assertFalse(hasattr(database, "_sqlite_connection"))

    def test_invalid_uri_is_reported_without_echoing_connection_details(self):
        with patch.object(database, "MONGODB_URI", "mongodb://credential-must-not-appear"), \
             patch.object(database, "client", None), \
             patch.object(database, "MongoClient", side_effect=ValueError("hidden connection text")):
            with self.assertRaises(database.DatabaseConnectionError) as raised:
                database.init_db()
        self.assertIn("ValueError", str(raised.exception))
        self.assertNotIn("credential-must-not-appear", str(raised.exception))
        self.assertNotIn("hidden connection text", str(raised.exception))

    def test_srv_dns_failure_is_distinguished_without_echoing_hostname(self):
        with patch.object(database, "MONGODB_URI", "mongodb+srv://private-host"), \
             patch.object(database, "client", None), \
             patch.object(database.time, "sleep"), \
             patch.object(database, "MongoClient", side_effect=ConfigurationError(
                 "DNS query timed out for _mongodb._tcp.private-host")):
            with self.assertRaises(database.DatabaseConnectionError) as raised:
                database.init_db()
        self.assertIn("resolve the MongoDB Atlas cluster through DNS", str(raised.exception))
        self.assertNotIn("private-host", str(raised.exception))

    def test_idna_failure_is_not_misreported_as_a_malformed_uri(self):
        with patch.object(database, "MONGODB_URI", "mongodb+srv://private-host"), \
             patch.object(database, "client", None), \
             patch.object(database, "MongoClient", side_effect=ConfigurationError(
                 "IDNA processing exception: invalid codepoint")):
            with self.assertRaises(database.DatabaseConnectionError) as raised:
                database.init_db()
        self.assertIn("encode a hostname", str(raised.exception))
        self.assertIn("computer name", str(raised.exception))
        self.assertNotIn("URI format", str(raised.exception))
        self.assertNotIn("private-host", str(raised.exception))
        self.assertFalse(raised.exception.retryable)

    def test_unavailable_mongo_fails_clearly_and_never_initializes_another_database(self):
        fake_client = Mock()
        fake_client.admin.command.side_effect = ServerSelectionTimeoutError("private host timeout")
        with patch.object(database, "MONGODB_URI", "mongodb://test.invalid"), \
             patch.object(database, "client", fake_client), \
             patch.object(database.time, "sleep"), \
             patch.object(database, "users_collection") as users, \
             patch.object(database, "detections_collection") as detections:
            with self.assertRaisesRegex(database.DatabaseConnectionError, "Could not connect to MongoDB Atlas"):
                database.init_db()
        users.create_index.assert_not_called()
        detections.create_index.assert_not_called()
        self.assertFalse(hasattr(database, "_init_sqlite"))
        self.assertEqual(fake_client.admin.command.call_count, database.MAX_STARTUP_ATTEMPTS)

    def test_startup_succeeds_after_a_temporary_atlas_connection_failure(self):
        fake_client = Mock()
        fake_client.admin.command.side_effect = [
            ServerSelectionTimeoutError("private host timeout"), None,
        ]
        with patch.object(database, "MONGODB_URI", "mongodb://test.invalid"), \
             patch.object(database, "client", fake_client), \
             patch.object(database, "users_collection") as users, \
             patch.object(database, "detections_collection") as detections, \
             patch.object(database.time, "sleep") as sleep:
            database.init_db()
        self.assertEqual(fake_client.admin.command.call_count, 2)
        sleep.assert_called_once_with(database.STARTUP_RETRY_DELAY_SECONDS)
        users.create_index.assert_called_once_with("email", unique=True)
        detections.create_index.assert_any_call([("created_at", database.DESCENDING)])

    def test_startup_logs_five_sanitized_attempts_then_raises(self):
        fake_client = Mock()
        fake_client.admin.command.side_effect = ServerSelectionTimeoutError(
            "mongodb://secret-user:secret-password@private-cluster"
        )
        with patch.object(database, "MONGODB_URI", "mongodb://test.invalid"), \
             patch.object(database, "client", fake_client), \
             patch.object(database.time, "sleep") as sleep, \
             self.assertLogs("database", level="WARNING") as captured:
            with self.assertRaises(database.DatabaseConnectionError) as raised:
                database.init_db()
        self.assertEqual(fake_client.admin.command.call_count, 5)
        self.assertEqual(sleep.call_count, 4)
        logs = " ".join(captured.output)
        self.assertEqual(logs.count("failed (retryable="), 5)
        self.assertNotIn("secret-user", logs)
        self.assertNotIn("secret-password", logs)
        self.assertNotIn("private-cluster", logs)
        self.assertNotIn("secret-password", str(raised.exception))

    def test_successful_mongo_ping_initializes_mongo_collections(self):
        fake_client = Mock()
        users = Mock()
        users.find_one.return_value = {"_id": "existing-admin"}
        detections = Mock()
        with patch.object(database, "MONGODB_URI", "mongodb://test.invalid"), \
             patch.object(database, "client", fake_client), \
             patch.object(database, "users_collection", users), \
             patch.object(database, "detections_collection", detections):
            database.init_db()
        fake_client.admin.command.assert_called_once_with("ping")
        users.create_index.assert_called_once_with("email", unique=True)
        detections.create_index.assert_any_call([("created_at", database.DESCENDING)])
        self.assertFalse(hasattr(database, "_sqlite_connection"))

    def test_mongo_client_supports_standard_and_srv_uris_with_secure_options(self):
        # Placeholder-only URIs: never use credentials or the configured .env URI.
        for uri in (
            "mongodb://user:password@node1.example.test:27017,node2.example.test:27017/"
            "?replicaSet=sample-rs&authSource=admin",
            "mongodb+srv://user:password@cluster.example.test/",
        ):
            with self.subTest(uri_scheme=uri.split(":", 1)[0]):
                fake_client = MagicMock()
                fake_db = MagicMock()
                fake_users, fake_detections, fake_gmail = Mock(), Mock(), Mock()
                fake_client.__getitem__.return_value = fake_db
                fake_db.__getitem__.side_effect = {
                    "users": fake_users,
                    "detections": fake_detections,
                    "gmail_connections": fake_gmail,
                }.__getitem__
                with patch.object(database, "MONGODB_URI", uri), \
                     patch.object(database, "client", None), \
                     patch.object(database, "db", None), \
                     patch.object(database, "users_collection", None), \
                     patch.object(database, "detections_collection", None), \
                     patch.object(database, "gmail_connections_collection", None), \
                     patch.object(database, "MongoClient", return_value=fake_client) as create_client:
                    database.init_db()

                args, kwargs = create_client.call_args
                self.assertEqual(args[0], uri)
                self.assertIs(kwargs["tls"], True)
                self.assertEqual(kwargs["tlsCAFile"], database.certifi.where())
                self.assertIs(kwargs["retryReads"], True)
                self.assertIs(kwargs["retryWrites"], True)
                self.assertEqual(kwargs["serverSelectionTimeoutMS"], 10_000)
                self.assertEqual(kwargs["connectTimeoutMS"], 10_000)
                self.assertEqual(kwargs["socketTimeoutMS"], 10_000)


class UserIsolationTests(unittest.TestCase):
    def test_duplicate_gmail_detection_write_is_not_replayed(self):
        collection = Mock()
        collection.insert_one.side_effect = DuplicateKeyError("duplicate key")
        with patch.object(database, "detections_collection", collection):
            result = database.insert_detection(
                user_id="user-a", sender_email="sender@example.test", subject="Subject",
                content="Body", prediction="Safe", risk_level="Low", confidence=90,
                threat_category=None, external_message_id="gmail-message-123",
            )
        self.assertIsNone(result)
        collection.insert_one.assert_called_once()

    def test_mongo_history_recent_and_stats_are_user_scoped(self):
        collection = FakeMongoDetections(SAMPLE_DETECTIONS)
        with patch.object(database, "detections_collection", collection):
            for user_id, expected_subjects, expected_counts in [
                ("user-a", {"A safe", "A fraud"}, (2, 1, 0, 1)),
                ("user-b", {"B suspicious"}, (1, 0, 1, 0)),
            ]:
                with self.subTest(user_id=user_id):
                    history = database.get_all_detections(user_id=user_id)
                    recent = database.get_recent_detections(limit=10, user_id=user_id)
                    stats = database.get_stats(user_id=user_id)
                    self.assertEqual({row["subject"] for row in history}, expected_subjects)
                    self.assertEqual({row["subject"] for row in recent}, expected_subjects)
                    self.assertEqual(
                        (stats["total"], stats["safe"], stats["suspicious"], stats["fraudulent"]),
                        expected_counts,
                    )
                    self.assertTrue(all(row["user_id"] == user_id for row in history + recent))
                    self.assertTrue(all(query.get("user_id") == user_id
                                        for query in collection.count_queries[-4:]))
                    self.assertEqual(collection.aggregate_queries[-2][0]["$match"]["user_id"], user_id)
                    self.assertEqual(collection.aggregate_queries[-1][0]["$match"]["user_id"], user_id)

    def test_mongo_global_stats_remain_available_to_protected_admin(self):
        collection = FakeMongoDetections(SAMPLE_DETECTIONS)
        with patch.object(database, "detections_collection", collection):
            stats = database.get_stats()
        self.assertEqual((stats["total"], stats["safe"], stats["suspicious"], stats["fraudulent"]),
                         (3, 1, 1, 1))

    def test_dashboard_history_and_api_use_authenticated_session_id(self):
        client = flask_app.app.test_client()
        with patch.object(flask_app.db, "get_stats", return_value={"trend": []}) as stats, \
             patch.object(flask_app.db, "get_recent_detections", return_value=[]) as recent, \
             patch.object(flask_app.db, "get_recent_gmail_alerts", return_value=[]), \
             patch.object(flask_app.db, "get_notifications", return_value=[]), \
             patch.object(flask_app.db, "get_unread_notification_count", return_value=0), \
             patch.object(flask_app.db, "get_all_detections", return_value=[]) as history:
            with client.session_transaction() as session:
                session["user_id"] = "user-a"
                session["name"] = "User A"
                session["role"] = "user"

            self.assertEqual(client.get("/dashboard?user_id=user-b").status_code, 200)
            self.assertEqual(client.get("/history?user_id=user-b").status_code, 200)
            self.assertEqual(client.get("/api/stats?user_id=user-b").status_code, 200)
            stats.assert_called_with(user_id="user-a")
            recent.assert_called_with(limit=6, user_id="user-a")
            history.assert_called_with(user_id="user-a")

    def test_admin_global_statistics_require_admin_role(self):
        client = flask_app.app.test_client()
        with patch.object(flask_app.db, "get_stats", return_value={}) as stats, \
             patch.object(flask_app.db, "get_all_users", return_value=[]):
            with client.session_transaction() as session:
                session["user_id"] = "user-a"
                session["name"] = "User A"
                session["role"] = "user"
            response = client.get("/admin")
            self.assertEqual(response.status_code, 302)
            stats.assert_not_called()

            with client.session_transaction() as session:
                session["role"] = "admin"
            response = client.get("/admin")
            self.assertEqual(response.status_code, 200)
            stats.assert_called_once_with()

    def test_dashboard_notifications_and_history_explanations_render_for_session_user(self):
        client = flask_app.app.test_client()
        detection = {"id": "detection-id", "subject": "Meeting notice",
                     "sender_email": "team@example.test", "prediction": "Safe",
                     "risk_level": "Low", "risk_score": 0, "signals": [],
                     "simple_explanation": "No strong warning was found.",
                     "created_at": "today", "threat_category": None}
        with patch.object(flask_app.db, "get_stats", return_value={"trend": []}), \
             patch.object(flask_app.db, "get_recent_detections", return_value=[]), \
             patch.object(flask_app.db, "get_recent_gmail_alerts", return_value=[]), \
             patch.object(flask_app.db, "get_notifications", return_value=[{
                 "id": "detection-id", "subject": "Meeting notice", "classification": "Fraudulent",
                 "title": "New Fraudulent Email Detected",
                 "explanation": "The message requests account credentials.",
                 "created_at": datetime.now(timezone.utc), "is_read": False,
             }]), \
             patch.object(flask_app.db, "get_unread_notification_count", return_value=1), \
             patch.object(flask_app.db, "get_all_detections", return_value=[detection]):
            with client.session_transaction() as session:
                session["user_id"] = "user-a"
                session["name"] = "User A"
                session["role"] = "user"
            dashboard = client.get("/dashboard")
            history = client.get("/history")
        self.assertIn(b"Notifications", dashboard.data)
        self.assertIn(b"Enable desktop alerts", dashboard.data)
        self.assertIn(b"New Fraudulent Email Detected", dashboard.data)
        self.assertIn(b"The message requests account credentials", dashboard.data)
        self.assertIn(b"View analysis in History", dashboard.data)
        self.assertIn(b"Explain Result", history.data)
        self.assertIn(b"No strong warning was recorded", history.data)

    def test_notification_read_endpoint_is_owner_scoped_and_csrf_protected(self):
        client = flask_app.app.test_client()
        with client.session_transaction() as session:
            session["user_id"] = "user-a"
            session["name"] = "User A"
            session["role"] = "user"
        with patch.object(flask_app.db, "mark_notification_read", return_value=False) as mark:
            response = client.post("/notifications/0123456789abcdef01234567/read")
            self.assertEqual(response.status_code, 400)
            mark.assert_not_called()

            response = client.post("/notifications/0123456789abcdef01234567/read",
                                   headers=csrf_headers(client))
        self.assertEqual(response.status_code, 404)
        mark.assert_called_once_with("0123456789abcdef01234567", "user-a")

    def test_browser_notification_api_returns_only_user_scoped_result_links(self):
        client = flask_app.app.test_client()
        with client.session_transaction() as session:
            session["user_id"] = "user-a"
            session["name"] = "User A"
            session["role"] = "user"
        notification = {"id": "detection-id", "subject": "Private subject",
                        "classification": "Fraudulent", "message": "Private email content",
                        "is_read": False}
        with patch.object(flask_app.db, "get_notifications", return_value=[notification]) as get_notifications:
            response = client.get("/api/notifications/unread")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {"notifications": [{
            "id": "detection-id", "url": "/history#detection-detection-id",
        }]})
        self.assertNotIn(b"Private subject", response.data)
        self.assertNotIn(b"Private email content", response.data)
        get_notifications.assert_called_once_with("user-a")

    def test_scan_preference_change_requires_csrf(self):
        client = flask_app.app.test_client()
        with client.session_transaction() as session:
            session["user_id"] = "user-a"
            session["name"] = "User A"
            session["role"] = "user"
        with patch.object(flask_app.db, "get_gmail_connection", return_value={"user_id": "user-a"}), \
             patch.object(flask_app.db, "set_gmail_auto_scan", return_value=True) as update:
            response = client.post("/gmail/auto-scan", data={"enabled": "0"})
            self.assertEqual(response.status_code, 400)
            update.assert_not_called()

    def test_manual_csv_and_gmail_analysis_use_session_user_id(self):
        client = flask_app.app.test_client()
        with client.session_transaction() as session:
            session["user_id"] = "user-a"
            session["name"] = "User A"
            session["role"] = "user"

        with patch.object(flask_app, "analyze_email", return_value={"prediction": "Safe"}) as analyze:
            response = client.post("/api/analyze", headers=csrf_headers(client), json={
                "sender_email": "a@example.test", "subject": "Subject", "content": "Body",
                "user_id": "user-b",
            })
            self.assertEqual(response.status_code, 200)
            analyze.assert_called_once_with("a@example.test", "Subject", "Body", "user-a")

            analyze.reset_mock()
            csv_data = BytesIO(b"sender_email,subject,content,user_id\na@example.test,Subject,Body,user-b\n")
            response = client.post("/api/analyze-bulk", headers=csrf_headers(client), data={"file": (csv_data, "emails.csv")},
                                   content_type="multipart/form-data")
            self.assertEqual(response.status_code, 200)
            analyze.assert_called_once_with("a@example.test", "Subject", "Body", "user-a")

        with patch.object(flask_app.db, "get_gmail_connection", return_value={"user_id": "user-a"}) as connection, \
             patch.object(flask_app, "scan_gmail_account", return_value={"new": 0}) as scan:
            response = client.post("/gmail/scan", headers=csrf_headers(client))
            self.assertEqual(response.status_code, 302)
            connection.assert_called_once_with("user-a")
            scan.assert_called_once_with("user-a")

    def test_new_analysis_replaces_csv_panel_with_personal_gmail_controls(self):
        client = flask_app.app.test_client()
        with client.session_transaction() as session:
            session["user_id"] = "user-a"
            session["name"] = "User A"
            session["role"] = "user"
        with patch.object(flask_app.db, "get_gmail_connection", return_value={
                "user_id": "user-a", "email": "owner@example.test", "scan_status": "ready"}) as get_connection:
            response = client.get("/new-analysis")
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn("Personal Gmail Protection", page)
        self.assertIn("Connect Personal Gmail", page)
        self.assertIn("Scan Gmail Now", page)
        self.assertIn("owner@example.test", page)
        self.assertIn("Gmail scan history", page)
        self.assertNotIn("Scan CSV Emails", page)
        self.assertNotIn("email_scan_template.csv", page)
        get_connection.assert_called_once_with("user-a")

    def test_gmail_scan_status_and_start_are_scoped_to_session_user(self):
        client = flask_app.app.test_client()
        with client.session_transaction() as session:
            session["user_id"] = "user-a"
            session["name"] = "User A"
            session["role"] = "user"
        private_connection = {
            "user_id": "user-a", "email": "owner@example.test", "scan_status": "running",
            "scan_mode": "historical", "scan_progress_count": 25,
            "scan_progress_total": 50, "token_ciphertext": "must-not-leak",
            "last_scan_error_category": "gemini_request_failed",
            "last_scan_http_status": 400,
        }
        with patch.object(flask_app.db, "get_gmail_connection", return_value=private_connection) as get_connection:
            status_response = client.get("/api/gmail/scan-status")
        self.assertEqual(status_response.status_code, 200)
        self.assertEqual(status_response.json["progress"], 25)
        self.assertEqual(status_response.json["attempted_count"], 25)
        self.assertEqual(status_response.json["mode"], "historical")
        self.assertEqual(status_response.json["error_category"], "gemini_request_failed")
        self.assertEqual(status_response.json["http_status"], 400)
        self.assertNotIn("token_ciphertext", status_response.json)
        get_connection.assert_called_once_with("user-a")

        finished_connection = {
            "scan_status": "error", "last_scan_count": 0,
            "last_scan_failed_count": 3, "last_scan_deferred_count": 201,
        }
        with patch.object(flask_app.db, "get_gmail_connection", return_value=finished_connection):
            finished_response = client.get("/api/gmail/scan-status")
        self.assertEqual(finished_response.json["failed_count"], 3)
        self.assertEqual(finished_response.json["deferred_count"], 201)

        thread = Mock()
        with patch.object(flask_app.db, "get_gmail_connection", return_value=private_connection), \
             patch.object(flask_app.db, "acquire_gmail_scan_lease", return_value=True), \
             patch.object(flask_app.threading, "Thread", return_value=thread) as thread_factory:
            start_response = client.post("/api/gmail/scan", headers=csrf_headers(client))
        self.assertEqual(start_response.status_code, 202)
        self.assertEqual(thread_factory.call_args.kwargs["args"][0], "user-a")
        thread.start.assert_called_once()

    def test_repeated_gmail_scan_start_does_not_create_another_worker(self):
        client = flask_app.app.test_client()
        with client.session_transaction() as session:
            session["user_id"] = "user-a"
            session["name"] = "User A"
            session["role"] = "user"
        thread = Mock()
        with patch.object(flask_app.db, "get_gmail_connection", return_value={
                "user_id": "user-a", "scan_status": "running"}), \
             patch.object(flask_app.db, "acquire_gmail_scan_lease", side_effect=[True, False]), \
             patch.object(flask_app.db, "release_gmail_scan_lease"), \
             patch.object(flask_app.threading, "Thread", return_value=thread) as thread_factory:
            first = client.post("/api/gmail/scan", headers=csrf_headers(client))
            second = client.post("/api/gmail/scan", headers=csrf_headers(client))

        self.assertEqual(first.status_code, 202)
        self.assertEqual(second.status_code, 202)
        self.assertEqual(second.json["status"], "already_running")
        thread_factory.assert_called_once()
        thread.start.assert_called_once()

    def test_private_routes_require_login(self):
        client = flask_app.app.test_client()
        for method, path in [
            ("get", "/dashboard"), ("get", "/new-analysis"), ("get", "/history"),
            ("get", "/account-security"), ("get", "/admin"), ("get", "/email-account"),
            ("get", "/gmail/connect"), ("get", "/gmail/oauth/callback"),
            ("post", "/gmail/scan"), ("post", "/gmail/auto-scan"),
            ("post", "/api/gmail/scan"), ("get", "/api/gmail/scan-status"),
            ("post", "/gmail/disconnect"), ("post", "/notifications/invalid/read"),
            ("post", "/api/analyze"), ("post", "/api/analyze-bulk"), ("get", "/api/stats"),
            ("get", "/api/notifications/unread"),
        ]:
            with self.subTest(path=path):
                response = getattr(client, method)(path)
                self.assertEqual(response.status_code, 302)
                self.assertIn("/login", response.headers["Location"])


class GmailNotificationPersistenceTests(unittest.TestCase):
    def test_gmail_cached_detection_lookup_is_scoped_to_user(self):
        collection = Mock()
        with patch.object(database, "detections_collection", collection):
            database.get_gmail_detection("user-a", "gmail-message")
        collection.find_one.assert_called_once_with(
            {"user_id": "user-a", "external_message_id": "gmail-message"},
            {"_id": 1, "analysis_fingerprint": 1},
        )

    def test_gmail_page_fingerprint_lookup_batches_ids_with_user_scope(self):
        collection = Mock()
        collection.find.return_value = [
            {"external_message_id": "m1", "analysis_fingerprint": "fp1"},
            {"external_message_id": "m2", "analysis_fingerprint": "fp2"},
        ]
        with patch.object(database, "detections_collection", collection):
            rows = database.get_gmail_detections("user-a", ["m1", "m2"])

        collection.find.assert_called_once_with(
            {"user_id": "user-a", "external_message_id": {"$in": ["m1", "m2"]}},
            {"_id": 1, "external_message_id": 1, "analysis_fingerprint": 1},
        )
        self.assertEqual(set(rows), {"m1", "m2"})

    def test_changed_gmail_message_updates_existing_record_and_preserves_read_alert(self):
        collection = Mock()
        detection_id = ObjectId()
        collection.find_one.return_value = {
            "notification": {"title": "New Fraudulent Email Detected", "read": True,
                              "created_at": datetime.now(timezone.utc),
                              "explanation": "Previous explanation"},
        }
        collection.update_one.return_value.matched_count = 1
        with patch.object(database, "detections_collection", collection):
            result = database.insert_detection(
                user_id="user-a", sender_email="sender@example.test", subject="Changed",
                content="Updated body", prediction="Fraudulent", risk_level="High",
                confidence=88, threat_category=None, external_message_id="gmail-id",
                analysis_fingerprint="new-fingerprint", existing_detection_id=detection_id,
                explanation="Updated analysis", notify_new_fraud=True,
            )
        self.assertEqual(result, str(detection_id))
        collection.insert_one.assert_not_called()
        query, update = collection.update_one.call_args.args
        self.assertEqual(query["user_id"], "user-a")
        self.assertEqual(query["external_message_id"], "gmail-id")
        self.assertEqual(update["$set"]["analysis_fingerprint"], "new-fingerprint")
        self.assertEqual(update["$set"]["notification"]["read"], True)
        self.assertEqual(update["$set"]["notification"]["explanation"], "Updated analysis")

    def test_new_gmail_connection_enables_scheduled_scanning(self):
        collection = Mock()
        with patch.object(database, "gmail_connections_collection", collection):
            database.save_gmail_connection("user-a", "inbox@example.test", "encrypted-token")
        update = collection.update_one.call_args
        self.assertEqual(update.kwargs["upsert"], True)
        self.assertTrue(update.args[1]["$setOnInsert"]["auto_scan_enabled"])

    def test_new_fraud_detection_and_notification_are_inserted_atomically(self):
        collection = Mock()
        detection_id = ObjectId()
        collection.insert_one.return_value.inserted_id = detection_id
        with patch.object(database, "detections_collection", collection):
            saved_id = database.insert_detection(
                user_id="user-a", sender_email="sender@example.test", subject="Notice",
                content="Private email body", prediction="Fraudulent", risk_level="High",
                confidence=80, threat_category=None, external_message_id="gmail-id",
                explanation="The message asks for a password.", notify_new_fraud=True,
            )
        inserted = collection.insert_one.call_args.args[0]
        self.assertEqual(saved_id, str(detection_id))
        self.assertEqual(inserted["explanation"], "The message asks for a password.")
        self.assertEqual(inserted["prediction"], "Fraudulent")
        self.assertEqual(inserted["notification"]["title"], "New Fraudulent Email Detected")
        self.assertEqual(inserted["notification"]["explanation"], inserted["explanation"])
        self.assertFalse(inserted["notification"]["read"])
        self.assertEqual(inserted["notification"]["created_at"], inserted["created_at"])

    def test_safe_suspicious_and_historical_fraud_records_do_not_create_notifications(self):
        for prediction, notify_new_fraud in [
            ("Safe", True), ("Suspicious", True), ("Fraudulent", False),
        ]:
            with self.subTest(prediction=prediction, notify_new_fraud=notify_new_fraud):
                collection = Mock()
                collection.insert_one.return_value.inserted_id = ObjectId()
                with patch.object(database, "detections_collection", collection):
                    database.insert_detection(
                        user_id="user-a", sender_email="sender@example.test", subject="Notice",
                        content="Body", prediction=prediction, risk_level="Medium", confidence=80,
                        threat_category=None, external_message_id="gmail-id",
                        explanation="Saved explanation.", notify_new_fraud=notify_new_fraud,
                    )
                self.assertNotIn("notification", collection.insert_one.call_args.args[0])

    def test_duplicate_gmail_detection_does_not_create_a_second_notification(self):
        collection = Mock()
        collection.insert_one.side_effect = DuplicateKeyError("duplicate")
        with patch.object(database, "detections_collection", collection):
            result = database.insert_detection(
                user_id="user-a", sender_email="sender@example.test", subject="Notice",
                content="Body", prediction="Fraudulent", risk_level="High", confidence=90,
                threat_category=None, external_message_id="same-message", notify_new_fraud=True,
            )
        self.assertIsNone(result)
        collection.insert_one.assert_called_once()

    def test_detection_write_failure_does_not_complete_or_persist_a_notification(self):
        collection = Mock()
        collection.insert_one.side_effect = RuntimeError("simulated Atlas write failure")
        with patch.object(database, "detections_collection", collection):
            with self.assertRaisesRegex(RuntimeError, "simulated Atlas write failure"):
                database.insert_detection(
                    user_id="user-a", sender_email="sender@example.test", subject="Notice",
                    content="Body", prediction="Fraudulent", risk_level="High", confidence=90,
                    threat_category=None, external_message_id="gmail-id",
                    explanation="Saved analysis explanation.", notify_new_fraud=True,
                )
        attempted = collection.insert_one.call_args.args[0]
        self.assertEqual(attempted["notification"]["title"], "New Fraudulent Email Detected")

    def test_notifications_and_read_updates_are_scoped_to_one_user(self):
        detection_id = ObjectId()
        row = {"_id": detection_id, "user_id": "user-a", "subject": "Notice",
               "prediction": "Fraudulent", "external_message_id": "gmail-id",
               "created_at": datetime.now(timezone.utc), "explanation": "Saved explanation.",
               "notification": {"title": "New Fraudulent Email Detected", "message": "Warning",
                                "explanation": "Saved explanation.", "read": False}}
        collection = Mock()
        collection.find.return_value = Cursor([row])
        collection.count_documents.return_value = 1
        collection.update_one.return_value.matched_count = 1
        with patch.object(database, "detections_collection", collection):
            notifications = database.get_notifications("user-a")
            unread = database.get_unread_notification_count("user-a")
            marked = database.mark_notification_read(str(detection_id), "user-a")
        self.assertEqual(notifications[0]["id"], str(detection_id))
        self.assertFalse(notifications[0]["is_read"])
        self.assertEqual(notifications[0]["title"], "New Fraudulent Email Detected")
        self.assertEqual(notifications[0]["explanation"], "Saved explanation.")
        self.assertEqual(unread, 1)
        self.assertTrue(marked)
        self.assertEqual(collection.find.call_args.args[0]["user_id"], "user-a")
        self.assertEqual(collection.count_documents.call_args.args[0]["user_id"], "user-a")
        self.assertEqual(collection.update_one.call_args.args[0]["user_id"], "user-a")

    def test_unread_query_excludes_legacy_detections_without_notifications(self):
        collection = Mock()
        with patch.object(database, "detections_collection", collection):
            database.get_unread_notification_count("user-a")
        query = collection.count_documents.call_args.args[0]
        self.assertEqual(query["user_id"], "user-a")
        self.assertEqual(query["notification.title"], "New Fraudulent Email Detected")

    def test_notification_feed_ignores_legacy_safe_and_suspicious_notifications(self):
        collection = Mock()
        cursor = Mock()
        cursor.sort.return_value.limit.return_value = []
        collection.find.return_value = cursor
        with patch.object(database, "detections_collection", collection):
            self.assertEqual(database.get_notifications("user-a"), [])
        query = collection.find.call_args.args[0]
        self.assertEqual(query["user_id"], "user-a")
        self.assertEqual(query["notification.title"], "New Fraudulent Email Detected")

    def test_background_connection_query_respects_per_user_auto_scan_and_reauth(self):
        collection = Mock()
        collection.find.return_value = []
        with patch.object(database, "gmail_connections_collection", collection):
            database.get_gmail_connections()
        query = collection.find.call_args.args[0]
        self.assertEqual(query["auto_scan_enabled"], {"$ne": False})
        self.assertEqual(query["needs_reauth"], {"$ne": True})

    def test_scan_lease_is_atomic_and_bound_to_one_user(self):
        collection = Mock()
        collection.find_one_and_update.return_value = {"scan_lease_token": "lease-token"}
        with patch.object(database, "gmail_connections_collection", collection):
            acquired = database.acquire_gmail_scan_lease("user-a", "lease-token")
        self.assertTrue(acquired)
        query = collection.find_one_and_update.call_args.args[0]
        self.assertEqual(query["user_id"], "user-a")
        self.assertEqual(query["$or"][1]["scan_lease_until"], {"$exists": False})


if __name__ == "__main__":
    unittest.main()
