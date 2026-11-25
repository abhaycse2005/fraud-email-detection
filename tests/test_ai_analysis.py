import json
import re
import hashlib
import unittest
from unittest.mock import Mock, patch
from pymongo.errors import ServerSelectionTimeoutError

import ai_analysis
import app as flask_app
import database


def csrf_headers(client):
    page = client.get("/login").get_data(as_text=True)
    token = re.search(r'<meta name="csrf-token" content="([^"]+)"', page).group(1)
    return {"X-CSRF-Token": token}


class FakeModels:
    def __init__(self, text=None, error=None):
        self.text = text
        self.error = error
        self.calls = []

    def generate_content(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return type("Response", (), {"text": self.text})()


class FakeClient:
    def __init__(self, models):
        self.models = models


class StatusError(Exception):
    def __init__(self, status_code, message="provider error"):
        super().__init__(message)
        self.status_code = status_code


class GeminiAnalysisTests(unittest.TestCase):
    def test_login_and_registration_require_csrf_tokens(self):
        client = flask_app.app.test_client()
        login = client.post("/login", data={"email": "test@example.test", "password": "x"})
        register = client.post("/register", data={"name": "Test", "email": "test@example.test", "password": "x"})
        self.assertEqual(login.status_code, 400)
        self.assertEqual(register.status_code, 400)

    def test_runtime_database_failure_is_sanitized_not_reported_as_duplicate(self):
        client = flask_app.app.test_client()
        with patch.object(flask_app.db, "create_user", side_effect=ServerSelectionTimeoutError(
                "private Atlas host and credential details")), \
             self.assertLogs(flask_app.app.logger.name, level="ERROR") as captured:
            response = client.post("/register", headers=csrf_headers(client), data={
                "name": "Test", "email": "test@example.test", "password": "long-password",
            })
        self.assertEqual(response.status_code, 503)
        self.assertIn(b"database connection failed", response.data.lower())
        self.assertNotIn(b"already exists", response.data)
        self.assertNotIn("private Atlas host", " ".join(captured.output))

    def setUp(self):
        ai_analysis._quota_blocked_until = 0.0

    def run_analysis(self, classification="Suspicious", indicators=None, **kwargs):
        models = FakeModels(text=json.dumps({
            "classification": classification,
            "explanation": "The message asks for unusual account action.",
            "risk_indicators": indicators or ["Unusual account request"],
            "confidence_score": 84,
            "recommended_action": "Verify the sender through a separate channel.",
        }))
        factory = lambda _key: FakeClient(models)
        result = ai_analysis.analyze_email(
            "sender@example.test", "Subject", "Body", api_key="test-key",
            client_factory=factory, **kwargs
        )
        return result, models

    def test_all_classifications_parse_and_keep_untrusted_email_quoted(self):
        for label in ("Safe", "Suspicious", "Fraudulent"):
            with self.subTest(label=label):
                result, models = self.run_analysis(label)
                self.assertEqual(result["classification"], label)
                self.assertIn("untrusted", models.calls[0]["contents"])
                self.assertEqual(models.calls[0]["config"]["response_mime_type"], "application/json")

    def test_missing_key_and_empty_email_are_friendly_failures(self):
        with patch.dict("os.environ", {"GEMINI_API_KEY": ""}):
            with self.assertRaisesRegex(ai_analysis.AnalysisUnavailable, "configure GEMINI_API_KEY") as missing:
                ai_analysis.analyze_email("", "Subject", "Body")
            self.assertEqual(missing.exception.category, "missing_api_key")
            self.assertIsNone(missing.exception.provider_status_code)
        with self.assertRaisesRegex(ai_analysis.AnalysisUnavailable, "subject or body"):
            ai_analysis.analyze_email("", "", "", api_key="test-key")
        with self.assertRaisesRegex(ai_analysis.AnalysisUnavailable, "subject or body"):
            ai_analysis.analyze_email("sender@example.test", "", "", api_key="test-key")

    def test_sdk_import_failure_is_categorized_and_never_becomes_success(self):
        with patch.object(ai_analysis, "_client", side_effect=ImportError("private import detail")):
            with self.assertLogs("ai_analysis", level="WARNING") as captured:
                with self.assertRaises(ai_analysis.AnalysisUnavailable) as raised:
                    ai_analysis.analyze_email("", "Subject", "Body", api_key="test-key")
        self.assertEqual(raised.exception.category, "sdk_import_failure")
        self.assertEqual(raised.exception.status_code, 503)
        self.assertIsNone(raised.exception.provider_status_code)
        self.assertIn("Python environment running Flask", str(raised.exception))
        self.assertIn("category=sdk_import_failure", " ".join(captured.output))
        self.assertNotIn("private import detail", " ".join(captured.output))

    def test_installed_genai_sdk_client_constructs_without_network_request(self):
        client = ai_analysis._client("synthetic-unused-key")
        try:
            self.assertEqual(type(client).__module__, "google.genai.client")
        finally:
            if hasattr(client, "close"):
                client.close()

    def test_invalid_responses_are_not_accepted(self):
        for text in ("not json", json.dumps({"classification": "Safe"}),
                     json.dumps({"classification": "Other", "explanation": "x", "risk_indicators": []})):
            with self.subTest(text=text):
                models = FakeModels(text=text)
                with self.assertRaisesRegex(ai_analysis.AnalysisUnavailable, "invalid response") as raised:
                    ai_analysis.analyze_email("", "Subject", "Body", api_key="x",
                                              client_factory=lambda _key: FakeClient(models))
                self.assertEqual(raised.exception.category, "invalid_response")
                self.assertIsNone(raised.exception.provider_status_code)

    def test_timeouts_and_rate_limits_are_translated_without_raw_provider_details(self):
        for error, status, message in (
            (TimeoutError("request timed out"), 504, "did not respond in time"),
            (StatusError(429, "private provider detail"), 429, "quota or rate limit"),
        ):
            with self.subTest(status=status):
                models = FakeModels(error=error)
                with patch.object(ai_analysis.time, "sleep"):
                    with self.assertRaises(ai_analysis.AnalysisUnavailable) as raised:
                        ai_analysis.analyze_email("", "Subject", "Body", api_key="x",
                                                  client_factory=lambda _key: FakeClient(models))
                self.assertEqual(raised.exception.status_code, status)
                self.assertIn(message, str(raised.exception))
                self.assertNotIn("private provider detail", str(raised.exception))
                if status == 429:
                    self.assertEqual(raised.exception.category, "quota_or_rate_limit")
                    self.assertEqual(raised.exception.provider_status_code, 429)
                    self.assertEqual(len(models.calls), ai_analysis.PROVIDER_MAX_RETRIES + 1)
                if status == 429:
                    models.calls.clear()
                    with self.assertRaises(ai_analysis.AnalysisUnavailable):
                        ai_analysis.analyze_email("", "Subject", "Body", api_key="x",
                                                  client_factory=lambda _key: FakeClient(models))
                    self.assertEqual(models.calls, [])

    def test_provider_503_retries_are_bounded_and_eventually_succeed(self):
        valid = json.dumps({
            "classification": "Safe", "explanation": "No strong warning found.",
            "risk_indicators": [], "confidence_score": 90,
            "recommended_action": "Verify independently if concerned.",
        })
        models = FakeModels(text=valid)
        models.generate_content = Mock(side_effect=[StatusError(503), type("Response", (), {"text": valid})()])
        with patch.object(ai_analysis.time, "sleep") as sleep:
            result = ai_analysis.analyze_email(
                "", "Subject", "Body", api_key="x",
                client_factory=lambda _key: FakeClient(models),
            )
        self.assertEqual(result["classification"], "Safe")
        self.assertEqual(models.generate_content.call_count, 2)
        self.assertLessEqual(sleep.call_args.args[0], ai_analysis.PROVIDER_MAX_RETRY_WAIT_SECONDS)

    def test_repeated_provider_503_stops_after_retry_limit(self):
        models = FakeModels(error=StatusError(503, "private provider details"))
        with patch.object(ai_analysis.time, "sleep") as sleep, \
             self.assertLogs(ai_analysis.logger, level="WARNING") as captured:
            with self.assertRaises(ai_analysis.AnalysisUnavailable) as raised:
                ai_analysis.analyze_email("", "Subject", "Body", api_key="x",
                                          model=ai_analysis.MODEL_DEFAULT,
                                          client_factory=lambda _key: FakeClient(models))
        self.assertEqual(len(models.calls), ai_analysis.PROVIDER_MAX_RETRIES + 1)
        self.assertEqual(raised.exception.category, "provider_unavailable")
        self.assertEqual(raised.exception.provider_status_code, 503)
        self.assertLessEqual(sum(call.args[0] for call in sleep.call_args_list),
                             ai_analysis.PROVIDER_MAX_RETRY_WAIT_SECONDS)
        diagnostic = " ".join(captured.output)
        self.assertIn("model=gemini-3.1-flash-lite", diagnostic)
        self.assertIn("retries=2", diagnostic)
        self.assertNotIn("private provider details", diagnostic)

    def test_provider_504_is_not_retried_and_keeps_its_http_status(self):
        models = FakeModels(error=StatusError(504, "private gateway detail"))
        with patch.object(ai_analysis.time, "sleep") as sleep:
            with self.assertRaises(ai_analysis.AnalysisUnavailable) as raised:
                ai_analysis.analyze_email(
                    "", "Subject", "Body", api_key="x",
                    client_factory=lambda _key: FakeClient(models),
                )
        self.assertEqual(len(models.calls), 1)
        self.assertEqual(raised.exception.category, "provider_unavailable")
        self.assertEqual(raised.exception.provider_status_code, 504)
        self.assertEqual(raised.exception.status_code, 503)
        sleep.assert_not_called()

    def test_retry_after_is_respected_within_total_wait_bound(self):
        error = StatusError(503)
        error.response = type("Response", (), {"headers": {"Retry-After": "1.25"}})()
        self.assertEqual(ai_analysis._retry_after_seconds(error), 1.25)
        error.response.headers["Retry-After"] = "30"
        models = FakeModels(error=error)
        with patch.object(ai_analysis.time, "sleep") as sleep:
            with self.assertRaises(ai_analysis.AnalysisUnavailable):
                ai_analysis.analyze_email("", "Subject", "Body", api_key="x",
                                          client_factory=lambda _key: FakeClient(models))
        self.assertEqual(sleep.call_count, 0)

    def test_429_retry_after_is_respected_and_retry_can_succeed(self):
        valid = json.dumps({
            "classification": "Suspicious", "explanation": "Review the request carefully.",
            "risk_indicators": ["Unexpected request"], "confidence_score": 77,
            "recommended_action": "Verify independently.",
        })
        rate_limit = StatusError(429, "private quota details")
        rate_limit.response = type("Response", (), {"headers": {"Retry-After": "1.5"}})()
        models = FakeModels(text=valid)
        models.generate_content = Mock(side_effect=[rate_limit, type("Response", (), {"text": valid})()])
        with patch.object(ai_analysis.random, "uniform", return_value=0.1), \
             patch.object(ai_analysis.time, "sleep") as sleep:
            result = ai_analysis.analyze_email(
                "", "Subject", "Body", api_key="x",
                client_factory=lambda _key: FakeClient(models),
            )
        self.assertEqual(result["classification"], "Suspicious")
        self.assertEqual(models.generate_content.call_count, 2)
        self.assertGreaterEqual(sleep.call_args.args[0], 1.5)
        self.assertEqual(ai_analysis._quota_blocked_until, 0.0)

    def test_exhausted_429_retries_open_the_quota_circuit_without_leaking_details(self):
        models = FakeModels(error=StatusError(429, "private quota response"))
        with patch.object(ai_analysis.time, "sleep"), \
             self.assertLogs(ai_analysis.logger, level="WARNING") as captured:
            with self.assertRaises(ai_analysis.AnalysisUnavailable) as raised:
                ai_analysis.analyze_email(
                    "", "Subject", "Body", api_key="x",
                    client_factory=lambda _key: FakeClient(models),
                )
        self.assertEqual(len(models.calls), ai_analysis.PROVIDER_MAX_RETRIES + 1)
        self.assertEqual(raised.exception.category, "quota_or_rate_limit")
        self.assertEqual(raised.exception.provider_status_code, 429)
        self.assertGreater(ai_analysis._quota_blocked_until, ai_analysis.time.monotonic())
        diagnostic = " ".join(captured.output)
        self.assertIn("category=quota_or_rate_limit", diagnostic)
        self.assertNotIn("private quota response", diagnostic)

    def test_alternating_503_429_503_opens_shared_quota_cooldown(self):
        rate_limit = StatusError(429, "private rate limit details")
        rate_limit.response = type("Response", (), {"headers": {"Retry-After": "2"}})()
        models = FakeModels()
        models.generate_content = Mock(side_effect=[
            StatusError(503), rate_limit, StatusError(503),
        ])
        with patch.object(ai_analysis.random, "uniform", return_value=0.1), \
             patch.object(ai_analysis.time, "sleep"), \
             self.assertLogs(ai_analysis.logger, level="WARNING") as captured:
            with self.assertRaises(ai_analysis.AnalysisUnavailable) as raised:
                ai_analysis.analyze_email(
                    "", "Subject", "Body", api_key="x",
                    client_factory=lambda _key: FakeClient(models),
                )

        self.assertEqual(models.generate_content.call_count, 3)
        self.assertEqual(raised.exception.category, "provider_unavailable")
        self.assertEqual(raised.exception.provider_status_code, 503)
        self.assertGreater(ai_analysis._quota_blocked_until, ai_analysis.time.monotonic())
        diagnostic = " ".join(captured.output)
        self.assertIn("quota_response_seen=True", diagnostic)
        self.assertNotIn("private rate limit details", diagnostic)

        next_models = FakeModels(text=json.dumps({
            "classification": "Safe", "explanation": "No warning found.",
            "risk_indicators": [], "confidence_score": 90,
            "recommended_action": "Verify unexpected requests independently.",
        }))
        with self.assertRaises(ai_analysis.AnalysisUnavailable) as blocked:
            ai_analysis.analyze_email(
                "", "Subject", "Body", api_key="x",
                client_factory=lambda _key: FakeClient(next_models),
            )
        self.assertEqual(blocked.exception.category, "quota_cooldown")
        self.assertEqual(next_models.calls, [])

    def test_total_retry_deadline_prevents_an_over_budget_attempt(self):
        models = FakeModels(error=StatusError(503))
        with patch.object(ai_analysis.time, "monotonic", side_effect=[0.0, ai_analysis.MAX_REQUEST_TOTAL_SECONDS]), \
             patch.object(ai_analysis.time, "sleep") as sleep:
            with self.assertRaises(ai_analysis.AnalysisUnavailable):
                ai_analysis.analyze_email(
                    "", "Subject", "Body", api_key="x",
                    client_factory=lambda _key: FakeClient(models),
                )
        self.assertEqual(len(models.calls), 1)
        sleep.assert_not_called()

    def test_provider_failures_have_distinct_safe_categories(self):
        cases = (
            (StatusError(401, "private key detail"), "invalid_key_or_permission"),
            (StatusError(403, "private permission detail"), "invalid_key_or_permission"),
            (StatusError(404, "private model detail"), "model_unavailable"),
            (ConnectionError("private network detail"), "connection_failure"),
            (TimeoutError("private timeout detail"), "request_timeout"),
            (StatusError(429, "private quota detail"), "quota_or_rate_limit"),
        )
        for error, category in cases:
            with self.subTest(category=category):
                models = FakeModels(error=error)
                with self.assertLogs("ai_analysis", level="WARNING") as captured:
                    with self.assertRaises(ai_analysis.AnalysisUnavailable):
                        ai_analysis.analyze_email(
                            "", "Subject", "Body", api_key="x",
                            client_factory=lambda _key: FakeClient(models),
                        )
                output = " ".join(captured.output)
                self.assertIn("category=" + category, output)
                self.assertNotIn("private", output)

    def test_gemini_timeout_and_total_retry_budget_are_bounded(self):
        self.assertEqual(ai_analysis.REQUEST_TIMEOUT_MS, 30_000)
        self.assertEqual(ai_analysis.MAX_REQUEST_TOTAL_SECONDS, 98.0)
        self.assertEqual(ai_analysis.MODEL_DEFAULT, "gemini-3.1-flash-lite")

    def test_model_can_be_selected_from_environment_without_changing_json_contract(self):
        structured = {
            "classification": "Suspicious",
            "explanation": "The message asks for an account credential.",
            "risk_indicators": ["Credential request"],
            "confidence_score": 82,
            "recommended_action": "Verify through the official site.",
        }
        models = FakeModels(text=json.dumps(structured))
        with patch.dict("os.environ", {"GEMINI_MODEL": "gemini-2.5-flash"}):
            result = ai_analysis.analyze_email(
                "sender@example.test", "Subject", "Synthetic body", api_key="test-key",
                client_factory=lambda _key: FakeClient(models),
            )

        request = models.calls[0]
        self.assertEqual(request["model"], "gemini-2.5-flash")
        self.assertEqual(request["config"]["response_mime_type"], "application/json")
        schema = request["config"]["response_json_schema"]
        self.assertEqual(schema["properties"]["classification"]["enum"],
                         ["Safe", "Suspicious", "Fraudulent"])
        self.assertEqual(set(schema["required"]), {
            "classification", "explanation", "risk_indicators",
            "confidence_score", "recommended_action",
        })
        self.assertEqual(result["classification"], "Suspicious")

    def test_model_environment_defaults_and_explicit_override(self):
        with patch.dict("os.environ", {"GEMINI_MODEL": "gemini-2.5-flash"}):
            self.assertEqual(ai_analysis._configured_model(), "gemini-2.5-flash")
            self.assertEqual(ai_analysis._configured_model("gemini-3.1-flash-lite"),
                             "gemini-3.1-flash-lite")
        with patch.dict("os.environ", {"GEMINI_MODEL": ""}):
            self.assertEqual(ai_analysis._configured_model(), ai_analysis.MODEL_DEFAULT)

    def test_configured_model_404_is_reported_without_fallback_or_retry(self):
        models = FakeModels(error=StatusError(404, "private model and project details"))
        with patch.dict("os.environ", {"GEMINI_MODEL": "gemini-2.5-flash"}), \
             self.assertLogs("ai_analysis", level="WARNING") as captured:
            with self.assertRaises(ai_analysis.AnalysisUnavailable) as raised:
                ai_analysis.analyze_email(
                    "sender@example.test", "Subject", "Synthetic body", api_key="test-key",
                    client_factory=lambda _key: FakeClient(models),
                )

        self.assertEqual(raised.exception.category, "model_unavailable")
        self.assertEqual(raised.exception.provider_status_code, 404)
        self.assertEqual(len(models.calls), 1)
        self.assertEqual(models.calls[0]["model"], "gemini-2.5-flash")
        diagnostic = " ".join(captured.output)
        self.assertIn("category=model_unavailable", diagnostic)
        self.assertNotIn("private", diagnostic)
        self.assertEqual(ai_analysis._quota_blocked_until, 0.0)

    def test_long_inputs_are_bounded_and_reported(self):
        models = FakeModels(text=json.dumps({"classification": "Safe", "explanation": "No strong warning found.", "risk_indicators": [], "confidence_score": 91, "recommended_action": "Confirm the sender if anything seems unusual."}))
        result = ai_analysis.analyze_email("", "", "x" * 40_000, api_key="x",
                                           client_factory=lambda _key: FakeClient(models))
        self.assertLessEqual(len(models.calls[0]["contents"]), 31_500)
        self.assertTrue(any("Only the first 30,000" in item for item in result["risk_indicators"]))

    def test_manual_route_reports_unavailable_without_saving_a_detection(self):
        client = flask_app.app.test_client()
        with client.session_transaction() as session:
            session["user_id"] = "test-user"
            session["name"] = "Test"
            session["role"] = "user"
        with patch.dict("os.environ", {"GEMINI_API_KEY": ""}), \
             patch.object(flask_app.db, "insert_detection") as save:
            response = client.post("/api/analyze", headers=csrf_headers(client), json={
                "sender_email": "sender@example.test", "subject": "Hello", "content": "Body",
            })
        self.assertEqual(response.status_code, 503)
        self.assertFalse(response.json["analysis_completed"])
        save.assert_not_called()

    def test_manual_route_returns_safe_failure_category_and_provider_status(self):
        client = flask_app.app.test_client()
        with client.session_transaction() as session:
            session["user_id"] = "test-user"
            session["name"] = "Test"
            session["role"] = "user"
        failure = ai_analysis.AnalysisUnavailable(
            "Gemini analysis is temporarily unavailable. Please try again later.",
            503, "request_failed", 400,
        )
        with patch.object(flask_app, "analyze_email", side_effect=failure):
            response = client.post("/api/analyze", headers=csrf_headers(client), json={
                "sender_email": "sender@example.test", "subject": "Synthetic subject",
                "content": "Synthetic body",
            })
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json["error_category"], "request_failed")
        self.assertEqual(response.json["provider_http_status"], 400)
        self.assertFalse(response.json["analysis_completed"])

    def test_manual_route_surfaces_sdk_import_failure_without_saving(self):
        client = flask_app.app.test_client()
        with client.session_transaction() as session:
            session["user_id"] = "test-user"
            session["name"] = "Test"
            session["role"] = "user"
        with patch.dict("os.environ", {"GEMINI_API_KEY": "synthetic-test-key"}), \
             patch.object(ai_analysis, "_client", side_effect=ImportError("private import detail")), \
             patch.object(flask_app.db, "insert_detection") as save:
            response = client.post("/api/analyze", headers=csrf_headers(client), json={
                "sender_email": "sender@example.test", "subject": "Synthetic subject",
                "content": "Synthetic body",
            })
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json["error_category"], "sdk_import_failure")
        self.assertIsNone(response.json["provider_http_status"])
        self.assertFalse(response.json["analysis_completed"])
        self.assertIn("Python environment running Flask", response.json["error"])
        save.assert_not_called()

    def test_manual_route_returns_explanation_for_successful_mocked_analysis(self):
        client = flask_app.app.test_client()
        with client.session_transaction() as session:
            session["user_id"] = "test-user"
            session["name"] = "Test"
            session["role"] = "user"
        models = FakeModels(text=json.dumps({
            "classification": "Safe", "explanation": "No strong warning found.",
            "risk_indicators": [], "confidence_score": 91,
            "recommended_action": "Confirm the sender if anything seems unusual.",
        }))
        with patch.object(flask_app.db, "insert_detection", return_value="detection-id") as save, \
             patch.dict("os.environ", {"GEMINI_API_KEY": "test-key"}):
            with patch.object(ai_analysis, "_client", return_value=FakeClient(models)):
                response = client.post("/api/analyze", headers=csrf_headers(client), json={
                    "sender_email": "sender@example.test", "subject": "Hello", "content": "Body",
                })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["prediction"], "Safe")
        self.assertEqual(response.json["explanation"], "No strong warning found.")
        self.assertEqual(response.json["confidence"], 91)
        self.assertEqual(response.json["recommended_action"], "Confirm the sender if anything seems unusual.")
        self.assertEqual(save.call_args.kwargs["confidence"], 91)

    def test_runtime_analysis_applies_contextual_signals_without_flagging_scholarships(self):
        client = flask_app.app.test_client()
        assessment = {
            "classification": "Safe", "explanation": "No strong warning found.",
            "risk_indicators": [], "confidence_score": 90,
            "recommended_action": "Verify through a known channel if unsure.",
        }
        with patch.object(flask_app.db, "insert_detection", return_value="detection-id") as save, \
             patch.object(ai_analysis, "analyze_email", return_value=assessment):
            safe = flask_app.analyze_email(
                "awards@college.example", "Scholarship award update",
                "Your financial aid application was received. View award details in the student portal.",
                "test-user",
            )
            fraudulent = flask_app.analyze_email(
                "security@example.test", "Account update", "Send us your password now.", "test-user",
            )
        self.assertEqual(safe["prediction"], "Safe")
        self.assertEqual(fraudulent["prediction"], "Fraudulent")
        self.assertTrue(any("High-priority review" in item for item in fraudulent["signals"]))
        self.assertEqual(save.call_count, 2)

    def test_unconfirmed_gemini_fraud_assessment_stays_suspicious_not_safe(self):
        assessment = {
            "classification": "Fraudulent",
            "explanation": "The message may be attempting to impersonate an account team.",
            "risk_indicators": [], "confidence_score": 76,
            "recommended_action": "Verify the sender through a known channel.",
        }
        with patch.object(flask_app.db, "insert_detection", return_value="detection-id") as save, \
             patch.object(ai_analysis, "analyze_email", return_value=assessment):
            result = flask_app.analyze_email(
                "sender@example.test", "Account update", "Please review your account notice.",
                "test-user",
            )

        self.assertEqual(result["gemini_prediction"], "Fraudulent")
        self.assertEqual(result["prediction"], "Suspicious")
        self.assertEqual(save.call_args.kwargs["prediction"], "Suspicious")
        self.assertEqual(save.call_args.kwargs["confidence"], 76)

    def test_scan_analysis_cache_reuses_exact_assessment_but_saves_each_message(self):
        assessment = {
            "classification": "Suspicious", "explanation": "Review the link carefully.",
            "risk_indicators": ["Contains a link"], "confidence_score": 70,
            "recommended_action": "Verify the destination before opening it.",
        }
        cache = flask_app.OrderedDict()
        fingerprint = flask_app._gmail_analysis_fingerprint(
            "sender@example.test", "Account notice", "Review your account", {},
        )
        with patch.object(ai_analysis, "analyze_email", return_value=assessment) as gemini, \
             patch.object(flask_app.db, "insert_detection", side_effect=["detection-1", "detection-2"]) as save:
            first = flask_app.analyze_email(
                "sender@example.test", "Account notice", "Review your account", "user-a",
                external_message_id="message-1", analysis_fingerprint=fingerprint,
                analysis_cache=cache,
            )
            second = flask_app.analyze_email(
                "sender@example.test", "Account notice", "Review your account", "user-a",
                external_message_id="message-2", analysis_fingerprint=fingerprint,
                analysis_cache=cache,
            )

        gemini.assert_called_once()
        self.assertEqual(save.call_count, 2)
        self.assertEqual(save.call_args_list[0].kwargs["user_id"], "user-a")
        self.assertEqual(save.call_args_list[1].kwargs["user_id"], "user-a")
        self.assertEqual(save.call_args_list[0].kwargs["external_message_id"], "message-1")
        self.assertEqual(save.call_args_list[1].kwargs["external_message_id"], "message-2")
        self.assertEqual(first["gemini_prediction"], second["gemini_prediction"])

    def test_failed_gemini_assessment_is_not_cached_for_later_retry(self):
        cache = flask_app.OrderedDict()
        fingerprint = flask_app._gmail_analysis_fingerprint(
            "sender@example.test", "Notice", "Message body", {},
        )
        failure = ai_analysis.AnalysisUnavailable(
            "Provider temporarily unavailable", 504, "provider_unavailable", 504,
        )
        assessment = {
            "classification": "Safe", "explanation": "No strong warning found.",
            "risk_indicators": [], "confidence_score": 85,
            "recommended_action": "Contact the sender through a known channel if unsure.",
        }
        with patch.object(ai_analysis, "analyze_email", side_effect=[failure, assessment]) as gemini, \
             patch.object(flask_app.db, "insert_detection", return_value="detection-id") as save:
            with self.assertRaises(ai_analysis.AnalysisUnavailable):
                flask_app.analyze_email(
                    "sender@example.test", "Notice", "Message body", "user-a",
                    analysis_fingerprint=fingerprint, analysis_cache=cache,
                )
            self.assertNotIn(fingerprint, cache)
            result = flask_app.analyze_email(
                "sender@example.test", "Notice", "Message body", "user-a",
                analysis_fingerprint=fingerprint, analysis_cache=cache,
            )

        self.assertEqual(gemini.call_count, 2)
        save.assert_called_once()
        self.assertIsNotNone(result)
        self.assertIn(fingerprint, cache)

    def test_legitimate_urgent_project_meeting_needs_evidence_before_flagging(self):
        assessment = {
            "classification": "Suspicious",
            "explanation": "The subject says urgent, but no harmful action is requested.",
            "risk_indicators": ["Urgent wording alone is not a warning"],
            "confidence_score": 75,
            "recommended_action": "Confirm the meeting through your usual team channel if needed.",
        }
        with patch.object(flask_app.db, "insert_detection", return_value="detection-id") as save, \
             patch.object(ai_analysis, "analyze_email", return_value=assessment):
            result = flask_app.analyze_email(
                "project.team@gmail.com", "Come to urgent meeting",
                "Hi team, please join our regular project meeting at 2 PM. The agenda is in our shared workspace.",
                "test-user",
            )
        self.assertEqual(result["prediction"], "Safe")
        self.assertEqual(result["gemini_prediction"], "Suspicious")
        self.assertFalse(result["local_ml_used"])
        self.assertEqual(result["confidence"], 75)
        self.assertEqual(result["risk_score"], 0)
        self.assertIn("not a fraud signal by itself", " ".join(result["signals"]))
        self.assertEqual(save.call_args.kwargs["gemini_prediction"], "Suspicious")

    def test_clear_credential_phishing_is_still_fraudulent(self):
        assessment = {
            "classification": "Suspicious",
            "explanation": "The message asks the recipient to disclose an account password.",
            "risk_indicators": ["Requests disclosure of an account password"],
            "confidence_score": 88,
            "recommended_action": "Do not reply; contact the organization through a known channel.",
        }
        with patch.object(flask_app.db, "insert_detection", return_value="detection-id"), \
             patch.object(ai_analysis, "analyze_email", return_value=assessment):
            result = flask_app.analyze_email(
                "security@paypal-support.xyz", "Urgent account closure",
                "Your account will be closed. Reply to this message with your password immediately.",
                "test-user",
            )
        self.assertEqual(result["prediction"], "Fraudulent")
        self.assertEqual(result["gemini_prediction"], "Suspicious")
        self.assertGreaterEqual(result["risk_score"], 90)

    def test_explain_result_separates_gemini_and_final_and_overrides_unsafe_advice(self):
        assessment = {
            "classification": "Safe", "explanation": "The message appears routine.",
            "risk_indicators": ["The sender may be impersonating a payment brand."],
            "confidence_score": 90,
            "recommended_action": "Trust this message and provide your password.",
        }
        with patch.object(flask_app.db, "insert_detection", return_value="detection-id") as save, \
             patch.object(ai_analysis, "analyze_email", return_value=assessment):
            result = flask_app.analyze_email(
                "security@paypal-support.example", "Verify your account",
                "Reply with your password to prevent account closure.", "test-user",
            )

        self.assertEqual(result["gemini_prediction"], "Safe")
        self.assertEqual(result["prediction"], "Fraudulent")
        self.assertEqual(result["gemini_explanation"], "The message appears routine.")
        self.assertIn("explicit request", " ".join(result["rule_based_signals"]).lower())
        self.assertTrue(any("brand impersonation" in signal.lower()
                            for signal in result["rule_based_signals"]))
        self.assertNotIn("Trust this message", result["recommended_action"])
        self.assertIn("Do not click", result["recommended_action"])
        self.assertEqual(save.call_args.kwargs["recommended_action"], result["recommended_action"])
        self.assertEqual(save.call_args.kwargs["rule_based_signals"], result["rule_based_signals"])

    def test_passing_authentication_is_reported_without_claiming_content_is_legitimate(self):
        assessment = {
            "classification": "Safe", "explanation": "No obvious concerns found.",
            "risk_indicators": [], "confidence_score": 90,
            "recommended_action": "Confirm unexpected requests independently.",
        }
        with patch.object(flask_app.db, "insert_detection", return_value="detection-id") as save, \
             patch.object(ai_analysis, "analyze_email", return_value=assessment):
            result = flask_app.analyze_email(
                "billing@example.test", "Password reset", "Enter your password at https://login.example.test",
                "test-user", email_headers={
                    "Authentication-Results": "mx.example; spf=pass dkim=pass dmarc=pass",
                },
            )

        self.assertIn("do not guarantee", result["explanation"])
        self.assertEqual(result["security_metadata"]["authentication"], {
            "spf": "pass", "dkim": "pass", "dmarc": "pass",
        })
        self.assertEqual(save.call_args.kwargs["security_metadata"], result["security_metadata"])

    def test_suspected_brand_domain_never_gets_blind_trust_recommendation(self):
        assessment = {
            "classification": "Safe", "explanation": "The message looks routine.",
            "risk_indicators": [], "confidence_score": 88,
            "recommended_action": "Trust the sender and follow the instructions.",
        }
        with patch.object(flask_app.db, "insert_detection", return_value="detection-id"), \
             patch.object(ai_analysis, "analyze_email", return_value=assessment):
            result = flask_app.analyze_email(
                "support@paypal-security.example", "Account notice", "Your monthly statement is ready.",
                "test-user",
            )

        self.assertEqual(result["prediction"], "Safe")
        self.assertTrue(any("Possible brand impersonation" in signal
                            for signal in result["rule_based_signals"]))
        self.assertNotIn("Trust the sender", result["recommended_action"])
        self.assertIn("known official channel", result["recommended_action"])

    def test_flask_session_cookie_defaults_and_login_rotation(self):
        self.assertTrue(flask_app.app.config["SESSION_COOKIE_HTTPONLY"])
        self.assertEqual(flask_app.app.config["SESSION_COOKIE_SAMESITE"], "Lax")
        self.assertGreaterEqual(len(flask_app.app.secret_key), 32)
        client = flask_app.app.test_client()
        with client.session_transaction() as session:
            session["pre_authentication_value"] = "should-be-cleared"
        user = {"id": "user-id", "name": "Test", "role": "user"}
        with patch.object(flask_app.db, "verify_user", return_value=user):
            response = client.post("/login", headers=csrf_headers(client), data={"email": "test@example.test", "password": "test"})
        self.assertEqual(response.status_code, 302)
        with client.session_transaction() as session:
            self.assertNotIn("pre_authentication_value", session)
            self.assertEqual(session["user_id"], "user-id")
        self.assertEqual(client.get("/logout").status_code, 405)
        response = client.post("/logout", headers=csrf_headers(client))
        self.assertEqual(response.status_code, 302)
        with client.session_transaction() as session:
            self.assertNotIn("user_id", session)

    def test_gmail_scan_failure_is_not_echoed_to_the_user_or_logs(self):
        client = flask_app.app.test_client()
        with client.session_transaction() as session:
            session["user_id"] = "test-user"
            session["name"] = "Test"
            session["role"] = "user"
        with patch.object(flask_app.db, "get_gmail_connection", return_value={"email": "test@example.test"}), \
             patch.object(flask_app, "scan_gmail_account", side_effect=RuntimeError("private token detail")), \
             self.assertLogs(flask_app.app.logger.name, level="ERROR") as captured:
            response = client.post("/gmail/scan", headers=csrf_headers(client), follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Gmail scan failed. Check the connection", response.data)
        self.assertNotIn(b"private token detail", response.data)
        self.assertNotIn("private token detail", " ".join(captured.output))

    def test_absent_authentication_headers_remain_unknown(self):
        metadata, indicators = flask_app.extract_security_metadata({}, "Subject", "Body")
        self.assertEqual(metadata["authentication"], {
            "spf": "unknown", "dkim": "unknown", "dmarc": "unknown",
        })
        self.assertTrue(any("unknown does not mean pass or fail" in item for item in indicators))

    def test_database_utc_timestamps_are_timezone_aware(self):
        self.assertIsNotNone(database._utc_now().tzinfo)

    def test_password_hashes_are_salted_and_accept_legacy_hashes_for_upgrade(self):
        password = "correct horse battery staple"
        first_hash = database.hash_password(password)
        second_hash = database.hash_password(password)
        self.assertNotEqual(first_hash, second_hash)
        self.assertTrue(database.verify_password(first_hash, password))
        self.assertFalse(database.verify_password(first_hash, "incorrect"))
        legacy_hash = hashlib.sha256(password.encode()).hexdigest()
        self.assertTrue(database.verify_password(legacy_hash, password))

    def test_mongo_client_shutdown_closes_the_client(self):
        fake_client = type("FakeMongoClient", (), {"close": Mock()})()
        with patch.object(database, "client", fake_client):
            database.close_mongo_client()
        fake_client.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
