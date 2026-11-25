import unittest
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import ANY, Mock, patch

from cryptography.fernet import Fernet
import app


class GmailIntegrationTests(unittest.TestCase):
    def setUp(self):
        live_progress = patch.object(app.db, "update_gmail_scan_live_progress")
        live_progress.start()
        self.addCleanup(live_progress.stop)

    def test_bounded_gmail_batch_fetch_handles_partial_failure_in_chunks(self):
        batches = []

        class FakeBatch:
            def __init__(self):
                self.requests = []
                batches.append(self)

            def add(self, request, *, request_id, callback):
                self.requests.append((request_id, callback))

            def execute(self):
                for request_id, callback in self.requests:
                    error = (RuntimeError("synthetic Gmail request failure")
                             if self is batches[0] and request_id == "1" else None)
                    callback(request_id, {"payload": {"headers": []}}, error)

        service = Mock()
        service.new_batch_http_request.side_effect = lambda: FakeBatch()
        with patch("googleapiclient.http.BatchHttpRequest", FakeBatch):
            messages, errors = app._fetch_gmail_messages_batch(
                service, "user-a", [f"message-{index}" for index in range(101)],
            )

        self.assertEqual([len(batch.requests) for batch in batches], [50, 50, 1])
        self.assertEqual(len(messages), 100)
        self.assertEqual(len(errors), 1)
        self.assertIn("message-1", errors)
        self.assertNotIn("message-1", messages)

    def test_gmail_transport_has_finite_timeout_without_changing_oauth_scope(self):
        credentials = object()
        with patch("httplib2.Http") as http_factory, \
             patch("google_auth_httplib2.AuthorizedHttp") as authorized_factory, \
             patch("googleapiclient.discovery.build", return_value=object()) as build:
            result = app._build_gmail_service(credentials)

        self.assertIsNotNone(result)
        http_factory.assert_called_once_with(timeout=app._GMAIL_REQUEST_TIMEOUT_SECONDS)
        authorized_factory.assert_called_once_with(credentials, http=http_factory.return_value)
        build.assert_called_once_with(
            "gmail", "v1", http=authorized_factory.return_value, cache_discovery=False,
        )

    def test_gemini_requests_are_serialized_across_concurrent_scan_threads(self):
        state_lock = app.threading.Lock()
        active = 0
        maximum_active = 0
        assessment = {
            "classification": "Safe", "explanation": "No strong warning found.",
            "risk_indicators": [], "confidence_score": 85,
            "recommended_action": "Verify through a known channel if unsure.",
        }

        def analyze(*args, **kwargs):
            nonlocal active, maximum_active
            with state_lock:
                active += 1
                maximum_active = max(maximum_active, active)
            time.sleep(0.02)
            with state_lock:
                active -= 1
            return assessment

        with patch.object(app.ai_analysis, "analyze_email", side_effect=analyze), \
             patch.object(app.db, "insert_detection", side_effect=[f"saved-{i}" for i in range(4)]):
            with ThreadPoolExecutor(max_workers=4) as pool:
                results = list(pool.map(
                    lambda index: app.analyze_email(
                        "sender@example.test", f"Subject {index}", f"Body {index}", "user-a",
                        analysis_fingerprint=f"fingerprint-{index}",
                    ), range(4),
                ))

        self.assertEqual(len(results), 4)
        self.assertEqual(maximum_active, 1)

    def test_repeated_gemini_timeouts_defer_remaining_messages_without_checkpointing(self):
        service = Mock()
        service.users.return_value.getProfile.return_value.execute.return_value = {
            "emailAddress": "inbox@example.test",
        }
        service.users.return_value.messages.return_value.list.return_value.execute.return_value = {
            "messages": [{"id": f"message-{index}"} for index in range(5)],
            "resultSizeEstimate": 5,
        }
        service.users.return_value.messages.return_value.get.return_value.execute.return_value = {
            "payload": {"headers": []},
        }
        timeout = app.ai_analysis.AnalysisUnavailable(
            "Gemini did not respond in time", 504, "request_timeout",
        )
        with patch("googleapiclient.discovery.build", return_value=service), \
             patch.object(app, "gmail_credentials", return_value=object()), \
             patch.object(app.db, "get_gmail_connection", return_value={
                 "email": "inbox@example.test", "auto_scan_enabled": True,
             }), \
             patch.object(app.db, "get_gmail_detections", return_value={}), \
             patch.object(app.db, "acquire_gmail_scan_lease", return_value=True), \
             patch.object(app.db, "renew_gmail_scan_lease", return_value=True), \
             patch.object(app.db, "release_gmail_scan_lease"), \
             patch.object(app.db, "update_gmail_scan_status") as status, \
             patch.object(app.db, "update_gmail_scan_progress") as checkpoint, \
             patch.object(app, "analyze_email", side_effect=[timeout, timeout, timeout]) as analyze:
            outcome = app.scan_gmail_account("user-a")

        self.assertEqual(analyze.call_count, 3)
        self.assertEqual(outcome["attempted"], 3)
        self.assertEqual(outcome["successful"], 0)
        self.assertEqual(outcome["failed"], 3)
        self.assertEqual(outcome["deferred"], 5)
        self.assertEqual(outcome["status"], "error")
        checkpoint.assert_not_called()
        self.assertEqual(status.call_args_list[-1].kwargs["failed"], 3)
        self.assertEqual(status.call_args_list[-1].kwargs["deferred"], 5)

    def test_single_gmail_fetch_failure_does_not_stop_other_emails_or_advance_cursor(self):
        service = Mock()
        service.users.return_value.getProfile.return_value.execute.return_value = {
            "emailAddress": "inbox@example.test",
        }
        service.users.return_value.messages.return_value.list.return_value.execute.return_value = {
            "messages": [{"id": "good-1"}, {"id": "deferred"}, {"id": "good-2"}],
        }
        full_message = {"payload": {"headers": []}}
        fetch_error = RuntimeError("synthetic Gmail transport failure")
        with patch("googleapiclient.discovery.build", return_value=service), \
             patch.object(app, "gmail_credentials", return_value=object()), \
             patch.object(app.db, "get_gmail_connection", return_value={
                 "email": "inbox@example.test", "last_scan_epoch": 100,
             }), \
             patch.object(app.db, "get_gmail_detections", return_value={}), \
             patch.object(app.db, "acquire_gmail_scan_lease", return_value=True), \
             patch.object(app.db, "renew_gmail_scan_lease", return_value=True), \
             patch.object(app.db, "release_gmail_scan_lease"), \
             patch.object(app.db, "update_gmail_scan_status") as status, \
             patch.object(app.db, "update_gmail_scan_checkpoint") as checkpoint, \
             patch.object(app, "_fetch_gmail_messages_batch", return_value=(
                 {"good-1": full_message, "good-2": full_message},
                 {"deferred": fetch_error},
             )), \
             patch.object(app, "analyze_email", side_effect=[{"id": "saved-1"}, {"id": "saved-2"}]) as analyze:
            outcome = app.scan_gmail_account("user-a")

        self.assertEqual(outcome["attempted"], 3)
        self.assertEqual(outcome["successful"], 2)
        self.assertEqual(outcome["failed"], 1)
        self.assertEqual(outcome["deferred"], 1)
        self.assertEqual(analyze.call_count, 2)
        checkpoint.assert_not_called()
        self.assertEqual(status.call_args_list[-1].kwargs["failed"], 1)

    def test_background_scanner_start_is_idempotent_within_process(self):
        previous_worker = app._gmail_worker
        app._gmail_worker = None
        worker = Mock()
        worker.is_alive.return_value = True
        try:
            with patch.object(app.threading, "Thread", return_value=worker) as factory:
                first = app.start_gmail_scanner_worker()
                second = app.start_gmail_scanner_worker()
            self.assertIs(first, worker)
            self.assertIs(second, worker)
            factory.assert_called_once_with(
                target=app.gmail_scanner_worker, name="gmail-scanner", daemon=True
            )
            worker.start.assert_called_once()
        finally:
            app._gmail_worker = previous_worker

    def test_local_loopback_token_exchange_allows_http_only_during_exchange(self):
        flow = Mock()
        flow.oauth2session.compliance_hook = {"access_token_response": set()}

        def check_scoped_setting(**kwargs):
            self.assertEqual(kwargs["authorization_response"],
                             "http://127.0.0.1:5000/gmail/oauth/callback?code=test")
            self.assertEqual(app.os.environ.get("OAUTHLIB_INSECURE_TRANSPORT"), "1")

        flow.fetch_token.side_effect = check_scoped_setting
        with patch.dict("os.environ", {}, clear=True):
            app.fetch_gmail_oauth_token(
                flow, "http://127.0.0.1:5000/gmail/oauth/callback?code=test",
            )
            self.assertNotIn("OAUTHLIB_INSECURE_TRANSPORT", app.os.environ)
        flow.fetch_token.assert_called_once()

    def test_loopback_transport_setting_is_restored_when_token_exchange_fails(self):
        from oauthlib.oauth2.rfc6749.errors import InsecureTransportError

        flow = Mock()
        flow.oauth2session.compliance_hook = {"access_token_response": set()}
        flow.fetch_token.side_effect = InsecureTransportError()
        with patch.dict("os.environ", {"OAUTHLIB_INSECURE_TRANSPORT": "existing-value"}):
            with self.assertRaises(InsecureTransportError):
                app.fetch_gmail_oauth_token(flow, "http://localhost:5000/callback?code=x")
            self.assertEqual(app.os.environ["OAUTHLIB_INSECURE_TRANSPORT"], "existing-value")

    def test_non_loopback_http_callback_does_not_enable_insecure_transport(self):
        flow = Mock()
        flow.oauth2session.compliance_hook = {"access_token_response": set()}

        def check_not_enabled(**kwargs):
            self.assertNotIn("OAUTHLIB_INSECURE_TRANSPORT", app.os.environ)

        flow.fetch_token.side_effect = check_not_enabled
        with patch.dict("os.environ", {}, clear=True):
            app.fetch_gmail_oauth_token(flow, "http://example.test/callback?code=x")
            self.assertNotIn("OAUTHLIB_INSECURE_TRANSPORT", app.os.environ)

    def test_oauth_callback_exchanges_code_and_saves_encrypted_token_for_session_user(self):
        client = app.app.test_client()
        with client.session_transaction(base_url="http://127.0.0.1:5000") as session:
            session["user_id"] = "user-a"
            session["name"] = "User A"
            session["role"] = "user"
            session["gmail_oauth_state"] = "bound-state"
            session["gmail_oauth_redirect_uri"] = "http://127.0.0.1:5000/gmail/oauth/callback"
            session["gmail_oauth_code_verifier"] = "encrypted-verifier"
            session["gmail_oauth_pkce_required"] = True
        flow = Mock()
        flow.credentials.to_json.return_value = '{"access_token":"synthetic"}'
        service = Mock()
        service.users.return_value.getProfile.return_value.execute.return_value = {
            "emailAddress": "owner@example.test",
        }
        with patch.object(app, "make_gmail_flow", return_value=flow) as make_flow, \
             patch.object(app, "fetch_gmail_oauth_token") as fetch_token, \
             patch.object(app, "decrypt_gmail_token", return_value="test-code-verifier") as decrypt_verifier, \
             patch("googleapiclient.discovery.build", return_value=service), \
             patch.object(app, "encrypt_gmail_token", return_value="encrypted-test-token") as encrypt, \
             patch.object(app.db, "save_gmail_connection") as save, \
             patch.object(app.db, "get_gmail_connection", return_value={"auto_scan_enabled": True}):
            response = client.get(
                "/gmail/oauth/callback?state=bound-state",
                base_url="http://127.0.0.1:5000",
            )
        self.assertEqual(response.status_code, 302)
        make_flow.assert_called_once_with(
            state="bound-state", redirect_uri="http://127.0.0.1:5000/gmail/oauth/callback",
            code_verifier="test-code-verifier",
        )
        fetch_token.assert_called_once_with(flow, ANY)
        decrypt_verifier.assert_called_once_with("encrypted-verifier")
        self.assertTrue(fetch_token.call_args.args[1].startswith("http://127.0.0.1:5000/"))
        encrypt.assert_called_once_with('{"access_token":"synthetic"}')
        save.assert_called_once_with("user-a", "owner@example.test", "encrypted-test-token")

    def test_oauth_state_mismatch_never_exchanges_or_saves_credentials(self):
        client = app.app.test_client()
        with client.session_transaction() as session:
            session["user_id"] = "user-a"
            session["name"] = "User A"
            session["role"] = "user"
            session["gmail_oauth_state"] = "expected-state"
            session["gmail_oauth_redirect_uri"] = "http://localhost:5000/gmail/oauth/callback"
        with patch.object(app, "make_gmail_flow") as make_flow, \
             patch.object(app.db, "save_gmail_connection") as save:
            response = client.get("/gmail/oauth/callback?state=wrong-state")
        self.assertEqual(response.status_code, 302)
        make_flow.assert_not_called()
        save.assert_not_called()

    def test_callback_rejects_missing_verifier_when_pkce_was_requested(self):
        client = app.app.test_client()
        with client.session_transaction(base_url="http://127.0.0.1:5000") as session:
            session["user_id"] = "user-a"
            session["name"] = "User A"
            session["role"] = "user"
            session["gmail_oauth_state"] = "bound-state"
            session["gmail_oauth_redirect_uri"] = "http://127.0.0.1:5000/gmail/oauth/callback"
            session["gmail_oauth_pkce_required"] = True
        with patch.object(app, "make_gmail_flow") as make_flow, \
             patch.object(app.db, "save_gmail_connection") as save:
            response = client.get(
                "/gmail/oauth/callback?state=bound-state",
                base_url="http://127.0.0.1:5000",
            )
        self.assertEqual(response.status_code, 302)
        make_flow.assert_not_called()
        save.assert_not_called()

    def test_oauth_callback_exchange_error_is_sanitized_and_does_not_connect_account(self):
        from oauthlib.oauth2.rfc6749.errors import InvalidGrantError

        invalid_grant_error = InvalidGrantError(description="Authorization code has expired")
        invalid_grant_error._gmail_oauth_diagnostics = {
            "http_status": 400, "description": "Authorization code has expired",
        }
        client = app.app.test_client()
        with client.session_transaction(base_url="http://127.0.0.1:5000") as session:
            session["user_id"] = "user-a"
            session["name"] = "User A"
            session["role"] = "user"
            session["gmail_oauth_state"] = "bound-state"
            session["gmail_oauth_redirect_uri"] = "http://127.0.0.1:5000/gmail/oauth/callback"
            session["gmail_oauth_code_verifier"] = "encrypted-verifier"
            session["gmail_oauth_pkce_required"] = True
        with patch.object(app, "make_gmail_flow", return_value=Mock()), \
             patch.object(app, "decrypt_gmail_token", return_value="test-code-verifier"), \
             patch.object(app, "fetch_gmail_oauth_token",
                          side_effect=invalid_grant_error), \
             patch.object(app.db, "save_gmail_connection") as save, \
             patch.object(app.app.logger, "error") as log_error:
            response = client.get(
                "/gmail/oauth/callback?state=bound-state",
                base_url="http://127.0.0.1:5000",
            )
        self.assertEqual(response.status_code, 302)
        save.assert_not_called()
        self.assertNotIn("private provider detail", response.get_data(as_text=True))
        self.assertIn("category=%s", log_error.call_args.args[0])
        self.assertEqual(log_error.call_args.args[1], "invalid_grant")
        self.assertEqual(log_error.call_args.args[2], "invalid_grant")
        self.assertEqual(log_error.call_args.args[3], "Authorization code has expired")
        self.assertEqual(log_error.call_args.args[4], 400)
        self.assertNotIn("code=", str(log_error.call_args).lower())
        self.assertNotIn("http://", str(log_error.call_args).lower())

    def test_invalid_grant_logs_safe_category_and_provider_details(self):
        from oauthlib.oauth2.rfc6749.errors import InvalidGrantError

        error = InvalidGrantError(description="Authorization code has expired")
        code, description, status = app._oauth_provider_diagnostics(error)
        self.assertEqual(code, "invalid_grant")
        self.assertEqual(description, "Authorization code has expired")
        self.assertEqual(status, "unavailable")
        self.assertEqual(type(error).__name__, "InvalidGrantError")

    def test_google_oauth_configuration_uses_expected_environment_variable_names(self):
        with patch.dict("os.environ", {
            "GOOGLE_CLIENT_ID": "synthetic-client-id",
            "GOOGLE_CLIENT_SECRET": "synthetic-client-secret",
        }, clear=True):
            self.assertTrue(app.google_oauth_configured())
        with patch.dict("os.environ", {"GOOGLE_CLIENT_ID": "", "GOOGLE_CLIENT_SECRET": ""}, clear=True):
            self.assertFalse(app.google_oauth_configured())

    def test_installed_flow_retains_pkce_verifier_for_token_exchange(self):
        with patch.dict("os.environ", {
            "GOOGLE_CLIENT_ID": "synthetic-client-id",
            "GOOGLE_CLIENT_SECRET": "synthetic-client-secret",
        }, clear=True), app.app.test_request_context(
            "/gmail/connect", base_url="http://127.0.0.1:5000",
        ):
            authorization_flow = app.make_gmail_flow()
            authorization_url, state = authorization_flow.authorization_url()
            verifier = authorization_flow.code_verifier
            self.assertIn("code_challenge=", authorization_url)
            self.assertTrue(verifier)

            callback_flow = app.make_gmail_flow(
                state=state, redirect_uri=authorization_flow.redirect_uri,
                code_verifier=verifier,
            )
            callback_url = authorization_flow.redirect_uri + "?code=mock-code&state=" + state
            with patch.object(callback_flow.oauth2session, "fetch_token",
                              return_value={"access_token": "mock-access-token"}) as exchange:
                callback_flow.fetch_token(authorization_response=callback_url)
            exchange.assert_called_once()
            self.assertEqual(exchange.call_args.args[0], "https://oauth2.googleapis.com/token")
            self.assertEqual(exchange.call_args.kwargs["code_verifier"], verifier)
            self.assertEqual(callback_flow.redirect_uri, authorization_flow.redirect_uri)

    def test_token_endpoint_error_diagnostics_capture_status_and_scrub_secrets(self):
        from oauthlib.oauth2.rfc6749.errors import InvalidGrantError

        class FakeResponse:
            status_code = 400

            def json(self):
                return {"error": "invalid_grant",
                        "error_description": "Authorization code=secret-code expired at https://example.test/path"}

        class FakeOAuthSession:
            compliance_hook = {"access_token_response": set()}

        class FakeFlow:
            oauth2session = FakeOAuthSession()

            def fetch_token(self, **kwargs):
                for hook in tuple(self.oauth2session.compliance_hook["access_token_response"]):
                    hook(FakeResponse())
                raise InvalidGrantError(description="provider rejected the grant")

        flow = FakeFlow()
        with self.assertRaises(InvalidGrantError) as raised:
            app.fetch_gmail_oauth_token(
                flow, "http://127.0.0.1:5000/gmail/oauth/callback?code=mock&state=mock",
            )
        code, description, status = app._oauth_provider_diagnostics(raised.exception)
        self.assertEqual(code, "invalid_grant")
        self.assertEqual(status, 400)
        self.assertIn("(redacted)", description)
        self.assertIn("[url]", description)
        self.assertNotIn("secret-code", description)
        self.assertNotIn("example.test", description)
        self.assertFalse(flow.oauth2session.compliance_hook["access_token_response"])

    def test_connect_route_stores_the_exact_authorization_redirect_uri(self):
        client = app.app.test_client()
        with client.session_transaction(base_url="http://127.0.0.1:5000") as session:
            session["user_id"] = "user-a"
            session["name"] = "User A"
            session["role"] = "user"
        flow = Mock()
        flow.redirect_uri = "http://127.0.0.1:5000/gmail/oauth/callback"
        flow.code_verifier = "synthetic-code-verifier"
        flow.authorization_url.return_value = ("https://accounts.google.test/authorize", "bound-state")
        with patch.dict("os.environ", {
            "GOOGLE_CLIENT_ID": "synthetic-client-id",
            "GOOGLE_CLIENT_SECRET": "synthetic-client-secret",
            "GMAIL_TOKEN_ENCRYPTION_KEY": "configured",
        }, clear=True), \
             patch.object(app, "make_gmail_flow", return_value=flow), \
             patch.object(app, "encrypt_gmail_token", return_value="encrypted-verifier") as encrypt_verifier:
            response = client.get("/gmail/connect", base_url="http://127.0.0.1:5000")
        self.assertEqual(response.status_code, 302)
        with client.session_transaction(base_url="http://127.0.0.1:5000") as session:
            self.assertEqual(session["gmail_oauth_state"], "bound-state")
            self.assertEqual(session["gmail_oauth_redirect_uri"], flow.redirect_uri)
            self.assertEqual(session["gmail_oauth_code_verifier"], "encrypted-verifier")
            self.assertTrue(session["gmail_oauth_pkce_required"])
        encrypt_verifier.assert_called_once_with("synthetic-code-verifier")

    def test_read_only_scope_and_token_encryption_round_trip(self):
        self.assertEqual(app.GMAIL_SCOPES, ["https://www.googleapis.com/auth/gmail.readonly"])
        key = Fernet.generate_key().decode()
        with patch.dict("os.environ", {"GMAIL_TOKEN_ENCRYPTION_KEY": key}):
            ciphertext = app.encrypt_gmail_token('{"access_token":"synthetic-test-token"}')
            self.assertNotIn("synthetic-test-token", ciphertext)
            self.assertEqual(
                app.decrypt_gmail_token(ciphertext),
                '{"access_token":"synthetic-test-token"}',
            )

    def test_scan_fetches_and_analyzes_messages_without_changing_mail(self):
        service = Mock()
        service.users.return_value.getProfile.return_value.execute.return_value = {
            "emailAddress": "inbox@example.test",
        }
        service.users.return_value.messages.return_value.list.return_value.execute.return_value = {
            "messages": [{"id": "message-1"}],
        }
        service.users.return_value.messages.return_value.get.return_value.execute.return_value = {
            "payload": {"headers": [
                {"name": "From", "value": "Sender <sender@example.test>"},
                {"name": "Subject", "value": "Synthetic test"},
            ]},
        }
        with patch("googleapiclient.discovery.build", return_value=service) as build, \
             patch.object(app, "gmail_credentials", return_value=object()), \
             patch.object(app.db, "get_gmail_connection", return_value={
                 "email": "inbox@example.test", "last_scan_epoch": 100,
                 "auto_scan_enabled": True,
             }), \
             patch.object(app.db, "get_gmail_detections", return_value={}), \
             patch.object(app.db, "acquire_gmail_scan_lease", return_value=True), \
             patch.object(app.db, "renew_gmail_scan_lease", return_value=True), \
             patch.object(app.db, "release_gmail_scan_lease") as release, \
             patch.object(app.db, "update_gmail_scan_status") as status, \
             patch.object(app.db, "update_gmail_scan_checkpoint") as checkpoint, \
             patch.object(app, "analyze_email", return_value={"id": "saved-id"}) as analyze:
            outcome = app.scan_gmail_account("user-id")

        self.assertEqual(outcome["scanned"], 1)
        self.assertEqual(outcome["new"], 1)
        self.assertEqual(outcome["email"], "inbox@example.test")
        build.assert_called_once_with("gmail", "v1", http=ANY,
                                     cache_discovery=False)
        analyze.assert_called_once()
        self.assertEqual(analyze.call_args.args[:4], (
            "sender@example.test", "Synthetic test", "(Email body could not be extracted.)", "user-id",
        ))
        self.assertEqual(analyze.call_args.args[4], "message-1")
        self.assertTrue(analyze.call_args.kwargs["notify_new_fraud"])
        self.assertIn("after:", service.users.return_value.messages.return_value.list.call_args.kwargs["q"])
        checkpoint.assert_called_once()
        release.assert_called_once()
        self.assertEqual(status.call_args_list[-1].args[1], "success")
        self.assertFalse(any("send" in call[0].lower() for call in service.method_calls))

    def test_gemini_timeout_defers_one_email_and_continues_incremental_scan(self):
        service = Mock()
        service.users.return_value.getProfile.return_value.execute.return_value = {
            "emailAddress": "inbox@example.test",
        }
        service.users.return_value.messages.return_value.list.return_value.execute.return_value = {
            "messages": [{"id": "timeout-message"}, {"id": "successful-message"}],
        }
        service.users.return_value.messages.return_value.get.return_value.execute.return_value = {
            "payload": {"headers": [{"name": "Subject", "value": "Private subject"}]},
        }
        failure = app.ai_analysis.AnalysisUnavailable(
            "Gemini did not respond in time", 504, "request_timeout",
        )
        with patch("googleapiclient.discovery.build", return_value=service), \
             patch.object(app, "gmail_credentials", return_value=object()), \
             patch.object(app, "_gmail_payload_text", return_value="PRIVATE EMAIL BODY"), \
             patch.object(app.db, "get_gmail_connection", return_value={
                 "email": "inbox@example.test", "last_scan_epoch": 100,
                 "auto_scan_enabled": True,
             }), \
             patch.object(app.db, "get_gmail_detections", return_value={}) as get_detections, \
             patch.object(app.db, "acquire_gmail_scan_lease", return_value=True), \
             patch.object(app.db, "renew_gmail_scan_lease", return_value=True), \
             patch.object(app.db, "release_gmail_scan_lease") as release, \
             patch.object(app.db, "update_gmail_scan_status") as status, \
             patch.object(app.db, "update_gmail_scan_checkpoint") as checkpoint, \
             patch.object(app, "analyze_email", side_effect=[failure, {"id": "saved-id"}]) as analyze, \
             self.assertLogs(app.app.logger, level="WARNING") as captured:
            outcome = app.scan_gmail_account("user-a")

        self.assertEqual(outcome["status"], "error")
        self.assertEqual(outcome["failed"], 1)
        self.assertEqual(outcome["scanned"], 1)
        self.assertEqual(analyze.call_count, 2)
        self.assertTrue(all(call.args[3] == "user-a" for call in analyze.call_args_list))
        self.assertEqual(get_detections.call_count, 1)
        self.assertEqual(get_detections.call_args.args[0], "user-a")
        self.assertEqual(get_detections.call_args.args[1], ["timeout-message", "successful-message"])
        self.assertEqual(status.call_args_list[-1].args[1], "error")
        self.assertEqual(status.call_args_list[-1].kwargs["error_category"], "gemini_request_timeout")
        self.assertIsNone(status.call_args_list[-1].kwargs["http_status"])
        checkpoint.assert_not_called()
        release.assert_called_once()
        log_output = " ".join(captured.output)
        self.assertNotIn("PRIVATE EMAIL BODY", log_output)
        self.assertNotIn("Private subject", log_output)

    def test_partial_historical_scan_stops_after_failed_page_and_defers_later_pages(self):
        service = Mock()
        service.users.return_value.getProfile.return_value.execute.return_value = {
            "emailAddress": "inbox@example.test",
        }
        service.users.return_value.messages.return_value.list.return_value.execute.side_effect = [
            {"messages": [{"id": "failed-message"}, {"id": "page-one-success"}],
             "nextPageToken": "page-two", "resultSizeEstimate": 5},
            {"messages": [{"id": "page-two-success"}]},
        ]
        service.users.return_value.messages.return_value.get.return_value.execute.return_value = {
            "payload": {"headers": [{"name": "Subject", "value": "Historical message"}]},
        }
        failure = app.ai_analysis.AnalysisUnavailable(
            "Gemini is temporarily unavailable", 503, "provider_unavailable", 503,
        )
        with patch("googleapiclient.discovery.build", return_value=service), \
             patch.object(app, "gmail_credentials", return_value=object()), \
             patch.object(app.db, "get_gmail_connection", return_value={
                 "email": "inbox@example.test", "auto_scan_enabled": True,
             }), \
             patch.object(app.db, "get_gmail_detections", return_value={}), \
             patch.object(app.db, "acquire_gmail_scan_lease", return_value=True), \
             patch.object(app.db, "renew_gmail_scan_lease", return_value=True), \
             patch.object(app.db, "release_gmail_scan_lease"), \
             patch.object(app.db, "update_gmail_scan_status") as status, \
             patch.object(app.db, "update_gmail_scan_progress") as progress, \
             patch.object(app.db, "update_gmail_scan_live_progress") as live_progress, \
             patch.object(app.db, "finish_gmail_historical_scan") as finish, \
             patch.object(app, "analyze_email", side_effect=[failure, {"id": "saved-1"}]) as analyze:
            outcome = app.scan_gmail_account("user-a")

        self.assertEqual(outcome["status"], "error")
        self.assertEqual(outcome["failed"], 1)
        self.assertEqual(outcome["deferred"], 4)
        self.assertEqual(outcome["scanned"], 1)
        self.assertEqual(analyze.call_count, 2)
        self.assertEqual(service.users.return_value.messages.return_value.list.call_count, 1)
        self.assertTrue(all(call.args[3] == "user-a" for call in analyze.call_args_list))
        self.assertEqual(status.call_args_list[-1].kwargs["error_category"], "gemini_provider_unavailable")
        self.assertEqual(status.call_args_list[-1].kwargs["http_status"], 503)
        self.assertEqual(status.call_args_list[-1].kwargs["deferred"], 4)
        progress.assert_not_called()
        self.assertEqual(live_progress.call_args_list[-1].kwargs["processed"], 2)
        self.assertEqual(live_progress.call_args_list[-1].kwargs["failed"], 1)
        finish.assert_not_called()

    def test_gemini_circuit_opens_without_counting_unrequested_emails_as_failures(self):
        service = Mock()
        service.users.return_value.getProfile.return_value.execute.return_value = {
            "emailAddress": "inbox@example.test",
        }
        ids = [f"message-{index}" for index in range(10)]
        service.users.return_value.messages.return_value.list.return_value.execute.side_effect = [
            {"messages": [{"id": item} for item in ids],
             "nextPageToken": "next-page", "resultSizeEstimate": 201},
        ]
        service.users.return_value.messages.return_value.get.return_value.execute.return_value = {
            "payload": {"headers": []},
        }
        failure = app.ai_analysis.AnalysisUnavailable(
            "Gemini temporarily unavailable", 503, "provider_unavailable", 503,
        )
        with patch("googleapiclient.discovery.build", return_value=service), \
             patch.object(app, "gmail_credentials", return_value=object()), \
             patch.object(app.db, "get_gmail_connection", return_value={
                 "email": "inbox@example.test", "auto_scan_enabled": True,
             }), \
             patch.object(app.db, "get_gmail_detections", return_value={}), \
             patch.object(app.db, "acquire_gmail_scan_lease", return_value=True), \
             patch.object(app.db, "renew_gmail_scan_lease", return_value=True), \
             patch.object(app.db, "release_gmail_scan_lease"), \
             patch.object(app.db, "update_gmail_scan_status") as status, \
             patch.object(app.db, "update_gmail_scan_progress") as checkpoint, \
             patch.object(app.db, "update_gmail_scan_live_progress") as live_progress, \
             patch.object(app, "analyze_email", side_effect=[failure, failure, failure]) as analyze, \
             self.assertLogs(app.app.logger, level="INFO") as captured:
            outcome = app.scan_gmail_account("user-a")

        self.assertEqual(analyze.call_count, 3)
        self.assertEqual(outcome["attempted"], 3)
        self.assertEqual(outcome["successful"], 0)
        self.assertEqual(outcome["failed"], 3)
        self.assertEqual(outcome["deferred"], 201)
        self.assertEqual(outcome["status"], "error")
        self.assertEqual(service.users.return_value.messages.return_value.list.call_count, 1)
        checkpoint.assert_not_called()
        self.assertEqual(status.call_args_list[-1].kwargs["deferred"], 201)
        self.assertEqual(live_progress.call_args_list[-1].kwargs["processed"], 3)
        self.assertEqual(live_progress.call_args_list[-1].kwargs["failed"], 3)
        diagnostic = " ".join(captured.output)
        self.assertIn("estimated_messages=201", diagnostic)
        self.assertIn("attempted=3", diagnostic)
        self.assertIn("duplicate_ids_skipped=0", diagnostic)
        self.assertNotIn("inbox@example.test", diagnostic)

    def test_duplicate_message_ids_are_only_fetched_and_attempted_once_per_scan(self):
        service = Mock()
        service.users.return_value.getProfile.return_value.execute.return_value = {
            "emailAddress": "inbox@example.test",
        }
        service.users.return_value.messages.return_value.list.return_value.execute.return_value = {
            "messages": [{"id": "duplicate"}, {"id": "duplicate"}, {"id": "unique"}],
            "resultSizeEstimate": 2,
        }
        service.users.return_value.messages.return_value.get.return_value.execute.return_value = {
            "payload": {"headers": []},
        }
        with patch("googleapiclient.discovery.build", return_value=service), \
             patch.object(app, "gmail_credentials", return_value=object()), \
             patch.object(app.db, "get_gmail_connection", return_value={
                 "email": "inbox@example.test", "last_scan_epoch": 100,
             }), \
             patch.object(app.db, "get_gmail_detections", return_value={}) as get_detections, \
             patch.object(app.db, "acquire_gmail_scan_lease", return_value=True), \
             patch.object(app.db, "renew_gmail_scan_lease", return_value=True), \
             patch.object(app.db, "release_gmail_scan_lease"), \
             patch.object(app.db, "update_gmail_scan_status"), \
             patch.object(app.db, "update_gmail_scan_checkpoint"), \
             patch.object(app, "analyze_email", side_effect=[{"id": "saved-1"}, {"id": "saved-2"}]) as analyze:
            outcome = app.scan_gmail_account("user-a")

        self.assertEqual(outcome["attempted"], 2)
        self.assertEqual(outcome["successful"], 2)
        self.assertEqual(outcome["failed"], 0)
        self.assertEqual(analyze.call_count, 2)
        self.assertEqual(get_detections.call_args.args[1], ["duplicate", "unique"])
        self.assertEqual(service.users.return_value.messages.return_value.get.call_count, 2)

    def test_repeated_gemini_504s_advance_attempt_progress_without_committing_failed_page(self):
        service = Mock()
        service.users.return_value.getProfile.return_value.execute.return_value = {
            "emailAddress": "inbox@example.test",
        }
        first_page_ids = [f"message-{index}" for index in range(25)]
        service.users.return_value.messages.return_value.list.return_value.execute.side_effect = [
            {"messages": [{"id": item} for item in first_page_ids],
             "nextPageToken": "resume-before-failures", "resultSizeEstimate": 201},
            {"messages": [{"id": "failed-26"}, {"id": "message-27"},
                          {"id": "failed-28"}], "nextPageToken": "page-three",
             "resultSizeEstimate": 201},
        ]
        service.users.return_value.messages.return_value.get.return_value.execute.return_value = {
            "payload": {"headers": [{"name": "Subject", "value": "Synthetic subject"}]},
        }
        provider_504 = app.ai_analysis.AnalysisUnavailable(
            "Gemini is temporarily unavailable", 503, "provider_unavailable", 504,
        )
        analysis_results = ([{"id": f"saved-{index}"} for index in range(25)]
                            + [provider_504, {"id": "saved-27"}, provider_504])
        with patch("googleapiclient.discovery.build", return_value=service), \
             patch.object(app, "gmail_credentials", return_value=object()), \
             patch.object(app.db, "get_gmail_connection", return_value={
                 "email": "inbox@example.test", "auto_scan_enabled": True,
             }), \
             patch.object(app.db, "get_gmail_detections", return_value={}) as cached, \
             patch.object(app.db, "acquire_gmail_scan_lease", return_value=True), \
             patch.object(app.db, "renew_gmail_scan_lease", return_value=True), \
             patch.object(app.db, "release_gmail_scan_lease"), \
             patch.object(app.db, "update_gmail_scan_status") as status, \
             patch.object(app.db, "update_gmail_scan_progress") as checkpoint, \
             patch.object(app.db, "update_gmail_scan_live_progress") as live_progress, \
             patch.object(app.db, "finish_gmail_historical_scan") as finish, \
             patch.object(app, "analyze_email", side_effect=analysis_results) as analyze:
            outcome = app.scan_gmail_account("user-a")

        self.assertEqual(outcome["status"], "error")
        self.assertEqual(outcome["failed"], 2)
        self.assertEqual(outcome["deferred"], 175)
        self.assertEqual(outcome["scanned"], 26)
        self.assertEqual(analyze.call_count, 28)
        self.assertEqual(cached.call_count, 2)
        self.assertTrue(all(call.args[0] == "user-a" for call in cached.call_args_list))
        self.assertTrue(all(call.args[3] == "user-a" for call in analyze.call_args_list))
        self.assertEqual(status.call_args_list[-1].kwargs["scanned"], 26)
        self.assertEqual(status.call_args_list[-1].kwargs["failed"], 2)
        self.assertEqual(status.call_args_list[-1].kwargs["error_category"],
                         "gemini_provider_unavailable")
        self.assertEqual(status.call_args_list[-1].kwargs["http_status"], 504)
        self.assertEqual(status.call_args_list[-1].kwargs["deferred"], 175)
        checkpoint.assert_called_once_with(
            "user-a", page_token="resume-before-failures", processed=25,
            total=201, historical=True,
        )
        self.assertEqual(live_progress.call_args_list[-1].kwargs["processed"], 28)
        self.assertEqual(live_progress.call_args_list[-1].kwargs["failed"], 2)
        self.assertTrue(all(call.args[0] == "user-a" for call in live_progress.call_args_list))
        finish.assert_not_called()

    def test_initial_historical_scan_saves_analysis_without_alert_policy(self):
        service = Mock()
        service.users.return_value.getProfile.return_value.execute.return_value = {
            "emailAddress": "inbox@example.test",
        }
        service.users.return_value.messages.return_value.list.return_value.execute.return_value = {
            "messages": [{"id": "old-message"}],
        }
        service.users.return_value.messages.return_value.get.return_value.execute.return_value = {
            "payload": {"headers": [{"name": "Subject", "value": "Old message"}]},
        }
        with patch("googleapiclient.discovery.build", return_value=service), \
             patch.object(app, "gmail_credentials", return_value=object()), \
             patch.object(app.db, "get_gmail_connection", return_value={
                 "email": "inbox@example.test", "auto_scan_enabled": True,
             }), \
             patch.object(app.db, "get_gmail_detections", return_value={}), \
             patch.object(app.db, "acquire_gmail_scan_lease", return_value=True), \
             patch.object(app.db, "renew_gmail_scan_lease", return_value=True), \
             patch.object(app.db, "release_gmail_scan_lease"), \
             patch.object(app.db, "update_gmail_scan_status"), \
             patch.object(app.db, "update_gmail_scan_progress") as progress, \
             patch.object(app.db, "update_gmail_scan_live_progress") as live_progress, \
             patch.object(app.db, "finish_gmail_historical_scan") as finish, \
             patch.object(app, "analyze_email", return_value={"id": "saved-old"}) as analyze:
            result = app.scan_gmail_account("user-id", automatic=True)
        self.assertEqual(result["status"], "success")
        self.assertFalse(analyze.call_args.kwargs["notify_new_fraud"])
        self.assertEqual("in:inbox", service.users.return_value.messages.return_value.list.call_args.kwargs["q"])
        progress.assert_called_once_with("user-id", page_token=None, processed=1,
                                         total=None, historical=True)
        self.assertEqual(live_progress.call_args_list[-1].kwargs["processed"], 1)
        finish.assert_called_once()

    def test_unchanged_gmail_message_reuses_saved_analysis_without_gemini(self):
        service = Mock()
        service.users.return_value.getProfile.return_value.execute.return_value = {
            "emailAddress": "inbox@example.test",
        }
        service.users.return_value.messages.return_value.list.return_value.execute.return_value = {
            "messages": [{"id": "existing-message"}],
        }
        headers = [{"name": "From", "value": "sender@example.test"},
                   {"name": "Subject", "value": "Existing"}]
        service.users.return_value.messages.return_value.get.return_value.execute.return_value = {
            "payload": {"headers": headers},
        }
        fingerprint = app._gmail_analysis_fingerprint(
            "sender@example.test", "Existing", "(Email body could not be extracted.)",
            {"from": "sender@example.test", "subject": "Existing"},
        )
        connection = {"email": "inbox@example.test", "last_scan_epoch": 100,
                      "auto_scan_enabled": True}
        with patch("googleapiclient.discovery.build", return_value=service), \
             patch.object(app, "gmail_credentials", return_value=object()), \
             patch.object(app.db, "get_gmail_connection", return_value=connection), \
             patch.object(app.db, "get_gmail_detections", return_value={"existing-message": {"_id": "saved-id", "analysis_fingerprint": fingerprint}}) as cached, \
             patch.object(app.db, "acquire_gmail_scan_lease", return_value=True), \
             patch.object(app.db, "renew_gmail_scan_lease", return_value=True), \
             patch.object(app.db, "release_gmail_scan_lease"), \
             patch.object(app.db, "update_gmail_scan_status"), \
             patch.object(app.db, "update_gmail_scan_checkpoint"), \
             patch.object(app, "analyze_email") as analyze:
            result = app.scan_gmail_account("user-a", automatic=True)
        self.assertEqual(result["scanned"], 1)
        self.assertEqual(result["new"], 0)
        cached.assert_called_once_with("user-a", ["existing-message"])
        analyze.assert_not_called()

    def test_initial_scan_processes_pages_and_resumes_from_saved_cursor(self):
        service = Mock()
        service.users.return_value.getProfile.return_value.execute.return_value = {
            "emailAddress": "inbox@example.test",
        }
        list_execute = service.users.return_value.messages.return_value.list.return_value.execute
        list_execute.return_value = {"messages": [{"id": "page-two"}], "resultSizeEstimate": 2}
        service.users.return_value.messages.return_value.get.return_value.execute.return_value = {
            "payload": {"headers": []},
        }
        connection = {"email": "inbox@example.test", "auto_scan_enabled": True,
                      "historical_page_token": "resume-token", "scan_progress_count": 1}
        with patch("googleapiclient.discovery.build", return_value=service), \
             patch.object(app, "gmail_credentials", return_value=object()), \
             patch.object(app.db, "get_gmail_connection", return_value=connection), \
             patch.object(app.db, "get_gmail_detections", return_value={}), \
             patch.object(app.db, "acquire_gmail_scan_lease", return_value=True), \
             patch.object(app.db, "renew_gmail_scan_lease", return_value=True), \
             patch.object(app.db, "release_gmail_scan_lease"), \
             patch.object(app.db, "update_gmail_scan_status"), \
             patch.object(app.db, "update_gmail_scan_progress") as progress, \
             patch.object(app.db, "update_gmail_scan_live_progress"), \
             patch.object(app.db, "finish_gmail_historical_scan") as finish, \
             patch.object(app, "analyze_email", return_value={"id": "saved"}) as analyze:
            outcome = app.scan_gmail_account("user-id", automatic=True)
        self.assertEqual(outcome["scanned"], 1)
        self.assertEqual(analyze.call_count, 1)
        self.assertFalse(analyze.call_args.kwargs["notify_new_fraud"])
        self.assertEqual(service.users.return_value.messages.return_value.list.call_args.kwargs["pageToken"], "resume-token")
        progress.assert_called_once_with("user-id", page_token=None, processed=2,
                                         total=2, historical=True)
        finish.assert_called_once_with("user-id", ANY, 2)

    def test_initial_history_scan_follows_all_bounded_gmail_pages(self):
        service = Mock()
        service.users.return_value.getProfile.return_value.execute.return_value = {
            "emailAddress": "inbox@example.test",
        }
        service.users.return_value.messages.return_value.list.return_value.execute.side_effect = [
            {"messages": [{"id": "old-1"}], "nextPageToken": "page-2", "resultSizeEstimate": 2},
            {"messages": [{"id": "old-2"}], "resultSizeEstimate": 2},
        ]
        service.users.return_value.messages.return_value.get.return_value.execute.return_value = {
            "payload": {"headers": []},
        }
        with patch("googleapiclient.discovery.build", return_value=service), \
             patch.object(app, "gmail_credentials", return_value=object()), \
             patch.object(app.db, "get_gmail_connection", return_value={
                 "email": "inbox@example.test", "auto_scan_enabled": True,
             }), \
             patch.object(app.db, "get_gmail_detections", return_value={}), \
             patch.object(app.db, "acquire_gmail_scan_lease", return_value=True), \
             patch.object(app.db, "renew_gmail_scan_lease", return_value=True), \
             patch.object(app.db, "release_gmail_scan_lease"), \
             patch.object(app.db, "update_gmail_scan_status"), \
             patch.object(app.db, "update_gmail_scan_progress") as progress, \
             patch.object(app.db, "update_gmail_scan_live_progress"), \
             patch.object(app.db, "finish_gmail_historical_scan") as finish, \
             patch.object(app, "analyze_email", return_value={"id": "saved"}) as analyze:
            outcome = app.scan_gmail_account("user-id")
        self.assertEqual(outcome["scanned"], 2)
        self.assertEqual(analyze.call_count, 2)
        self.assertTrue(all(call.kwargs["maxResults"] == 100
                            for call in service.users.return_value.messages.return_value.list.call_args_list))
        self.assertEqual(service.users.return_value.messages.return_value.list.call_args_list[1].kwargs["pageToken"], "page-2")
        self.assertEqual(progress.call_count, 2)
        finish.assert_called_once_with("user-id", ANY, 2)

    def test_automatic_scan_skips_when_user_disabled_it(self):
        with patch.object(app.db, "get_gmail_connection", return_value={
                "auto_scan_enabled": False}), \
             patch.object(app.db, "acquire_gmail_scan_lease") as claim, \
             patch.object(app, "gmail_credentials") as credentials:
            result = app.scan_gmail_account("user-id", automatic=True)
        self.assertTrue(result["skipped"])
        claim.assert_not_called()
        credentials.assert_not_called()

    def test_background_scan_cycle_runs_incremental_scan_for_connected_user(self):
        with patch.object(app.db, "get_gmail_connections", return_value=[
                {"user_id": "user-a", "auto_scan_enabled": True}]), \
             patch.object(app, "scan_gmail_account", return_value={"new": 0}) as scan:
            app.scan_all_connected_gmail_accounts()
        scan.assert_called_once_with("user-a", automatic=True)

    def test_second_worker_does_not_scan_the_same_account_while_lease_is_held(self):
        with patch.object(app.db, "get_gmail_connection", return_value={
                "auto_scan_enabled": True}), \
             patch.object(app.db, "acquire_gmail_scan_lease", return_value=False), \
             patch.object(app, "gmail_credentials") as credentials:
            result = app.scan_gmail_account("user-id", automatic=True)
        self.assertEqual(result["reason"], "scan_in_progress")
        credentials.assert_not_called()

    def test_scan_failure_updates_status_and_releases_account_lease(self):
        with patch.object(app.db, "get_gmail_connection", return_value={
                "email": "inbox@example.test", "auto_scan_enabled": True}), \
             patch.object(app.db, "acquire_gmail_scan_lease", return_value=True), \
             patch.object(app.db, "update_gmail_scan_status") as status, \
             patch.object(app.db, "release_gmail_scan_lease") as release, \
             patch.object(app, "gmail_credentials", return_value=object()), \
             patch("googleapiclient.discovery.build", side_effect=TimeoutError("private network details")):
            with self.assertRaises(TimeoutError):
                app.scan_gmail_account("user-id")
        self.assertEqual(status.call_args_list[-1].args[1], "error")
        self.assertEqual(status.call_args_list[-1].kwargs["error_code"], "TimeoutError")
        release.assert_called_once()

    def test_scan_reports_gemini_category_and_status_without_email_contents(self):
        service = Mock()
        service.users.return_value.getProfile.return_value.execute.return_value = {
            "emailAddress": "inbox@example.test",
        }
        service.users.return_value.messages.return_value.list.return_value.execute.return_value = {
            "messages": [{"id": "message-private"}],
        }
        private_body = "PRIVATE EMAIL BODY MUST NOT APPEAR IN LOGS"
        service.users.return_value.messages.return_value.get.return_value.execute.return_value = {
            "payload": {"headers": [{"name": "Subject", "value": "Private subject"}]},
        }
        # Mock parsing directly to avoid coupling this test to MIME/base64 details.
        with patch("googleapiclient.discovery.build", return_value=service), \
             patch.object(app, "gmail_credentials", return_value=object()), \
             patch.object(app, "_gmail_payload_text", return_value=private_body), \
             patch.object(app.db, "get_gmail_connection", return_value={
                 "email": "inbox@example.test", "last_scan_epoch": 100,
                 "auto_scan_enabled": True,
             }), \
             patch.object(app.db, "get_gmail_detections", return_value={}), \
             patch.object(app.db, "acquire_gmail_scan_lease", return_value=True), \
             patch.object(app.db, "renew_gmail_scan_lease", return_value=True), \
             patch.object(app.db, "release_gmail_scan_lease"), \
             patch.object(app.db, "update_gmail_scan_status") as status, \
             patch.object(app, "analyze_email", side_effect=app.ai_analysis.AnalysisUnavailable(
                 "Gemini analysis is temporarily unavailable", 503, "request_failed", 400)):
            with self.assertLogs(app.app.logger, level="WARNING") as captured:
                outcome = app.scan_gmail_account("user-id")
        self.assertEqual(outcome["status"], "error")
        self.assertEqual(outcome["failed"], 1)
        failure_update = status.call_args_list[-1]
        self.assertEqual(failure_update.args[1], "error")
        self.assertEqual(failure_update.kwargs["error_category"], "gemini_request_failed")
        self.assertEqual(failure_update.kwargs["http_status"], 400)
        output = " ".join(captured.output)
        self.assertIn("category=gemini_request_failed", output)
        self.assertIn("status=400", output)
        self.assertNotIn(private_body, output)
        self.assertNotIn("Private subject", output)

    def test_scan_surfaces_genai_import_failure_without_saving_email(self):
        service = Mock()
        service.users.return_value.getProfile.return_value.execute.return_value = {
            "emailAddress": "inbox@example.test",
        }
        service.users.return_value.messages.return_value.list.return_value.execute.return_value = {
            "messages": [{"id": "message-private"}],
        }
        private_body = "PRIVATE EMAIL BODY MUST NOT APPEAR IN LOGS"
        service.users.return_value.messages.return_value.get.return_value.execute.return_value = {
            "payload": {"headers": [
                {"name": "From", "value": "sender@example.test"},
                {"name": "Subject", "value": "Private subject"},
            ]},
        }
        with patch("googleapiclient.discovery.build", return_value=service), \
             patch.dict("os.environ", {"GEMINI_API_KEY": "synthetic-test-key"}), \
             patch.object(app.ai_analysis, "_quota_blocked_until", 0.0), \
             patch.object(app.ai_analysis, "_client",
                          side_effect=ImportError("private dependency detail")), \
             patch.object(app, "gmail_credentials", return_value=object()), \
             patch.object(app, "_gmail_payload_text", return_value=private_body), \
             patch.object(app.db, "get_gmail_connection", return_value={
                 "email": "inbox@example.test", "last_scan_epoch": 100,
                 "auto_scan_enabled": True,
             }), \
             patch.object(app.db, "get_gmail_detections", return_value={}), \
             patch.object(app.db, "acquire_gmail_scan_lease", return_value=True), \
             patch.object(app.db, "renew_gmail_scan_lease", return_value=True), \
             patch.object(app.db, "release_gmail_scan_lease"), \
             patch.object(app.db, "update_gmail_scan_status") as status, \
             patch.object(app.db, "insert_detection") as save:
            with self.assertLogs("ai_analysis", level="WARNING") as analysis_logs, \
                 self.assertLogs(app.app.logger, level="WARNING") as scan_logs:
                outcome = app.scan_gmail_account("user-id")

        self.assertEqual(outcome["status"], "error")
        self.assertEqual(outcome["failed"], 1)
        failure_update = status.call_args_list[-1]
        self.assertEqual(failure_update.kwargs["error_category"], "gemini_sdk_import_failure")
        self.assertIsNone(failure_update.kwargs["http_status"])
        output = " ".join(analysis_logs.output + scan_logs.output)
        self.assertIn("category=sdk_import_failure", output)
        self.assertIn("category=gemini_sdk_import_failure", output)
        self.assertIn("exception_type=ImportError", output)
        self.assertNotIn("private dependency detail", output)
        self.assertNotIn(private_body, output)
        self.assertNotIn("Private subject", output)
        save.assert_not_called()

    def test_scan_failure_diagnostics_separate_gmail_and_database_errors(self):
        from googleapiclient.errors import HttpError
        from pymongo.errors import ConnectionFailure

        gmail_error = HttpError(
            resp=type("Response", (), {"status": 429, "reason": "Too Many Requests"})(),
            content=b"provider private response",
        )
        self.assertEqual(app._gmail_scan_failure_diagnostics(gmail_error), ("gmail_api", 429))
        self.assertEqual(app._gmail_scan_failure_diagnostics(ConnectionFailure("database detail")),
                         ("mongodb", None))
        self.assertEqual(app._gmail_scan_failure_diagnostics(TimeoutError("network detail")),
                         ("gmail_api_timeout", None))
        self.assertEqual(app._gmail_scan_failure_diagnostics(
            app.ai_analysis.AnalysisUnavailable("unavailable", 504, "request_timeout")),
            ("gemini_request_timeout", None),
        )

    def test_cached_and_fallback_explanations_use_only_recorded_evidence(self):
        self.assertEqual(
            app.explain_detection({"prediction": "Safe", "explanation": "Normal notice; no strong warning found."}),
            "Normal notice; no strong warning found.",
        )
        fallback = app.explain_detection({
            "prediction": "Suspicious",
            "signals": ["AI assessment: internal summary", "Local rule: SPF authentication failed"],
        })
        self.assertIn("SPF authentication failed", fallback)
        self.assertNotIn("internal summary", fallback)
        safe_fallback = app.explain_detection({"prediction": "Safe", "signals": []})
        self.assertIn("does not guarantee the email is safe", safe_fallback)

    def test_revoked_gmail_api_permission_marks_user_for_reauthorization(self):
        from googleapiclient.errors import HttpError
        from unittest.mock import Mock

        error = HttpError(
            resp=type("Response", (), {"status": 401, "reason": "Unauthorized"})(),
            content=b'{"error":{"message":"private provider detail"}}',
        )
        with patch.object(app.db, "mark_gmail_reauth_required") as mark:
            with self.assertRaises(app.GmailAuthorizationError) as raised:
                app._execute_gmail(Mock(execute=Mock(side_effect=error)), "user-id")
        mark.assert_called_once_with("user-id")
        self.assertNotIn("private provider detail", str(raised.exception))

    def test_api_quota_errors_are_not_misclassified_as_revoked_auth(self):
        from googleapiclient.errors import HttpError
        from unittest.mock import Mock

        error = HttpError(
            resp=type("Response", (), {"status": 429, "reason": "Too Many Requests"})(), content=b"quota",
        )
        with patch.object(app.db, "mark_gmail_reauth_required") as mark:
            with self.assertRaises(HttpError):
                app._execute_gmail(Mock(execute=Mock(side_effect=error)), "user-id")
        mark.assert_not_called()


if __name__ == "__main__":
    unittest.main()

