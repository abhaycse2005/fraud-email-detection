import os
import re
import json
import csv
import io
import base64
import html
import threading
import time
import secrets
import hmac
import hashlib
import ipaddress
from collections import OrderedDict
from email.utils import parseaddr
from functools import wraps
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import joblib
from flask import Flask, abort, render_template, request, redirect, url_for, session, jsonify, flash
from dotenv import load_dotenv

# Load this project's .env explicitly before reading application settings.
# Existing process environment values take precedence over .env values.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

import database as db
import ai_analysis
from pymongo.errors import PyMongoError

app = Flask(__name__)
_flask_secret_key = os.getenv("FLASK_SECRET_KEY", "")
if (len(_flask_secret_key) < 32
        or _flask_secret_key in {"replace-with-a-long-random-secret", "development-only-change-me"}):
    raise RuntimeError("Set FLASK_SECRET_KEY to a random value of at least 32 characters in .env.")
app.secret_key = _flask_secret_key
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Local HTTP development stays usable; set SESSION_COOKIE_SECURE=1 behind HTTPS.
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "0").strip() == "1",
)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

# A scan-local cache avoids repeat Gemini calls for byte-for-byte equivalent
# analysis inputs while keeping memory use bounded and user scope isolated.
_GMAIL_ANALYSIS_CACHE_MAX_ENTRIES = 128
_GMAIL_LIST_PAGE_SIZE = 100
_GMAIL_BATCH_SIZE = 50
_GMAIL_REQUEST_TIMEOUT_SECONDS = 30
_GEMINI_CONSECUTIVE_FAILURE_LIMIT = 3
# The active Gemini project quota is not available to this process. Serialize
# calls within this process instead of guessing at a higher model concurrency.
_GEMINI_REQUEST_LOCK = threading.Lock()


@app.errorhandler(PyMongoError)
def handle_database_operation_error(error):
    """Return a safe temporary-unavailable response for runtime Atlas errors."""
    app.logger.error("MongoDB Atlas operation failed exception_type=%s",
                     type(error).__name__)
    if request.path.startswith("/api/"):
        return jsonify({"error": "Database temporarily unavailable. Please try again."}), 503
    return render_template("service_unavailable.html"), 503


@app.context_processor
def inject_csrf_token():
    """Make one session-bound CSRF token available to templates."""
    def csrf_token():
        token = session.get("_csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["_csrf_token"] = token
        return token

    return {"csrf_token": csrf_token}


@app.before_request
def protect_state_changing_requests():
    """Require a session-bound token for browser-originated mutations."""
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return None
    if "user_id" not in session and request.endpoint not in {"login", "register"}:
        # Let login_required produce its normal redirect for private routes.
        return None
    expected = session.get("_csrf_token", "")
    supplied = request.headers.get("X-CSRF-Token", "")
    if not supplied:
        supplied = request.form.get("csrf_token", "")
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        if request.is_json:
            return jsonify({"error": "Request verification failed. Refresh the page and try again."}), 400
        abort(400, description="Request verification failed. Refresh the page and try again.")
    return None

MODEL_PATH = os.path.join(BASE_DIR, "model", "model.pkl")
VECTORIZER_PATH = os.path.join(BASE_DIR, "model", "vectorizer.pkl")
MODEL_BUNDLE_PATH = os.path.join(BASE_DIR, "model", "model_bundle.pkl")
METRICS_PATH = os.path.join(BASE_DIR, "model", "metrics.json")

# ---------- load ML model at startup ----------
model = None
vectorizer = None
metrics = {}

if os.path.exists(MODEL_BUNDLE_PATH):
    model_bundle = joblib.load(MODEL_BUNDLE_PATH)
    model = model_bundle["model"]
    vectorizer = model_bundle["vectorizer"]
    metrics = model_bundle.get("metrics", {})
elif os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
    model = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)

if not metrics and os.path.exists(METRICS_PATH):
    with open(METRICS_PATH) as f:
        metrics = json.load(f)

LABEL_MAP = {"safe": "Safe", "suspicious": "Suspicious", "fraudulent": "Fraudulent"}
RISK_MAP = {"Safe": "Low", "Suspicious": "Medium", "Fraudulent": "High"}
# The text model's probabilities are estimates, not proof. Reserve the strongest
# label for predictions with a clear margin; send uncertain messages to review.
DECISION_CONFIDENCE_THRESHOLD = 70.0

THREAT_KEYWORDS = {
    "Phishing Links": ["click", "link", "verify", "login", "http"],
    "Suspicious Attachments": ["attachment", "attached", "invoice", "download"],
    "Sender Spoofing": ["paypal", "microsoft", "amazon", "bank", "support"],
    "Urgent / Threatening Language": ["urgent", "immediately", "warning", "suspend", "final notice", "act now"],
}

# A visible From address is useful but can be spoofed, so these checks only
# contribute to the assessment; they never prove an email is legitimate.
FREE_MAIL_DOMAINS = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com", "proton.me", "protonmail.com"}
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "gq", "tk", "work", "support"}
BRAND_NAMES = {"paypal", "microsoft", "google", "amazon", "apple", "netflix", "bank"}
SENSITIVE_REQUESTS = {"password", "passcode", "pin", "otp", "ssn", "social security", "card number", "cvv", "bank details", "login credentials", "verification code", "one-time code", "mfa code"}
HIGH_RISK_ACTIONS = {"click", "verify", "login", "sign in", "download", "wire transfer", "gift card"}
URGENCY_WORDS = {"urgent", "immediately", "act now", "final warning", "within 1 hour", "asap"}

# Look for an explicit request to disclose/enter credentials, not mere mentions
# such as "we will never ask for your password".
CREDENTIAL_REQUEST_RE = re.compile(
    r"\b(send|share|provide|reply(?:\s+to\s+(?:this\s+)?(?:message|email))?\s+with|enter|submit|email|tell us|give us|type in|hand over)\b"
    r".{0,90}\b(password|passcode|pin|otp|one[- ]time (?:password|code)|verification code|mfa code|"
    r"login credentials|cvv|security code|full card number|banking password)\b",
    re.IGNORECASE | re.DOTALL,
)
NEGATED_CREDENTIAL_RE = re.compile(
    r"\b(?:never|don't|do not|never ask for|will not ask for|would never ask for|without)\b"
    r".{0,45}\b(?:share|send|provide|email|give|reveal|disclose|ask for|enter)\b"
    r".{0,45}\b(?:password|passcode|pin|otp|verification code|mfa code|cvv|bank details)\b",
    re.IGNORECASE | re.DOTALL,
)


def inspect_sender(sender: str):
    """Return cautious risk signals from the provided From address."""
    sender = sender.strip().lower()
    if not sender:
        return 0, ["No sender address was supplied"]

    match = re.fullmatch(r"([a-z0-9.!#$%&'*+/=?^_`{|}~-]+)@([a-z0-9-]+(?:\.[a-z0-9-]+)+)", sender)
    if not match:
        return 2, ["Sender address format is invalid"]

    local_part, domain = match.groups()
    score, signals = 0, []
    tld = domain.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        score += 1
        signals.append(f"Unusual sender domain extension: .{tld}")
    if re.search(r"(?:\d{4,}|[-_]{2,})", local_part):
        score += 1
        signals.append("Sender address has an unusually random-looking local part")
    for brand in BRAND_NAMES:
        if brand in domain and domain != f"{brand}.com" and not domain.endswith(f".{brand}.com"):
            score += 2
            signals.append(f"Possible brand impersonation in sender domain: {domain}")
            break
    if domain in FREE_MAIL_DOMAINS:
        signals.append("Sender uses a public mail provider (not a fraud signal by itself)")
    return score, signals


def inspect_message(subject: str, content: str):
    """Find contextual warning signals; a keyword mention alone is not proof."""
    text = f"{subject} {content}".lower()
    score, signals = 0, []
    has_link = bool(re.search(r"https?://|www\.", text))
    actions = [word for word in HIGH_RISK_ACTIONS if word in text]
    urgency = [word for word in URGENCY_WORDS if word in text]

    # Do not count educational/defensive statements like "never share your password"
    # as a request for sensitive data.
    explicit_credential_request = bool(CREDENTIAL_REQUEST_RE.search(text)) and not bool(NEGATED_CREDENTIAL_RE.search(text))
    sensitive_mentions = [word for word in SENSITIVE_REQUESTS if word in text]

    if has_link:
        score += 1
        signals.append("Contains a web link; destination still needs verification")
    if explicit_credential_request:
        score += 4
        signals.append("Explicit request to disclose or enter sensitive credentials/security codes")
    elif sensitive_mentions:
        signals.append("Mentions sensitive information, but no explicit request was detected")
    if has_link and actions:
        score += 1
        signals.append("Link combined with an action request")
    if urgency and (explicit_credential_request or has_link or actions):
        score += 1
        signals.append("Urgency is combined with another warning signal")
    elif urgency:
        signals.append("Urgent wording alone is not treated as fraud")
    return score, signals


def combine_assessment(model_label, model_confidence, sender, subject, content,
                       model_indicators=None):
    """Apply a general evidence policy to Gemini's result and local signals.

    Urgency or a public-mail address alone is not supporting evidence. A
    suspicious rating requires a concrete indicator; fraud requires a direct
    credential/code disclosure request or corroborating local signals.
    """
    sender_score, sender_signals = inspect_sender(sender)
    message_score, message_signals = inspect_message(subject, content)
    text = f"{subject} {content}"
    explicit_credential_request = bool(CREDENTIAL_REQUEST_RE.search(text)) and not bool(NEGATED_CREDENTIAL_RE.search(text))

    local_evidence = sender_score > 0 or message_score > 0
    weak_only = (model_indicators or []) and all(
        any(term in str(item).lower() for term in (
            "urgency alone", "urgent wording alone", "public mail provider",
            "g mail sender", "gmail sender", "unknown does not mean",
            "unverified link", "link destination still needs verification",
        )) for item in model_indicators
    )
    ai_evidence = bool(model_indicators) and not weak_only
    assessed_label = str(model_label).lower()
    if explicit_credential_request or (assessed_label == "fraudulent" and message_score >= 3):
        assessed_label = "fraudulent"
        sender_signals.append("High-priority review: request for password, verification code, or sensitive card credentials")
    elif assessed_label == "fraudulent":
        # Keep unsupported Gemini fraud assessments under review, not as a
        # confirmed fraud classification.
        assessed_label = "suspicious"
    elif assessed_label == "suspicious" and not (local_evidence or ai_evidence):
        assessed_label = "safe"

    return assessed_label, model_confidence, sender_signals + message_signals


def calculate_risk_score(label, sender, subject, content):
    """Return a transparent 0-100 severity score; this is not a probability."""
    sender_score, _ = inspect_sender(sender)
    message_score, _ = inspect_message(subject, content)
    signal_score = sender_score + message_score
    if label == "fraudulent":
        return min(100, 70 + signal_score * 5)
    if label == "suspicious":
        return min(69, 35 + signal_score * 5)
    return min(34, signal_score * 7)


def detect_threat_category(text: str) -> str:
    text_lower = text.lower()
    best_cat, best_score = "Other", 0
    for cat, keywords in THREAT_KEYWORDS.items():
        score = sum(1 for k in keywords if k in text_lower)
        if score > best_score:
            best_cat, best_score = cat, score
    return best_cat


def extract_security_metadata(headers=None, subject="", content=""):
    """Extract real email-authentication results and link domains when available.

    Missing authentication headers remain unknown; they are never assumed to pass
    or fail. URLs are parsed locally only; this function does not visit them.
    """
    headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    auth_text = " ".join([
        headers.get("authentication-results", ""),
        headers.get("arc-authentication-results", ""),
    ]).lower()

    auth = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}
    for name in auth:
        match = re.search(r"\b" + name + r"\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b", auth_text)
        if match:
            auth[name] = match.group(1)

    text = f"{subject} {content}"
    raw_urls = re.findall(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", text, flags=re.IGNORECASE)
    domains = []
    for raw_url in raw_urls:
        candidate = raw_url.rstrip(".,);]}")
        parsed = urlparse(candidate if candidate.lower().startswith(("http://", "https://")) else "http://" + candidate)
        domain = (parsed.hostname or "").lower().strip(".")
        if domain and domain not in domains:
            domains.append(domain)

    signals = []
    for name, status in auth.items():
        if status == "fail":
            signals.append(f"Email authentication {name.upper()} failed according to available headers")
        elif status == "pass":
            signals.append(f"Email authentication {name.upper()} passed according to available headers")
        elif status != "unknown":
            signals.append(f"Email authentication {name.upper()} result: {status}")
    if any(value == "unknown" for value in auth.values()):
        signals.append("Some email authentication results are unavailable; unknown does not mean pass or fail")
    if domains:
        signals.append("Link domain(s) extracted for review: " + ", ".join(domains[:10]))
    return {"authentication": auth, "link_domains": domains}, signals


def classify_email(text_model, text_vectorizer, sender, subject, content, authentication=None):
    """Apply the same cautious model policy used by training evaluation.

    Model scores are uncalibrated evidence, not real-world probabilities. A
    Fraudulent label needs a contextual credential request or corroboration
    from the sender/message signals; uncertain classifications go to review.
    """
    if text_model is None or text_vectorizer is None:
        return "suspicious", None

    try:
        full_text = f"{subject} {content}"
        probabilities = text_model.predict_proba(text_vectorizer.transform([full_text]))[0]
        best_index = int(probabilities.argmax())
        best_label = str(text_model.classes_[best_index])
        confidence = round(float(probabilities[best_index]) * 100, 1)

        _, sender_signals = inspect_sender(sender)
        message_score, _ = inspect_message(subject, content)
        explicit_credential_request = (
            bool(CREDENTIAL_REQUEST_RE.search(full_text))
            and not bool(NEGATED_CREDENTIAL_RE.search(full_text))
        )
        auth_failed = any(
            value in {"fail", "softfail"}
            for value in (authentication or {}).values()
        )

        if explicit_credential_request:
            return "fraudulent", confidence
        if confidence < DECISION_CONFIDENCE_THRESHOLD:
            return "suspicious", confidence
        if best_label == "fraudulent":
            brand_impersonation = any(
                signal.startswith("Possible brand impersonation")
                for signal in sender_signals
            )
            # A bare keyword or model score alone cannot label an email
            # fraudulent. Require multiple message warning signals or strong
            # sender impersonation evidence.
            if message_score >= 3 or brand_impersonation:
                return "fraudulent", confidence
            return "suspicious", confidence
        if best_label == "safe" and auth_failed:
            return "suspicious", confidence
        return best_label, confidence
    except Exception:
        return "suspicious", None


def _gmail_analysis_fingerprint(sender, subject, content, email_headers=None):
    """Create a local content identity without logging or exposing message data."""
    security_metadata, _ = extract_security_metadata(email_headers, subject, content)
    canonical = json.dumps(
        [str(sender or "").strip(), str(subject or "").strip(), str(content or "").strip(), security_metadata],
        ensure_ascii=False, separators=(",", ":"), sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def analyze_email(sender, subject, content, user_id, external_message_id=None,
                  email_headers=None, notify_new_fraud=False,
                  existing_detection_id=None, analysis_fingerprint=None,
                  analysis_cache=None):
    """Run Gemini plus locally extracted, evidence-based metadata, then save it."""
    full_text = f"{subject} {content}"
    security_metadata, metadata_signals = extract_security_metadata(
        email_headers, subject, content
    )
    cache_hit = bool(analysis_cache is not None and analysis_fingerprint
                     and analysis_fingerprint in analysis_cache)
    if cache_hit:
        assessment = analysis_cache[analysis_fingerprint]
        analysis_cache.move_to_end(analysis_fingerprint)
    else:
        with _GEMINI_REQUEST_LOCK:
            assessment = ai_analysis.analyze_email(
                sender, subject, content, security_metadata=security_metadata,
            )
    prediction, _, contextual_signals = combine_assessment(
        assessment["classification"].lower(), assessment["confidence_score"],
        sender, subject, content, assessment.get("risk_indicators"),
    )
    prediction = prediction.title()
    gemini_explanation = str(assessment.get("explanation") or "No Gemini explanation was returned.")
    explanation = gemini_explanation
    if prediction.lower() != assessment["classification"].lower():
        if prediction == "Safe":
            explanation = (
                f"Gemini suggested {assessment['classification']}, but the supplied indicators "
                "were not corroborated by concrete local evidence. No strong warning was found; "
                "this does not verify the email as safe."
            )
        else:
            explanation = (
                f"Gemini suggested {assessment['classification']}; local evidence checks adjusted "
                f"the final label to {prediction}. {assessment['explanation']}"
            )
    risk_level = RISK_MAP.get(prediction, "Low")
    pred_label = prediction.lower()
    confidence = assessment["confidence_score"]  # Estimate only; not a calibrated probability.
    risk_score = calculate_risk_score(pred_label, sender, subject, content)
    rule_signals = contextual_signals + metadata_signals
    if prediction.lower() != assessment["classification"].lower():
        if contextual_signals:
            explanation += " Local evidence that affected the final label: " + "; ".join(contextual_signals) + "."
        elif assessment["classification"].lower() == "fraudulent" and prediction == "Suspicious":
            explanation = (
                "Gemini assessed this message as Fraudulent, but the local checks found no "
                "concrete corroborating evidence. The final label is Suspicious pending review. "
                + gemini_explanation
            )
    gemini_indicators = assessment["risk_indicators"]
    sender_warning = any(
        marker in str(signal).lower()
        for signal in contextual_signals
        for marker in ("brand impersonation", "unusual sender domain", "sender address format is invalid")
    )
    credential_request = any("explicit request to disclose" in str(signal).lower()
                             for signal in contextual_signals)
    if credential_request or sender_warning or prediction != "Safe":
        recommended_action = (
            "Do not click links or provide passwords, verification codes, or payment details. "
            "Verify the request using a known official channel, such as an official app or a phone number you already trust."
        )
    else:
        recommended_action = str(assessment.get("recommended_action") or
                                 "Treat the message as unverified and confirm unexpected requests independently.")
    auth_values = security_metadata.get("authentication", {})
    auth_passed = any(value == "pass" for value in auth_values.values())
    if auth_passed:
        auth_caveat = (
            " Available Authentication-Results headers report one or more passing SPF/DKIM/DMARC checks; "
            "those checks do not guarantee that the email content or request is legitimate."
        )
    if prediction.lower() != assessment["classification"].lower():
        explanation += " The final label reflects the local evidence checks shown below."
    if auth_passed:
        explanation += auth_caveat
    signals = (["Gemini indicator: " + item for item in gemini_indicators]
               + ["Local rule: " + item for item in rule_signals])
    if not sender:
        signals.insert(0, "No sender address was supplied")
    stored_signals = ["AI assessment: " + assessment["explanation"]] + signals
    stored_signals.append("Recommended action: " + recommended_action)
    threat_category = detect_threat_category(full_text) if prediction != "Safe" else None
    detection_id = db.insert_detection(
        user_id=user_id, sender_email=sender, subject=subject, content=content,
        prediction=prediction, risk_level=risk_level, confidence=confidence,
        threat_category=threat_category, risk_score=risk_score, signals=stored_signals,
        external_message_id=external_message_id,
        gemini_prediction=assessment["classification"],
        gemini_indicators=gemini_indicators,
        rule_based_signals=rule_signals,
        decision_method="Gemini with local evidence policy",
        explanation=explanation,
        recommended_action=recommended_action,
        security_metadata=security_metadata,
        notify_new_fraud=notify_new_fraud,
        existing_detection_id=existing_detection_id,
        analysis_fingerprint=analysis_fingerprint,
    )
    if detection_id is None:
        # A Gmail message can be observed by two workers at the same instant;
        # the unique detection index decides the winner and only it notifies.
        return None
    if analysis_cache is not None and analysis_fingerprint and not cache_hit:
        analysis_cache[analysis_fingerprint] = assessment
        analysis_cache.move_to_end(analysis_fingerprint)
        while len(analysis_cache) > _GMAIL_ANALYSIS_CACHE_MAX_ENTRIES:
            analysis_cache.popitem(last=False)
    return {
        "id": detection_id, "sender_email": sender, "subject": subject,
        "prediction": prediction, "risk_level": risk_level, "risk_score": risk_score,
        "confidence": confidence, "threat_category": threat_category,
        "gemini_prediction": assessment["classification"],
        "gemini_indicators": gemini_indicators,
        "rule_based_signals": rule_signals,
        "local_ml_prediction": None, "local_ml_used": False,
        "decision_method": "Gemini with local evidence policy",
        "signals": signals, "security_metadata": security_metadata,
        "explanation": explanation, "gemini_explanation": gemini_explanation,
        "recommended_action": recommended_action,
    }


def explain_detection(detection):
    """Return a cached explanation or a conservative fallback from saved evidence."""
    explanation = str(detection.get("explanation") or "").strip()
    if explanation:
        return explanation[:500]
    label = str(detection.get("prediction") or "email").lower()
    recorded_signals = detection.get("signals", [])
    if not isinstance(recorded_signals, list):
        recorded_signals = []
    evidence = [str(item).strip() for item in recorded_signals
                if str(item).startswith(("Gemini indicator:", "Local rule:", "High-priority review:"))]
    if evidence:
        reasons = "; ".join(evidence[:2])
        return f"This email was marked {label} because the analysis recorded: {reasons}. Review the message before acting."
    if label == "safe":
        return "No strong warning was recorded in this analysis. That does not guarantee the email is safe; verify unexpected requests."
    return f"This email was marked {label}, but no specific reason was saved. Treat it cautiously and verify the sender independently."


GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
_oauth_transport_lock = threading.Lock()


class GmailAuthorizationError(RuntimeError):
    """The saved Gmail grant needs the user to connect again."""


def google_oauth_configured():
    return bool(os.getenv("GOOGLE_CLIENT_ID", "").strip()
                and os.getenv("GOOGLE_CLIENT_SECRET", "").strip())


def make_gmail_flow(state=None, redirect_uri=None, code_verifier=None):
    from google_auth_oauthlib.flow import Flow

    callback_uri = redirect_uri or url_for("gmail_oauth_callback", _external=True)
    flow = Flow.from_client_config(
        {"web": {
            "client_id": os.getenv("GOOGLE_CLIENT_ID", "").strip(),
            "client_secret": os.getenv("GOOGLE_CLIENT_SECRET", "").strip(),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [callback_uri],
        }},
        scopes=GMAIL_SCOPES,
        state=state,
        code_verifier=code_verifier,
        autogenerate_code_verifier=True,
    )
    flow.redirect_uri = callback_uri
    return flow


def _oauth_provider_diagnostics(error):
    """Return constrained provider diagnostics without credential-like data."""
    import re

    code = getattr(error, "error", None) or getattr(error, "error_code", None)
    known_provider_codes = {
        "invalid_grant", "invalid_client", "invalid_request", "unauthorized_client",
        "access_denied", "unsupported_grant_type", "invalid_scope",
    }
    if not isinstance(code, str) or code.lower() not in known_provider_codes:
        code = "unavailable"
    else:
        code = code.lower()
    captured = getattr(error, "_gmail_oauth_diagnostics", {})
    description = (captured.get("description")
                   or getattr(error, "description", None)
                   or getattr(error, "error_description", None))
    safe_description = "not logged"
    if isinstance(description, str):
        # Provider text is untrusted. Scrub URLs, emails, explicitly labelled
        # secrets/codes, and opaque long values before logging a short excerpt.
        description = re.sub(r"https?://\S+", "[url]", description, flags=re.IGNORECASE)
        description = re.sub(
            r"(?i)\b(code|token|secret|verifier|authorization|refresh_token|access_token)\b"
            r"\s*[:=]\s*[^\s,;]+", r"\1=(redacted)", description,
        )
        description = re.sub(
            r"(?i)\b(authorization code|auth code|access token|refresh token|code verifier)\s+"
            r"[A-Za-z0-9._~-]{12,}", r"\1 (redacted)", description,
        )
        description = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "[email]", description)
        description = re.sub(r"\b[A-Za-z0-9._~-]{24,}\b", "(value)", description)
        description = re.sub(r"[^A-Za-z0-9 .,;:_()'/-\[\]]", " ", description)
        description = " ".join(description.split())[:180]
        if description:
            safe_description = description
    status = captured.get("http_status")
    if not isinstance(status, int) or not 100 <= status <= 599:
        status = "unavailable"
    return code, safe_description, status


def fetch_gmail_oauth_token(flow, authorization_response):
    """Exchange a callback URL, allowing HTTP only for loopback development.

    OAuthlib requires HTTPS by default. Its insecure-transport switch is set
    only during this local callback exchange and restored immediately; remote
    HTTP callbacks continue to be rejected. OAuth state validation is performed
    by the callback route before this helper is called.
    """
    captured = {}

    def capture_token_response(response):
        captured["http_status"] = getattr(response, "status_code", None)
        try:
            payload = response.json()
        except (ValueError, AttributeError):
            payload = {}
        if isinstance(payload, dict):
            captured["error"] = payload.get("error")
            captured["description"] = payload.get("error_description") or payload.get("error_description_legacy")
        return response

    response_hooks = flow.oauth2session.compliance_hook["access_token_response"]
    response_hooks.add(capture_token_response)

    def exchange():
        try:
            return flow.fetch_token(authorization_response=authorization_response)
        except Exception as error:
            error._gmail_oauth_diagnostics = dict(captured)
            raise
        finally:
            response_hooks.discard(capture_token_response)

    callback = urlparse(authorization_response)
    hostname = (callback.hostname or "").lower()
    try:
        is_loopback = hostname == "localhost" or ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        is_loopback = False
    if callback.scheme.lower() != "http" or not is_loopback:
        return exchange()

    # OAuthlib reads this process environment variable. Serialize our OAuth
    # exchanges and restore it even when the provider/token exchange fails.
    with _oauth_transport_lock:
        previous_value = os.environ.get("OAUTHLIB_INSECURE_TRANSPORT")
        os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
        try:
            return exchange()
        finally:
            response_hooks.discard(capture_token_response)
            if previous_value is None:
                os.environ.pop("OAUTHLIB_INSECURE_TRANSPORT", None)
            else:
                os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = previous_value


def encrypt_gmail_token(token_json):
    from cryptography.fernet import Fernet

    key = os.getenv("GMAIL_TOKEN_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError("Set GMAIL_TOKEN_ENCRYPTION_KEY before connecting Gmail.")
    return Fernet(key.encode()).encrypt(token_json.encode()).decode()


def decrypt_gmail_token(token_ciphertext):
    from cryptography.fernet import Fernet

    key = os.getenv("GMAIL_TOKEN_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError("GMAIL_TOKEN_ENCRYPTION_KEY is not configured.")
    return Fernet(key.encode()).decrypt(token_ciphertext.encode()).decode()


def gmail_credentials(user_id):
    from google.auth.exceptions import RefreshError
    from google.oauth2.credentials import Credentials
    from google.auth.transport.requests import Request as GoogleRequest

    connection = db.get_gmail_connection(user_id)
    if not connection:
        return None
    if connection.get("needs_reauth"):
        raise GmailAuthorizationError("Reconnect the Gmail account to resume scanning.")
    credentials = Credentials.from_authorized_user_info(
        json.loads(decrypt_gmail_token(connection["token_ciphertext"])), GMAIL_SCOPES
    )
    if credentials.expired and credentials.refresh_token:
        try:
            credentials.refresh(GoogleRequest())
        except RefreshError:
            db.mark_gmail_reauth_required(user_id)
            raise GmailAuthorizationError("Gmail authorization expired or was revoked. Reconnect the account.") from None
        db.save_gmail_connection(user_id, connection["email"], encrypt_gmail_token(credentials.to_json()))
    elif credentials.expired:
        db.mark_gmail_reauth_required(user_id)
        raise GmailAuthorizationError("Gmail authorization expired. Reconnect the account.")
    return credentials


def _gmail_error_requires_reauthorization(error):
    status = getattr(getattr(error, "resp", None), "status", None)
    if status == 401:
        return True
    if status != 403:
        return False
    details = getattr(error, "error_details", None) or []
    auth_reasons = {"authError", "insufficientPermissions", "invalidCredentials", "forbidden"}
    return any(isinstance(item, dict) and item.get("reason") in auth_reasons for item in details)


def _execute_gmail(api_request, user_id):
    from googleapiclient.errors import HttpError

    try:
        return api_request.execute()
    except HttpError as error:
        if _gmail_error_requires_reauthorization(error):
            db.mark_gmail_reauth_required(user_id)
            raise GmailAuthorizationError("Gmail access was revoked or is no longer permitted. Reconnect the account.") from None
        raise


def _build_gmail_service(credentials):
    """Build the readonly Gmail client with a finite socket timeout."""
    import httplib2
    from google_auth_httplib2 import AuthorizedHttp
    from googleapiclient.discovery import build

    transport = httplib2.Http(timeout=_GMAIL_REQUEST_TIMEOUT_SECONDS)
    authorized_transport = AuthorizedHttp(credentials, http=transport)
    return build("gmail", "v1", http=authorized_transport, cache_discovery=False)


def _fetch_gmail_messages_batch(service, user_id, message_ids):
    """Fetch a page of Gmail bodies in bounded batches; return per-ID errors."""
    from googleapiclient.errors import HttpError
    from googleapiclient.http import BatchHttpRequest

    messages = {}
    errors = {}
    ids = [str(message_id) for message_id in message_ids]
    for offset in range(0, len(ids), _GMAIL_BATCH_SIZE):
        chunk = ids[offset:offset + _GMAIL_BATCH_SIZE]
        batch = service.new_batch_http_request()
        # Non-discovery test doubles and compatible adapters use the safe
        # sequential path. The real google-api-python-client returns this type.
        if not isinstance(batch, BatchHttpRequest):
            for message_id in chunk:
                try:
                    messages[message_id] = _execute_gmail(
                        service.users().messages().get(
                            userId="me", id=message_id, format="full", fields="id,payload",
                        ), user_id,
                    )
                except Exception as error:
                    if isinstance(error, GmailAuthorizationError):
                        raise
                    if _gmail_error_requires_reauthorization(error):
                        db.mark_gmail_reauth_required(user_id)
                        raise GmailAuthorizationError(
                            "Gmail access was revoked or is no longer permitted. Reconnect the account."
                        ) from None
                    errors[message_id] = error
            continue

        request_ids = {}

        def on_response(request_id, response, exception):
            message_id = request_ids.get(request_id)
            if message_id is None:
                return
            if exception is not None:
                errors[message_id] = exception
            else:
                messages[message_id] = response

        for index, message_id in enumerate(chunk):
            request_id = str(index)
            request_ids[request_id] = message_id
            batch.add(service.users().messages().get(
                userId="me", id=message_id, format="full", fields="id,payload",
            ), request_id=request_id, callback=on_response)
        try:
            batch.execute()
        except Exception as error:
            # Batch transport failure can leave individual callbacks unresolved.
            # Preserve successful callbacks and defer only messages with no result.
            for message_id in chunk:
                if message_id not in messages and message_id not in errors:
                    errors[message_id] = error

        for message_id in chunk:
            error = errors.get(message_id)
            if error is not None and _gmail_error_requires_reauthorization(error):
                db.mark_gmail_reauth_required(user_id)
                raise GmailAuthorizationError(
                    "Gmail access was revoked or is no longer permitted. Reconnect the account."
                ) from None
    return messages, errors


def _gmail_payload_text(payload):
    mime_type = payload.get("mimeType", "")
    data = payload.get("body", {}).get("data")
    if mime_type == "text/plain" and data:
        return base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="replace")
    for part in payload.get("parts", []):
        body = _gmail_payload_text(part)
        if body:
            return body
    if mime_type == "text/html" and data:
        raw_html = base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="replace")
        return html.unescape(re.sub(r"<[^>]+>", " ", raw_html))
    return ""


def _gmail_scan_failure_diagnostics(error):
    """Classify scan failures without including private email or provider text."""
    if isinstance(error, ai_analysis.AnalysisUnavailable):
        return "gemini_" + str(error.category), error.provider_status_code
    if isinstance(error, GmailAuthorizationError):
        return "gmail_authorization", None
    if isinstance(error, PyMongoError):
        return "mongodb", None
    if isinstance(error, (TimeoutError,)) or error.__class__.__name__.lower().endswith("timeout"):
        return "gmail_api_timeout", None
    try:
        from googleapiclient.errors import HttpError
        if isinstance(error, HttpError):
            status = getattr(getattr(error, "resp", None), "status", None)
            return "gmail_api", status if isinstance(status, int) else None
    except ImportError:
        pass
    return "scanner_internal", None


def scan_gmail_account(user_id, *, automatic=False, _reserved_lease_token=None):
    """Scan one user's inbox without overlapping another worker's scan."""
    try:
        connection = db.get_gmail_connection(user_id)
    except Exception as error:
        category, http_status = _gmail_scan_failure_diagnostics(error)
        app.logger.error("Gmail scan preflight failed category=%s status=%s exception_type=%s",
                         category, http_status if http_status is not None else "none",
                         type(error).__name__)
        raise
    if not connection:
        if _reserved_lease_token:
            db.release_gmail_scan_lease(user_id, _reserved_lease_token)
        return {"scanned": 0, "new": 0, "error": "Gmail account is not connected."}
    if automatic and (connection.get("auto_scan_enabled", True) is False
                      or connection.get("needs_reauth")):
        return {"scanned": 0, "new": 0, "skipped": True}

    lease_token = _reserved_lease_token or secrets.token_urlsafe(24)
    if _reserved_lease_token is None:
        try:
            if not db.acquire_gmail_scan_lease(user_id, lease_token):
                return {"scanned": 0, "new": 0, "skipped": True, "reason": "scan_in_progress"}
        except Exception as error:
            category, http_status = _gmail_scan_failure_diagnostics(error)
            app.logger.error("Gmail scan lease failed category=%s status=%s exception_type=%s",
                             category, http_status if http_status is not None else "none",
                             type(error).__name__)
            raise

    try:
        connection = db.get_gmail_connection(user_id) or {}
        if automatic and (connection.get("auto_scan_enabled", True) is False
                          or connection.get("needs_reauth")):
            db.update_gmail_scan_status(user_id, "paused")
            return {"scanned": 0, "new": 0, "skipped": True}
        db.update_gmail_scan_status(user_id, "running")
        credentials = gmail_credentials(user_id)
        if not credentials:
            db.update_gmail_scan_status(user_id, "disconnected", error_code="not_connected")
            return {"scanned": 0, "new": 0, "error": "Gmail account is not connected."}
        service = _build_gmail_service(credentials)
        profile = _execute_gmail(service.users().getProfile(userId="me"), user_id)
        account_email = profile.get("emailAddress") or connection.get("email", "")
        scan_started = int(time.time())
        checkpoint = connection.get("last_scan_epoch")
        initial_scan = checkpoint is None
        query = "in:inbox" if initial_scan else f"in:inbox after:{max(0, int(checkpoint) - 60)}"
        # The first pass is paginated and its next-page token is saved only
        # after that complete page has been analyzed. Replaying a page after a
        # crash is safe because each Gmail message has a unique per-user key.
        page_token = connection.get("historical_page_token") if initial_scan else None
        # Resume only from a fully committed page. The visible counter may
        # include attempts in a page whose cursor must still be replayed.
        processed_count = int(connection.get(
            "scan_progress_checkpoint_count", connection.get("scan_progress_count", 0)
        )) if initial_scan else 0
        attempted_count = processed_count
        successful_count = processed_count
        paused = False
        new_count = 0
        scanned_count = 0
        failed_count = 0
        deferred_count = 0
        consecutive_analysis_failures = 0
        gemini_circuit_open = False
        first_scan_failure = None
        seen_message_ids = set()
        duplicate_ids_skipped = 0
        # Never shared between scans or users; only successful exact-fingerprint
        # assessments are cached, and each message still gets its own DB record.
        analysis_cache = OrderedDict()
        total_estimate = connection.get("scan_progress_total") if initial_scan else None
        db.update_gmail_scan_live_progress(
            user_id, processed=attempted_count, total=total_estimate,
            historical=initial_scan, failed=0, successful=successful_count, deferred=0,
        )
        while True:
            if not db.renew_gmail_scan_lease(user_id, lease_token):
                paused = True
                break
            if automatic:
                latest = db.get_gmail_connection(user_id) or {}
                if latest.get("auto_scan_enabled", True) is False or latest.get("needs_reauth"):
                    paused = True
                    break
            list_args = {"userId": "me", "q": query, "maxResults": _GMAIL_LIST_PAGE_SIZE}
            if page_token:
                list_args["pageToken"] = page_token
            page = _execute_gmail(service.users().messages().list(**list_args), user_id)
            messages = page.get("messages", [])
            total_estimate = page.get("resultSizeEstimate", total_estimate)
            db.update_gmail_scan_live_progress(
                user_id, processed=attempted_count, total=total_estimate,
                historical=initial_scan, failed=failed_count,
                successful=successful_count, deferred=deferred_count,
            )
            page_processed = 0
            message_ids = []
            duplicate_positions = set()
            page_seen_ids = set()
            for item_index, item in enumerate(messages):
                message_id = str(item.get("id") or "")
                if not message_id:
                    continue
                if message_id in seen_message_ids or message_id in page_seen_ids:
                    duplicate_positions.add(item_index)
                    continue
                page_seen_ids.add(message_id)
                message_ids.append(message_id)
            seen_message_ids.update(page_seen_ids)
            duplicate_ids_skipped += len(duplicate_positions)
            existing_by_id = db.get_gmail_detections(user_id, message_ids)
            fetched_by_id, fetch_errors = _fetch_gmail_messages_batch(
                service, user_id, message_ids,
            )
            page_failed = False
            for item_index, item in enumerate(messages):
                message_id = str(item.get("id") or "")
                if item_index in duplicate_positions:
                    continue
                if not message_id:
                    page_failed = True
                    attempted_count += 1
                    failed_count += 1
                    deferred_count += 1
                    if first_scan_failure is None:
                        first_scan_failure = RuntimeError("Gmail list response omitted a message ID")
                    db.update_gmail_scan_live_progress(
                        user_id, processed=attempted_count, total=total_estimate,
                        historical=initial_scan, failed=failed_count,
                        successful=successful_count, deferred=deferred_count,
                    )
                    continue
                if gemini_circuit_open:
                    page_failed = True
                    if total_estimate is not None:
                        remaining = max(0, int(total_estimate) - attempted_count)
                    else:
                        remaining = sum(
                            1 for pending_index, _ in enumerate(messages[item_index:], item_index)
                            if pending_index not in duplicate_positions
                        )
                    deferred_count += remaining
                    db.update_gmail_scan_live_progress(
                        user_id, processed=attempted_count, total=total_estimate,
                        historical=initial_scan, failed=failed_count,
                        successful=successful_count, deferred=deferred_count,
                    )
                    break
                if not db.renew_gmail_scan_lease(user_id, lease_token):
                    paused = True
                    break
                if automatic:
                    latest = db.get_gmail_connection(user_id) or {}
                    if latest.get("auto_scan_enabled", True) is False or latest.get("needs_reauth"):
                        paused = True
                        break
                attempted_count += 1
                existing = existing_by_id.get(message_id)
                fetch_error = fetch_errors.get(message_id)
                if fetch_error is not None:
                    page_failed = True
                    failed_count += 1
                    deferred_count += 1
                    if first_scan_failure is None:
                        first_scan_failure = fetch_error
                    db.update_gmail_scan_live_progress(
                        user_id, processed=attempted_count, total=total_estimate,
                        historical=initial_scan, failed=failed_count,
                        successful=successful_count, deferred=deferred_count,
                    )
                    continue
                message = fetched_by_id.get(message_id)
                if not message:
                    page_failed = True
                    failed_count += 1
                    deferred_count += 1
                    if first_scan_failure is None:
                        first_scan_failure = RuntimeError("Gmail batch omitted a message response")
                    db.update_gmail_scan_live_progress(
                        user_id, processed=attempted_count, total=total_estimate,
                        historical=initial_scan, failed=failed_count,
                        successful=successful_count, deferred=deferred_count,
                    )
                    continue
                try:
                    payload = message.get("payload", {})
                    headers = {header["name"].lower(): header["value"] for header in payload.get("headers", [])}
                    sender = parseaddr(headers.get("from", ""))[1]
                    subject = headers.get("subject", "")
                    content = _gmail_payload_text(payload).strip() or "(Email body could not be extracted.)"
                    full_sender = sender or headers.get("from", "")
                    bounded_content = content[:50000]
                    fingerprint = _gmail_analysis_fingerprint(
                        full_sender, subject, bounded_content, headers,
                    )
                except Exception as error:
                    page_failed = True
                    failed_count += 1
                    deferred_count += 1
                    if first_scan_failure is None:
                        first_scan_failure = error
                    db.update_gmail_scan_live_progress(
                        user_id, processed=attempted_count, total=total_estimate,
                        historical=initial_scan, failed=failed_count,
                        successful=successful_count, deferred=deferred_count,
                    )
                    continue
                if existing and existing.get("analysis_fingerprint") == fingerprint:
                    page_processed += 1
                    successful_count += 1
                    scanned_count += 1
                    db.update_gmail_scan_live_progress(
                        user_id, processed=attempted_count, total=total_estimate,
                        historical=initial_scan, failed=failed_count,
                        successful=successful_count, deferred=deferred_count,
                    )
                    continue
                try:
                    result = analyze_email(
                        full_sender, subject, bounded_content, user_id, message_id,
                        email_headers=headers,
                        # Historical pages never create alerts. Incremental scans
                        # notify only after the saved detection write succeeds.
                        notify_new_fraud=not initial_scan,
                        existing_detection_id=existing.get("_id") if existing else None,
                        analysis_fingerprint=fingerprint,
                        analysis_cache=analysis_cache,
                    )
                except ai_analysis.AnalysisUnavailable as error:
                    page_failed = True
                    failed_count += 1
                    deferred_count += 1
                    consecutive_analysis_failures += 1
                    if first_scan_failure is None:
                        first_scan_failure = error
                    if (error.category in {"quota_or_rate_limit", "quota_cooldown"}
                            or consecutive_analysis_failures >= _GEMINI_CONSECUTIVE_FAILURE_LIMIT):
                        gemini_circuit_open = True
                    db.update_gmail_scan_live_progress(
                        user_id, processed=attempted_count, total=total_estimate,
                        historical=initial_scan, failed=failed_count,
                        successful=successful_count, deferred=deferred_count,
                    )
                    continue
                consecutive_analysis_failures = 0
                if result and result.get("id"):
                    new_count += 1
                else:
                    # A write conflict is not treated as success without
                    # confirming that a current detection exists for this message.
                    saved = db.get_gmail_detection(user_id, message_id)
                    if not saved or saved.get("analysis_fingerprint") != fingerprint:
                        page_failed = True
                        failed_count += 1
                        deferred_count += 1
                        if first_scan_failure is None:
                            first_scan_failure = RuntimeError("MongoDB did not confirm the email analysis write")
                        db.update_gmail_scan_live_progress(
                            user_id, processed=attempted_count, total=total_estimate,
                            historical=initial_scan, failed=failed_count,
                            successful=successful_count, deferred=deferred_count,
                        )
                        continue
                page_processed += 1
                successful_count += 1
                scanned_count += 1
                db.update_gmail_scan_live_progress(
                    user_id, processed=attempted_count, total=total_estimate,
                    historical=initial_scan, failed=failed_count,
                    successful=successful_count, deferred=deferred_count,
                )
            if paused:
                break
            if page_failed:
                # The durable cursor cannot pass a page with a failed message.
                # Stop here so later pages are not fetched and replayed on the
                # next retry; successful writes in this page remain reusable.
                if not gemini_circuit_open and total_estimate is not None:
                    deferred_count += max(0, int(total_estimate) - attempted_count)
                db.update_gmail_scan_live_progress(
                    user_id, processed=attempted_count, total=total_estimate,
                    historical=initial_scan, failed=failed_count,
                    successful=successful_count, deferred=deferred_count,
                )
                break
            next_page_token = page.get("nextPageToken")
            processed_count += page_processed
            if initial_scan and failed_count == 0:
                db.update_gmail_scan_progress(
                    user_id, page_token=next_page_token, processed=processed_count,
                    total=total_estimate, historical=True,
                )
            if not next_page_token:
                break
            page_token = next_page_token

        if not paused and failed_count:
            category, http_status = _gmail_scan_failure_diagnostics(first_scan_failure)
            app.logger.warning(
                "Gmail scan completed with deferred emails failed_count=%d category=%s status=%s exception_type=%s",
                failed_count, category,
                http_status if http_status is not None else "none",
                type(first_scan_failure).__name__,
            )
            db.update_gmail_scan_status(
                user_id, "error", scanned=scanned_count,
                failed=failed_count, deferred=deferred_count,
                error_code=type(first_scan_failure).__name__,
                error_category=category, http_status=http_status,
            )
        elif not paused:
            if initial_scan:
                db.finish_gmail_historical_scan(user_id, scan_started, processed_count)
            else:
                db.update_gmail_scan_checkpoint(user_id, scan_started)
                db.update_gmail_scan_status(user_id, "success", scanned=scanned_count)
        else:
            db.update_gmail_scan_status(user_id, "paused", scanned=scanned_count)
        safe_total = (int(total_estimate) if isinstance(total_estimate, (int, float))
                      and not isinstance(total_estimate, bool) else "unknown")
        app.logger.info(
            "Gmail scan totals mode=%s estimated_messages=%s unique_ids_seen=%d "
            "attempted=%d classified=%d failed=%d deferred=%d duplicate_ids_skipped=%d",
            "historical" if initial_scan else "incremental", safe_total,
            len(seen_message_ids), attempted_count, successful_count,
            failed_count, deferred_count, duplicate_ids_skipped,
        )
        return {"scanned": scanned_count, "attempted": attempted_count,
                "successful": successful_count, "new": new_count, "email": account_email,
                "failed": failed_count, "deferred": deferred_count,
                "status": "paused" if paused else "error" if failed_count else "success"}
    except GmailAuthorizationError:
        db.mark_gmail_reauth_required(user_id)
        raise
    except Exception as error:
        category, http_status = _gmail_scan_failure_diagnostics(error)
        app.logger.error(
            "Gmail scan failed category=%s status=%s exception_type=%s",
            category, http_status if http_status is not None else "none",
            type(error).__name__,
        )
        db.update_gmail_scan_status(
            user_id, "error", error_code=type(error).__name__,
            error_category=category, http_status=http_status,
        )
        raise
    finally:
        db.release_gmail_scan_lease(user_id, lease_token)


def scan_all_connected_gmail_accounts():
    try:
        connections = db.get_gmail_connections()
    except Exception as error:
        category, http_status = _gmail_scan_failure_diagnostics(error)
        app.logger.error("Gmail scanner could not load connections category=%s status=%s exception_type=%s",
                         category, http_status if http_status is not None else "none",
                         type(error).__name__)
        return
    for connection in connections:
        try:
            outcome = scan_gmail_account(connection["user_id"], automatic=True)
            if outcome.get("new"):
                app.logger.info("Gmail scanner stored %s new detection(s).", outcome["new"])
        except Exception as error:
            category, status = _gmail_scan_failure_diagnostics(error)
            app.logger.error("Gmail scanner failed category=%s status=%s exception_type=%s",
                             category, status if status is not None else "none",
                             type(error).__name__)


def gmail_scanner_worker():
    interval = max(60, int(os.getenv("GMAIL_SCAN_INTERVAL_SECONDS", "180")))
    while True:
        try:
            scan_all_connected_gmail_accounts()
        except Exception as error:
            app.logger.error("Gmail scanner cycle failed exception_type=%s",
                             type(error).__name__)
        time.sleep(interval)


_gmail_worker_lock = threading.Lock()
_gmail_worker = None


def start_gmail_scanner_worker():
    """Start at most one scanner thread in this process.

    MongoDB scan leases remain the cross-process guard; this lock prevents
    duplicate embedded workers when startup hooks call this more than once.
    """
    global _gmail_worker
    with _gmail_worker_lock:
        if _gmail_worker is not None and _gmail_worker.is_alive():
            return _gmail_worker
        _gmail_worker = threading.Thread(
            target=gmail_scanner_worker, name="gmail-scanner", daemon=True
        )
        _gmail_worker.start()
        return _gmail_worker


# ---------- auth helpers ----------

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            flash("Admin access required.", "error")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return wrapper


# ---------- auth routes ----------

@app.route("/")
def index():
    return redirect(url_for("dashboard") if "user_id" in session else url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            flash("All fields are required.", "error")
            return render_template("register.html")

        if db.create_user(name, email, password):
            flash("Account created successfully. Please log in.", "success")
            return redirect(url_for("login"))
        else:
            flash("An account with this email already exists.", "error")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = db.verify_user(email, password)
        if user:
            # Rotate the signed session on authentication.
            session.clear()
            session["user_id"] = user["id"]
            session["name"] = user["name"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password.", "error")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/account-security", methods=["GET", "POST"])
@login_required
def account_security():
    if request.method == "POST":
        action = request.form.get("action", "")
        current_password = request.form.get("current_password", "")
        if action == "change_email":
            new_email = request.form.get("new_email", "").strip().lower()
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", new_email):
                flash("Enter a valid email address.", "error")
            else:
                result = db.change_user_email(session["user_id"], current_password, new_email)
                if result == "changed":
                    flash("Email address changed successfully.", "success")
                elif result == "exists":
                    flash("That email is already used by another account.", "error")
                elif result == "unchanged":
                    flash("That is already your current email address.", "error")
                elif result == "invalid_password":
                    flash("Current password is incorrect. Your email was not changed.", "error")
                else:
                    flash("Could not change the email address. Please try again.", "error")
        elif action == "change_password":
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")

            if len(new_password) < 8:
                flash("New password must be at least 8 characters long.", "error")
            elif new_password != confirm_password:
                flash("New password and confirmation do not match.", "error")
            elif current_password == new_password:
                flash("Choose a password different from your current password.", "error")
            elif not db.change_user_password(session["user_id"], current_password, new_password):
                flash("Current password is incorrect. Your password was not changed.", "error")
            else:
                flash("Password changed successfully.", "success")
        else:
            flash("Choose an account change to continue.", "error")

    return render_template(
        "account_security.html",
        user_name=session.get("name"),
        active="account_security",
    )


# ---------- app routes ----------

@app.route("/dashboard")
@login_required
def dashboard():
    user_id = session["user_id"]
    stats = db.get_stats(user_id=user_id)
    trend_by_day = {row["day"]: row for row in stats.get("trend", [])}
    today = datetime.now(timezone.utc).date()
    trend_days = []
    for offset in range(6, -1, -1):
        day = today - timedelta(days=offset)
        values = trend_by_day.get(day.isoformat(), {})
        trend_days.append({
            "day_label": day.strftime("%d %b"),
            "safe": int(values.get("safe", 0)),
            "suspicious": int(values.get("suspicious", 0)),
            "fraudulent": int(values.get("fraudulent", 0)),
        })
        trend_days[-1]["total"] = sum(trend_days[-1][key] for key in ("safe", "suspicious", "fraudulent"))
    daily_counts = [day["total"] for day in trend_days]
    max_daily_count = max([1] + daily_counts)
    for day in trend_days:
        day["bar_height"] = max(3, round(day["total"] / max_daily_count * 82)) if day["total"] else 0
    recent = db.get_recent_detections(limit=6, user_id=user_id)
    gmail_alerts = db.get_recent_gmail_alerts(user_id)
    notifications = db.get_notifications(user_id)
    unread_notification_count = db.get_unread_notification_count(user_id)
    return render_template(
        "dashboard.html",
        user_name=session.get("name"),
        stats=stats,
        trend_days=trend_days,
        recent=recent,
        metrics=metrics,
        gmail_alerts=gmail_alerts,
        notifications=notifications,
        unread_notification_count=unread_notification_count,
        ai_configured=bool(os.getenv("GEMINI_API_KEY", "").strip()),
        active="dashboard",
    )


@app.route("/new-analysis")
@login_required
def new_analysis():
    connection = db.get_gmail_connection(session["user_id"])
    return render_template("new_analysis.html", user_name=session.get("name"),
                           active="new_analysis", gmail_connection=connection)


@app.route("/history")
@login_required
def history():
    detections = db.get_all_detections(user_id=session["user_id"])
    for detection in detections:
        detection["simple_explanation"] = explain_detection(detection)
    return render_template("history.html", user_name=session.get("name"), detections=detections, active="history")


@app.route("/admin")
@login_required
@admin_required
def admin():
    users = db.get_all_users()
    stats = db.get_stats()
    return render_template("admin.html", user_name=session.get("name"), users=users, stats=stats, metrics=metrics, active="admin")


@app.route("/email-account")
@login_required
def email_account():
    connection = db.get_gmail_connection(session["user_id"])
    return render_template(
        "email_account.html", user_name=session.get("name"), active="email_account",
        connection=connection, oauth_configured=google_oauth_configured(),
        auto_scan_enabled=connection.get("auto_scan_enabled", True) if connection else False,
    )


@app.route("/gmail/connect")
@login_required
def gmail_connect():
    if not google_oauth_configured():
        flash("Gmail setup is incomplete. Add Google OAuth credentials to your .env file.", "error")
        return redirect(url_for("email_account"))
    if not os.getenv("GMAIL_TOKEN_ENCRYPTION_KEY"):
        flash("Gmail setup is incomplete. Add GMAIL_TOKEN_ENCRYPTION_KEY to your .env file.", "error")
        return redirect(url_for("email_account"))
    try:
        flow = make_gmail_flow()
        authorization_url, state = flow.authorization_url(
            access_type="offline", include_granted_scopes="true", prompt="consent"
        )
        session["gmail_oauth_state"] = state
        # Keep the exact URI used in Google's authorization request for the
        # token exchange; rebuilding it on callback can differ behind proxies
        # or when localhost and 127.0.0.1 are mixed.
        session["gmail_oauth_redirect_uri"] = flow.redirect_uri
        session.pop("gmail_oauth_code_verifier", None)
        session["gmail_oauth_pkce_required"] = bool(flow.code_verifier)
        if flow.code_verifier:
            session["gmail_oauth_code_verifier"] = encrypt_gmail_token(flow.code_verifier)
        return redirect(authorization_url)
    except ImportError:
        flash("Gmail packages are missing. Install the project requirements first.", "error")
        return redirect(url_for("email_account"))


@app.route("/gmail/oauth/callback")
@login_required
def gmail_oauth_callback():
    expected_state = session.pop("gmail_oauth_state", None)
    expected_redirect_uri = session.pop("gmail_oauth_redirect_uri", None)
    encrypted_code_verifier = session.pop("gmail_oauth_code_verifier", None)
    pkce_required = session.pop("gmail_oauth_pkce_required", False)
    if (not expected_state or request.args.get("state") != expected_state
            or not expected_redirect_uri or (pkce_required and not encrypted_code_verifier)):
        flash("Gmail connection could not be verified. Please try again.", "error")
        return redirect(url_for("email_account"))
    try:
        code_verifier = (decrypt_gmail_token(encrypted_code_verifier)
                         if encrypted_code_verifier else None)
        flow = make_gmail_flow(state=expected_state, redirect_uri=expected_redirect_uri,
                               code_verifier=code_verifier)
        fetch_gmail_oauth_token(flow, request.url)
        credentials = flow.credentials
        from googleapiclient.discovery import build
        service = build("gmail", "v1", credentials=credentials, cache_discovery=False)
        profile = service.users().getProfile(userId="me").execute()
        email_address = profile.get("emailAddress")
        if not email_address:
            raise RuntimeError("Google did not return a Gmail address.")
        db.save_gmail_connection(
            session["user_id"], email_address, encrypt_gmail_token(credentials.to_json())
        )
        connected = db.get_gmail_connection(session["user_id"]) or {}
        scan_state = "enabled" if connected.get("auto_scan_enabled", True) else "disabled"
        flash(f"Gmail connected: {email_address}. Automatic scanning is {scan_state}.", "success")
    except Exception as error:
        provider_code, provider_description, provider_status = _oauth_provider_diagnostics(error)
        category = "invalid_grant" if (
            type(error).__name__ == "InvalidGrantError"
            or provider_code.lower() == "invalid_grant"
        ) else "token_exchange_or_profile_error"
        app.logger.error(
            "Gmail OAuth callback failed category=%s provider_error=%s "
            "provider_description=%s provider_http_status=%s exception_type=%s",
            category, provider_code, provider_description, provider_status, type(error).__name__,
        )
        flash("Could not connect Gmail. Check the OAuth setup and try again.", "error")
    return redirect(url_for("email_account"))


@app.route("/gmail/scan", methods=["POST"])
@login_required
def gmail_scan_now():
    if not db.get_gmail_connection(session["user_id"]):
        flash("Connect a Gmail account before starting a scan.", "error")
    else:
        try:
            outcome = scan_gmail_account(session["user_id"])
            if outcome.get("skipped"):
                flash("A Gmail scan is already running or the account is paused.", "info")
            elif outcome.get("status") == "error":
                flash(
                    f"Gmail scan partially completed: {outcome['scanned']} emails processed; "
                    f"{outcome['failed']} could not be analyzed. Retry the scan to resume.",
                    "error",
                )
            else:
                flash(f"Scan complete: {outcome['new']} new emails analyzed.", "success")
        except GmailAuthorizationError:
            flash("Gmail authorization expired or was revoked. Reconnect Gmail to continue scanning.", "error")
        except Exception as error:
            category, status = _gmail_scan_failure_diagnostics(error)
            app.logger.error("Manual Gmail scan failed category=%s status=%s exception_type=%s",
                             category, status if status is not None else "none",
                             type(error).__name__)
            flash("Gmail scan failed. Check the connection and try again.", "error")
    return redirect(url_for("email_account"))


def _run_user_gmail_scan(user_id, lease_token=None):
    try:
        scan_gmail_account(user_id, _reserved_lease_token=lease_token)
    except GmailAuthorizationError:
        app.logger.info("Gmail scan requires reauthorization for a user account.")
    except Exception as error:
        category, status = _gmail_scan_failure_diagnostics(error)
        app.logger.error("Gmail scan failed category=%s status=%s exception_type=%s",
                         category, status if status is not None else "none",
                         type(error).__name__)


@app.route("/api/gmail/scan", methods=["POST"])
@login_required
def api_start_gmail_scan():
    user_id = session["user_id"]
    connection = db.get_gmail_connection(user_id)
    if not connection:
        return jsonify({"error": "Connect a Gmail account before scanning."}), 409
    if connection.get("needs_reauth"):
        return jsonify({"error": "Reconnect Gmail to resume scanning."}), 409
    lease_token = secrets.token_urlsafe(24)
    if not db.acquire_gmail_scan_lease(user_id, lease_token):
        return jsonify({"status": "already_running"}), 202
    # Pass the already-acquired token to prevent a second click from creating a
    # worker that later races for the same user's scan slot.
    try:
        worker = threading.Thread(target=_run_user_gmail_scan, args=(user_id, lease_token),
                                  name="gmail-manual-scan", daemon=True)
        worker.start()
    except Exception:
        db.release_gmail_scan_lease(user_id, lease_token)
        raise
    return jsonify({"status": "starting"}), 202


@app.route("/api/gmail/scan-status")
@login_required
def api_gmail_scan_status():
    connection = db.get_gmail_connection(session["user_id"])
    if not connection:
        return jsonify({"connected": False, "status": "disconnected"})
    return jsonify({
        "connected": True,
        "account_email": connection.get("email", ""),
        "automatic_scanning": connection.get("auto_scan_enabled", True),
        "needs_reauth": bool(connection.get("needs_reauth")),
        "status": connection.get("scan_status", "ready"),
        "mode": connection.get("scan_mode"),
        "progress": int(connection.get("scan_progress_count", 0)),
        "attempted_count": int(connection.get("scan_progress_count", 0)),
        "successful_count": int(connection.get("scan_progress_success_count", 0)),
        "total": connection.get("scan_progress_total"),
        "failed_count": int(
            connection.get("scan_progress_failed_count", 0)
            if connection.get("scan_status") == "running"
            else connection.get("last_scan_failed_count", 0)
        ),
        "deferred_count": int(
            connection.get("scan_progress_deferred_count", 0)
            if connection.get("scan_status") == "running"
            else connection.get("last_scan_deferred_count",
                                connection.get("last_scan_failed_count", 0))
        ),
        "last_scan_count": int(connection.get("last_scan_count", 0)),
        "last_scan_at": connection.get("last_scan_at").isoformat()
            if hasattr(connection.get("last_scan_at"), "isoformat") else None,
        "error_code": connection.get("last_scan_error"),
        "error_category": connection.get("last_scan_error_category"),
        "http_status": connection.get("last_scan_http_status"),
    })


@app.route("/gmail/auto-scan", methods=["POST"])
@login_required
def gmail_auto_scan():
    connection = db.get_gmail_connection(session["user_id"])
    if not connection:
        flash("Connect a Gmail account before changing automatic scanning.", "error")
    elif connection.get("needs_reauth"):
        flash("Reconnect Gmail before enabling automatic scanning.", "error")
    else:
        enabled = request.form.get("enabled") == "1"
        if db.set_gmail_auto_scan(session["user_id"], enabled):
            flash(f"Automatic Gmail scanning {'enabled' if enabled else 'disabled'}.", "success")
        else:
            flash("Could not update the automatic scan setting. Please try again.", "error")
    return redirect(url_for("email_account"))


@app.route("/notifications/<notification_id>/read", methods=["POST"])
@login_required
def notification_mark_read(notification_id):
    if not db.mark_notification_read(notification_id, session["user_id"]):
        abort(404)
    return redirect(url_for("dashboard"))


@app.route("/gmail/disconnect", methods=["POST"])
@login_required
def gmail_disconnect():
    db.delete_gmail_connection(session["user_id"])
    flash("Gmail account disconnected. Future automatic scans are stopped.", "success")
    return redirect(url_for("email_account"))


# ---------- API ----------

@app.route("/api/analyze", methods=["POST"])
@login_required
def api_analyze():
    data = request.get_json(silent=True) or request.form
    sender = str(data.get("sender_email") or "").strip()
    subject = str(data.get("subject") or "").strip()
    content = str(data.get("content") or "").strip()

    try:
        return jsonify(analyze_email(sender, subject, content, session["user_id"]))
    except ai_analysis.AnalysisUnavailable as error:
        return jsonify({
            "error": str(error),
            "analysis_completed": False,
            "error_category": error.category,
            "provider_http_status": error.provider_status_code,
        }), error.status_code


@app.route("/api/analyze-bulk", methods=["POST"])
@login_required
def api_analyze_bulk():
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        return jsonify({"error": "Choose a CSV file to scan."}), 400
    if not uploaded.filename.lower().endswith(".csv"):
        return jsonify({"error": "Please upload a .csv file."}), 400

    try:
        text = uploaded.stream.read().decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            return jsonify({"error": "CSV is empty or missing its header row."}), 400
        headers = {name.strip().lower(): name for name in reader.fieldnames if name}
        required = {"sender_email", "subject", "content"}
        if not required.issubset(headers):
            return jsonify({"error": "CSV needs these columns: sender_email, subject, content."}), 400

        rows = []
        for row in reader:
            sender = (row.get(headers["sender_email"]) or "").strip()
            subject = (row.get(headers["subject"]) or "").strip()
            content = (row.get(headers["content"]) or "").strip()
            if not (sender or subject or content):
                continue
            if not content:
                return jsonify({"error": f"CSV row {reader.line_num} has no email content."}), 400
            rows.append((sender, subject, content))
            if len(rows) > 100:
                return jsonify({"error": "Upload limit is 100 non-empty email rows per scan."}), 400
    except (UnicodeDecodeError, csv.Error):
        return jsonify({"error": "Could not read this CSV. Save it as UTF-8 CSV and try again."}), 400

    if not rows:
        return jsonify({"error": "No email rows found in the CSV."}), 400
    results = []
    try:
        for row in rows:
            results.append(analyze_email(*row, session["user_id"]))
    except ai_analysis.AnalysisUnavailable as error:
        return jsonify({
            "error": str(error),
            "analysis_completed": False,
            "error_category": error.category,
            "provider_http_status": error.provider_status_code,
            "completed_before_error": len(results),
        }), error.status_code
    return jsonify({"results": results, "total": len(results)})


@app.route("/api/stats")
@login_required
def api_stats():
    return jsonify(db.get_stats(user_id=session["user_id"]))


@app.route("/api/notifications/unread")
@login_required
def api_unread_notifications():
    user_id = session["user_id"]
    targets = [
        {"id": item["id"], "url": url_for("history") + "#detection-" + item["id"]}
        for item in db.get_notifications(user_id) if not item.get("is_read")
    ]
    return jsonify({"notifications": targets})


if __name__ == "__main__":
    try:
        db.init_db()
    except db.DatabaseConnectionError as error:
        app.logger.critical("Database startup failed: %s", error)
        raise SystemExit(1) from None
    start_gmail_scanner_worker()
    debug_enabled = os.getenv("FLASK_DEBUG", "0").strip().lower() in {"1", "true", "yes"}
    app.run(debug=debug_enabled, use_reloader=False)
