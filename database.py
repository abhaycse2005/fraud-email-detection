import os
import atexit
import hashlib
import json
import logging
import time
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
from pymongo import MongoClient, DESCENDING, ReturnDocument
from pymongo.errors import ConnectionFailure, DuplicateKeyError
from bson import ObjectId
from bson.errors import InvalidId
import certifi
import hmac
import re
from werkzeug.security import check_password_hash, generate_password_hash


# ============================================================
# LOAD ENVIRONMENT VARIABLES
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BASE_DIR, ".env")
load_dotenv(ENV_PATH)


# ============================================================
# MONGODB ATLAS CONFIGURATION
# ============================================================

MONGODB_URI = os.getenv("MONGODB_URI", "").strip()
MAX_STARTUP_ATTEMPTS = 5
STARTUP_RETRY_DELAY_SECONDS = 3
logger = logging.getLogger(__name__)


# ============================================================
# MONGODB CLIENT
# ============================================================
# TLS/SSL configuration added for MongoDB Atlas.
# certifi provides trusted CA certificates.
# ============================================================

class DatabaseConnectionError(RuntimeError):
    """Raised when the required MongoDB Atlas database is not available."""

    def __init__(self, message, *, retryable=False):
        super().__init__(message)
        self.retryable = retryable


client = None
db = None
users_collection = None
detections_collection = None
gmail_connections_collection = None


def close_mongo_client():
    """Close the process-wide Mongo client during orderly shutdown."""
    if client is not None:
        client.close()


atexit.register(close_mongo_client)


def _utc_now():
    return datetime.now(timezone.utc)


# ============================================================
# DATABASE
# ============================================================

# ============================================================
# PASSWORD HASHING
# ============================================================

def hash_password(password: str) -> str:
    return generate_password_hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Verify modern password hashes and support legacy SHA-256 hashes."""
    if re.fullmatch(r"[0-9a-f]{64}", password_hash or ""):
        legacy_hash = hashlib.sha256(password.encode()).hexdigest()
        return hmac.compare_digest(password_hash, legacy_hash)
    try:
        return check_password_hash(password_hash, password)
    except (TypeError, ValueError):
        return False


def _ensure_initial_admin():
    """Create an initial administrator only when explicitly configured."""
    email = os.getenv("INITIAL_ADMIN_EMAIL", "").strip().lower()
    password = os.getenv("INITIAL_ADMIN_PASSWORD", "")
    if not email or not password:
        return
    user = {
        "name": "Admin", "email": email, "password_hash": hash_password(password),
        "role": "admin", "created_at": _utc_now(),
    }
    # The unique email index and upsert make repeated startup initialization safe.
    users_collection.update_one(
        {"email": email}, {"$setOnInsert": user}, upsert=True
    )


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def _init_db_once():
    """
    Verify MongoDB Atlas availability and initialize its collections/indexes.
    """

    # --------------------------------------------------------
    # Test MongoDB connection first
    # --------------------------------------------------------

    global client, db, users_collection, detections_collection, gmail_connections_collection
    if not MONGODB_URI:
        raise DatabaseConnectionError("MONGODB_URI is missing. Add the Atlas connection string to .env.")
    if client is None:
        try:
            client = MongoClient(
                MONGODB_URI,
                tls=True,
                tlsCAFile=certifi.where(),
                serverSelectionTimeoutMS=10_000,
                connectTimeoutMS=10_000,
                socketTimeoutMS=10_000,
                retryReads=True,
                retryWrites=True,
            )
            db = client["fraud_email_detection"]
            users_collection = db["users"]
            detections_collection = db["detections"]
            gmail_connections_collection = db["gmail_connections"]
        except Exception as error:
            client = db = None
            users_collection = detections_collection = gmail_connections_collection = None
            error_detail = str(error).lower()
            if "idna" in error_detail or "codepoint" in error_detail:
                raise DatabaseConnectionError(
                    "DNS could not encode a hostname while preparing the MongoDB SRV connection. "
                    "Check that the computer name and Atlas hostname use valid DNS characters; "
                    "the URI value was not logged.",
                    retryable=False,
                ) from None
            if ("dns" in error_detail or "srv" in error_detail
                    or "name resolution" in error_detail):
                raise DatabaseConnectionError(
                    "Could not resolve the MongoDB Atlas cluster through DNS. "
                    "Check the cluster hostname and network DNS access.",
                    retryable=True,
                ) from None
            raise DatabaseConnectionError(
                "Could not configure the MongoDB Atlas client "
                f"({error.__class__.__name__}). Check the URI format in .env."
            ) from None

    try:
        client.admin.command("ping")
    except DatabaseConnectionError:
        raise
    except Exception as error:
        raise DatabaseConnectionError(
            "Could not connect to MongoDB Atlas "
            f"({error.__class__.__name__}). Check the URI, Atlas IP access list, database user, and network.",
            retryable=isinstance(error, ConnectionFailure),
        ) from None


    # --------------------------------------------------------
    # Create useful indexes
    # --------------------------------------------------------

    try:
        users_collection.create_index("email", unique=True)
        detections_collection.create_index([("created_at", DESCENDING)])
        detections_collection.create_index(
            [("user_id", 1), ("external_message_id", 1)],
            unique=True,
            partialFilterExpression={"external_message_id": {"$type": "string"}},
        )
    except Exception as error:
        raise DatabaseConnectionError(
            f"Connected to MongoDB Atlas but database initialization failed ({error.__class__.__name__}).",
            retryable=isinstance(error, ConnectionFailure),
        ) from None


    # --------------------------------------------------------
    # Create an administrator only when the operator configured one.
    # --------------------------------------------------------

    try:
        _ensure_initial_admin()
    except Exception as error:
        raise DatabaseConnectionError(
            f"Connected to MongoDB Atlas but initial database setup failed ({error.__class__.__name__}).",
            retryable=isinstance(error, ConnectionFailure),
        ) from None


    print("MongoDB Atlas initialized successfully.")


def init_db():
    """Initialize Atlas, retrying transient connection failures during startup.

    PyMongo's pooled client also handles supported retryable operations during
    normal runtime. This loop deliberately wraps startup only; application writes
    are not blindly replayed by our code.
    """
    if not MONGODB_URI:
        # Missing configuration cannot be repaired by retrying a network call.
        return _init_db_once()

    last_error = None
    for attempt in range(1, MAX_STARTUP_ATTEMPTS + 1):
        try:
            return _init_db_once()
        except DatabaseConnectionError as error:
            last_error = error
            logger.warning(
                "MongoDB Atlas startup attempt %d/%d failed (retryable=%s).",
                attempt, MAX_STARTUP_ATTEMPTS, error.retryable,
            )
            if not error.retryable or attempt == MAX_STARTUP_ATTEMPTS:
                break
            time.sleep(STARTUP_RETRY_DELAY_SECONDS)

    if last_error is None:
        raise DatabaseConnectionError("MongoDB Atlas initialization did not run.")
    if last_error.retryable:
        logger.error(
            "MongoDB Atlas is unavailable after %d startup attempts; stopping without a database fallback.",
            attempt,
        )
    raise last_error


# ============================================================
# USERS
# ============================================================

def create_user(name, email, password):
    email = email.strip().lower()
    if users_collection.find_one({"email": email}):
        return False
    user = {
        "name": name,
        "email": email,
        "password_hash": hash_password(password),
        "role": "user",
        "created_at": _utc_now(),
    }
    try:
        users_collection.insert_one(user)
        return True
    except DuplicateKeyError:
        return False


# ============================================================
# GET USER BY EMAIL
# ============================================================

def get_user_by_email(email):
    email = email.strip().lower()
    user = users_collection.find_one({"email": email})
    if not user:
        return None


    # --------------------------------------------------------
    # Convert MongoDB ObjectId to string
    # --------------------------------------------------------

    user["id"] = str(user["_id"])

    return user


# ============================================================
# VERIFY USER
# ============================================================

def verify_user(email, password):

    user = get_user_by_email(email)

    if user:

        if verify_password(user["password_hash"], password):
            if re.fullmatch(r"[0-9a-f]{64}", user["password_hash"] or ""):
                upgraded_hash = hash_password(password)
                users_collection.update_one(
                    {"_id": ObjectId(user["id"]), "password_hash": user["password_hash"]},
                    {"$set": {"password_hash": upgraded_hash}},
                )
                user["password_hash"] = upgraded_hash
            return user

    return None


def change_user_password(user_id, current_password, new_password):
    """Change a user's password only when the current password matches."""
    new_hash = hash_password(new_password)

    try:
        object_id = ObjectId(user_id)
        user = users_collection.find_one({"_id": object_id})
        if not user or not verify_password(user.get("password_hash", ""), current_password):
            return False
        result = users_collection.update_one(
            {"_id": object_id},
            {"$set": {"password_hash": new_hash}},
        )
        return result.modified_count == 1
    except (InvalidId, TypeError):
        return False


def change_user_email(user_id, current_password, new_email):
    """Change the account email after verifying the current password."""
    normalized_email = new_email.strip().lower()

    try:
        object_id = ObjectId(user_id)
        user = users_collection.find_one({"_id": object_id})
        if not user or not verify_password(user.get("password_hash", ""), current_password):
            return "invalid_password"
        if user.get("email", "").lower() == normalized_email:
            return "unchanged"
        users_collection.update_one(
            {"_id": object_id},
            {"$set": {"email": normalized_email}},
        )
        return "changed"
    except DuplicateKeyError:
        return "exists"
    except (InvalidId, TypeError):
        return "error"


# ============================================================
# GET ALL USERS
# ============================================================

def get_all_users():
    users = users_collection.find().sort(
        "created_at",
        DESCENDING
    )

    result = []

    for user in users:

        result.append({
            "id": str(user["_id"]),
            "name": user.get("name", ""),
            "email": user.get("email", ""),
            "role": user.get("role", "user"),
            "created_at": user.get("created_at")
        })

    return result


# ============================================================
# DETECTIONS
# ============================================================

def insert_detection(
    user_id,
    sender_email,
    subject,
    content,
    prediction,
    risk_level,
    confidence,
    threat_category,
    risk_score=None,
    signals=None,
    external_message_id=None,
    gemini_prediction=None,
    gemini_indicators=None,
    rule_based_signals=None,
    decision_method=None,
    explanation=None,
    recommended_action=None,
    security_metadata=None,
    notify_new_fraud=False,
    analysis_fingerprint=None,
    existing_detection_id=None,
):

    detection = {
        "user_id": str(user_id),
        "sender_email": sender_email,
        "subject": subject,
        "content": content,
        "prediction": prediction,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "signals": signals or [],
        "confidence": confidence,
        "gemini_prediction": gemini_prediction,
        "gemini_indicators": gemini_indicators or [],
        "rule_based_signals": rule_based_signals or [],
        "decision_method": decision_method,
        "local_ml_prediction": None,
        "local_ml_used": False,
        "threat_category": threat_category,
        "explanation": explanation,
        "recommended_action": recommended_action,
        "security_metadata": security_metadata or {},
        "created_at": _utc_now()
    }
    if external_message_id:
        detection["external_message_id"] = external_message_id
    if analysis_fingerprint:
        detection["analysis_fingerprint"] = str(analysis_fingerprint)
    if (external_message_id and notify_new_fraud
            and str(prediction).lower() == "fraudulent"):
        detection["notification"] = {
            "title": "New Fraudulent Email Detected",
            "message": "A newly received email was classified as fraudulent. Review the analysis before taking action.",
            "created_at": detection["created_at"],
            "explanation": str(explanation or "Review the saved analysis evidence and verify the sender independently.")[:500],
            "read": False,
        }


    if existing_detection_id is not None and external_message_id:
        # Replace stale analysis for changed message content in place. Keep the
        # original notification's read state so reanalysis cannot duplicate alerts.
        existing = detections_collection.find_one({
            "_id": existing_detection_id,
            "user_id": str(user_id),
            "external_message_id": external_message_id,
        }, {"notification": 1, "created_at": 1})
        if existing:
            detection.pop("created_at", None)
            detection["updated_at"] = _utc_now()
            notification = existing.get("notification")
            if notification and str(prediction).lower() == "fraudulent":
                detection["notification"] = {
                    **notification,
                    "explanation": str(explanation or notification.get("explanation", ""))[:500],
                }
            elif notify_new_fraud and str(prediction).lower() == "fraudulent":
                detection["notification"] = {
                    "title": "New Fraudulent Email Detected",
                    "message": "A newly received email was classified as fraudulent. Review the analysis before taking action.",
                    "created_at": _utc_now(),
                    "explanation": str(explanation or "Review the saved analysis evidence and verify the sender independently.")[:500],
                    "read": False,
                }
            result = detections_collection.update_one(
                {"_id": existing_detection_id, "user_id": str(user_id),
                 "external_message_id": external_message_id},
                {"$set": detection,
                 **({"$unset": {"notification": ""}}
                    if str(prediction).lower() != "fraudulent" else {})},
            )
            return str(existing_detection_id) if result.matched_count else None

    try:
        result = detections_collection.insert_one(detection)
    except Exception as error:
        if external_message_id and isinstance(error, DuplicateKeyError):
            return None
        raise

    return str(result.inserted_id)


def save_gmail_connection(user_id, email, token_ciphertext):
    user_id = str(user_id)
    gmail_connections_collection.update_one(
        {"user_id": user_id},
        {"$set": {"email": email, "token_ciphertext": token_ciphertext,
                   "connected_at": _utc_now(), "needs_reauth": False},
         "$setOnInsert": {"auto_scan_enabled": True, "scan_status": "ready"}},
        upsert=True,
    )


def update_gmail_scan_checkpoint(user_id, epoch):
    user_id = str(user_id)
    gmail_connections_collection.update_one(
        {"user_id": user_id}, {"$set": {"last_scan_epoch": float(epoch)}}
    )


def set_gmail_auto_scan(user_id, enabled):
    """Change only this user's auto-scan preference; do not clear reauth state."""
    result = gmail_connections_collection.update_one(
        {"user_id": str(user_id), "needs_reauth": {"$ne": True}},
        {"$set": {"auto_scan_enabled": bool(enabled), "scan_status": "ready" if enabled else "paused"}},
    )
    return result.modified_count == 1 or result.matched_count == 1


def mark_gmail_reauth_required(user_id):
    gmail_connections_collection.update_one(
        {"user_id": str(user_id)},
        {"$set": {"needs_reauth": True, "auto_scan_enabled": False,
                  "scan_status": "reauthorization_required", "last_scan_at": _utc_now()}},
    )


def update_gmail_scan_status(user_id, status, *, scanned=None, failed=None,
                             deferred=None, error_code=None, error_category=None,
                             http_status=None):
    values = {"scan_status": status}
    if status != "running":
        values["last_scan_at"] = _utc_now()
    if scanned is not None:
        values["last_scan_count"] = int(scanned)
    if failed is not None:
        values["last_scan_failed_count"] = int(failed)
    elif status == "running":
        values["last_scan_failed_count"] = 0
    if deferred is not None:
        values["last_scan_deferred_count"] = int(deferred)
    elif status == "running":
        values["last_scan_deferred_count"] = 0
    if error_code:
        values["last_scan_error"] = str(error_code)[:80]
    else:
        values["last_scan_error"] = None
    values["last_scan_error_category"] = str(error_category)[:80] if error_category else None
    values["last_scan_http_status"] = int(http_status) if isinstance(http_status, int) else None
    gmail_connections_collection.update_one(
        {"user_id": str(user_id)}, {"$set": values}
    )


def update_gmail_scan_progress(user_id, *, page_token, processed, total=None, historical):
    """Persist a safe resume cursor after a whole Gmail page has succeeded."""
    values = {
        "scan_status": "running",
        "scan_mode": "historical" if historical else "incremental",
        "scan_progress_count": int(processed),
        "scan_progress_total": int(total) if total is not None else None,
        "scan_progress_checkpoint_count": int(processed),
        "scan_progress_failed_count": 0,
        "scan_progress_success_count": int(processed),
        "scan_progress_deferred_count": 0,
    }
    if historical:
        values["historical_page_token"] = page_token
        values["historical_scan_in_progress"] = bool(page_token)
    gmail_connections_collection.update_one(
        {"user_id": str(user_id)}, {"$set": values}
    )


def update_gmail_scan_live_progress(user_id, *, processed, total=None,
                                    historical, failed=0, successful=None,
                                    deferred=None):
    """Update displayed attempts without advancing the durable Gmail cursor."""
    values = {
        "scan_mode": "historical" if historical else "incremental",
        "scan_progress_count": int(processed),
        "scan_progress_total": int(total) if total is not None else None,
        "scan_progress_failed_count": int(failed),
    }
    if successful is not None:
        values["scan_progress_success_count"] = int(successful)
    if deferred is not None:
        values["scan_progress_deferred_count"] = int(deferred)
    gmail_connections_collection.update_one(
        {"user_id": str(user_id)}, {"$set": values},
    )


def finish_gmail_historical_scan(user_id, epoch, scanned):
    """Complete the first pass and establish the incremental scan checkpoint."""
    gmail_connections_collection.update_one(
        {"user_id": str(user_id)},
        {"$set": {
            "last_scan_epoch": float(epoch), "historical_scan_complete": True,
            "historical_scan_in_progress": False, "historical_page_token": None,
            "scan_progress_count": int(scanned),
            "scan_progress_checkpoint_count": int(scanned),
            "scan_progress_failed_count": 0, "scan_progress_total": int(scanned),
            "scan_progress_success_count": int(scanned), "scan_progress_deferred_count": 0,
            "scan_mode": "historical", "scan_status": "success",
            "last_scan_at": _utc_now(), "last_scan_count": int(scanned),
            "last_scan_failed_count": 0,
            "last_scan_deferred_count": 0,
            "last_scan_error": None, "last_scan_error_category": None,
            "last_scan_http_status": None,
        }},
    )


def acquire_gmail_scan_lease(user_id, token, lease_seconds=900):
    """Atomically claim this account's scan slot so workers don't duplicate work."""
    now = _utc_now()
    connection = gmail_connections_collection.find_one_and_update(
        {"user_id": str(user_id), "$or": [
            {"scan_lease_until": {"$lte": now}},
            {"scan_lease_until": {"$exists": False}},
        ]},
        {"$set": {"scan_lease_token": token,
                   "scan_lease_until": now + timedelta(seconds=lease_seconds)}},
        return_document=ReturnDocument.AFTER,
    )
    return bool(connection and connection.get("scan_lease_token") == token)


def renew_gmail_scan_lease(user_id, token, lease_seconds=900):
    result = gmail_connections_collection.update_one(
        {"user_id": str(user_id), "scan_lease_token": token},
        {"$set": {"scan_lease_until": _utc_now() + timedelta(seconds=lease_seconds)}},
    )
    return result.matched_count == 1


def release_gmail_scan_lease(user_id, token):
    gmail_connections_collection.update_one(
        {"user_id": str(user_id), "scan_lease_token": token},
        {"$unset": {"scan_lease_token": "", "scan_lease_until": ""}},
    )


def get_gmail_connection(user_id):
    user_id = str(user_id)
    return gmail_connections_collection.find_one({"user_id": user_id})


def get_gmail_connections():
    # Missing auto_scan_enabled is treated as enabled for existing connections.
    return list(gmail_connections_collection.find({
        "auto_scan_enabled": {"$ne": False}, "needs_reauth": {"$ne": True},
    }))


def delete_gmail_connection(user_id):
    user_id = str(user_id)
    gmail_connections_collection.delete_one({"user_id": user_id})


def has_scanned_gmail_message(user_id, external_message_id):
    return detections_collection.find_one({"user_id": str(user_id), "external_message_id": external_message_id}, {"_id": 1}) is not None


def get_gmail_detection(user_id, external_message_id):
    """Read a cached Gmail result only within its owning user's namespace."""
    return detections_collection.find_one(
        {"user_id": str(user_id), "external_message_id": external_message_id},
        {"_id": 1, "analysis_fingerprint": 1},
    )


def get_gmail_detections(user_id, external_message_ids):
    """Load cached message identities in one user-scoped query for a Gmail page."""
    message_ids = [str(message_id) for message_id in external_message_ids if message_id]
    if not message_ids:
        return {}
    rows = detections_collection.find(
        {"user_id": str(user_id), "external_message_id": {"$in": message_ids}},
        {"_id": 1, "external_message_id": 1, "analysis_fingerprint": 1},
    )
    return {row["external_message_id"]: row for row in rows
            if row.get("external_message_id")}


def get_notifications(user_id, limit=10):
    """Return only this user's unread-or-read new-fraud Gmail alerts."""
    rows = detections_collection.find(
        {"user_id": str(user_id), "external_message_id": {"$exists": True},
         "notification.title": "New Fraudulent Email Detected"},
        {"subject": 1, "prediction": 1, "notification": 1, "created_at": 1},
    ).sort("created_at", DESCENDING).limit(limit)
    return [{
        "id": str(row["_id"]), "subject": row.get("subject", ""),
        "classification": row.get("prediction", ""),
        "title": row.get("notification", {}).get("title", "Email analysis is ready."),
        "message": row.get("notification", {}).get("message", "Email analysis is ready."),
        "explanation": row.get("notification", {}).get("explanation", row.get("explanation", "")),
        "created_at": row.get("notification", {}).get("created_at", row.get("created_at")),
        "is_read": bool(row.get("notification", {}).get("read", False)),
    } for row in rows]


def get_unread_notification_count(user_id):
    return detections_collection.count_documents({
        "user_id": str(user_id), "external_message_id": {"$exists": True},
        "notification.title": "New Fraudulent Email Detected",
        "notification.read": {"$ne": True},
    })


def mark_notification_read(notification_id, user_id):
    try:
        object_id = ObjectId(notification_id)
    except (InvalidId, TypeError):
        return False
    result = detections_collection.update_one(
        {"_id": object_id, "user_id": str(user_id),
         "external_message_id": {"$exists": True},
         "notification.title": "New Fraudulent Email Detected"},
        {"$set": {"notification.read": True}},
    )
    return result.matched_count == 1


def get_recent_gmail_alerts(user_id, limit=5):
    rows = detections_collection.find(
        {"user_id": str(user_id), "external_message_id": {"$exists": True},
         "prediction": {"$in": ["Suspicious", "Fraudulent"]}},
        {"subject": 1, "prediction": 1, "risk_level": 1, "risk_score": 1, "signals": 1, "created_at": 1},
    ).sort("created_at", DESCENDING).limit(limit)
    return [{"subject": row.get("subject", ""), "prediction": row.get("prediction", ""),
             "risk_level": row.get("risk_level", ""), "risk_score": row.get("risk_score"),
             "signals": row.get("signals", []),
             "created_at": row.get("created_at")}
            for row in rows]


def _decode_detection_signals(detection):
    signals = detection.get("signals")
    if isinstance(signals, str):
        try:
            detection["signals"] = json.loads(signals)
        except (TypeError, json.JSONDecodeError):
            detection["signals"] = []
    elif not isinstance(signals, list):
        detection["signals"] = []
    return detection


# ============================================================
# GET RECENT DETECTIONS
# ============================================================

def get_recent_detections(limit=10, user_id=None):
    query = {"user_id": str(user_id)} if user_id is not None else {}
    detections = detections_collection.find(query).sort(
        "created_at",
        DESCENDING
    ).limit(limit)

    result = []

    for detection in detections:

        result.append({
            "id": str(detection["_id"]),
            "user_id": detection.get("user_id"),
            "sender_email": detection.get("sender_email", ""),
            "subject": detection.get("subject", ""),
            "content": detection.get("content", ""),
            "prediction": detection.get("prediction", ""),
            "risk_level": detection.get("risk_level", ""),
            "risk_score": detection.get("risk_score"),
            "signals": detection.get("signals", []),
            "confidence": detection.get("confidence"),
            "gemini_prediction": detection.get("gemini_prediction"),
            "gemini_indicators": detection.get("gemini_indicators", []),
            "rule_based_signals": detection.get("rule_based_signals", []),
            "decision_method": detection.get("decision_method"),
            "local_ml_prediction": detection.get("local_ml_prediction"),
            "local_ml_used": detection.get("local_ml_used", False),
            "threat_category": detection.get("threat_category"),
            "explanation": detection.get("explanation"),
            "recommended_action": detection.get("recommended_action"),
            "security_metadata": detection.get("security_metadata", {}),
            "created_at": detection.get("created_at")
        })

    return result


# ============================================================
# GET ALL DETECTIONS
# ============================================================

def get_all_detections(user_id=None):
    query = {}

    if user_id is not None:
        query["user_id"] = str(user_id)


    detections = detections_collection.find(
        query
    ).sort(
        "created_at",
        DESCENDING
    )


    result = []

    for detection in detections:

        result.append({
            "id": str(detection["_id"]),
            "user_id": detection.get("user_id"),
            "sender_email": detection.get("sender_email", ""),
            "subject": detection.get("subject", ""),
            "content": detection.get("content", ""),
            "prediction": detection.get("prediction", ""),
            "risk_level": detection.get("risk_level", ""),
            "risk_score": detection.get("risk_score"),
            "signals": detection.get("signals", []),
            "confidence": detection.get("confidence"),
            "gemini_prediction": detection.get("gemini_prediction"),
            "gemini_indicators": detection.get("gemini_indicators", []),
            "rule_based_signals": detection.get("rule_based_signals", []),
            "decision_method": detection.get("decision_method"),
            "local_ml_prediction": detection.get("local_ml_prediction"),
            "local_ml_used": detection.get("local_ml_used", False),
            "threat_category": detection.get("threat_category"),
            "explanation": detection.get("explanation"),
            "recommended_action": detection.get("recommended_action"),
            "security_metadata": detection.get("security_metadata", {}),
            "created_at": detection.get("created_at")
        })

    return result


# ============================================================
# STATISTICS
# ============================================================

def get_stats(user_id=None):
    # --------------------------------------------------------
    # Total detections
    # --------------------------------------------------------

    detection_filter = {"user_id": str(user_id)} if user_id is not None else {}
    total = detections_collection.count_documents(detection_filter)


    # --------------------------------------------------------
    # Safe emails
    # --------------------------------------------------------

    safe = detections_collection.count_documents({**detection_filter,
        "prediction": "Safe"
    })


    # --------------------------------------------------------
    # Suspicious emails
    # --------------------------------------------------------

    suspicious = detections_collection.count_documents({**detection_filter,
        "prediction": "Suspicious"
    })


    # --------------------------------------------------------
    # Fraudulent emails
    # --------------------------------------------------------

    fraudulent = detections_collection.count_documents({**detection_filter,
        "prediction": "Fraudulent"
    })


    # --------------------------------------------------------
    # Threat Categories
    # --------------------------------------------------------

    threat_categories = list(
        detections_collection.aggregate([

            {
                "$match": {
                    **detection_filter,
                    "threat_category": {
                        "$ne": None
                    }
                }
            },

            {
                "$group": {
                    "_id": "$threat_category",
                    "c": {
                        "$sum": 1
                    }
                }
            },

            {
                "$sort": {
                    "c": -1
                }
            }

        ])
    )


    threat_categories = [

        {
            "threat_category": item["_id"],
            "c": item["c"]
        }

        for item in threat_categories

    ]


    # --------------------------------------------------------
    # Trend
    # --------------------------------------------------------

    trend_pipeline = []
    if detection_filter:
        trend_pipeline.append({"$match": detection_filter})
    trend_pipeline.extend([

            {
                "$group": {

                    "_id": {

                        "$dateToString": {

                            "format": "%Y-%m-%d",

                            "date": "$created_at"

                        }

                    },


                    "safe": {

                        "$sum": {

                            "$cond": [

                                {
                                    "$eq": [
                                        "$prediction",
                                        "Safe"
                                    ]
                                },

                                1,

                                0

                            ]

                        }

                    },


                    "suspicious": {

                        "$sum": {

                            "$cond": [

                                {
                                    "$eq": [
                                        "$prediction",
                                        "Suspicious"
                                    ]
                                },

                                1,

                                0

                            ]

                        }

                    },


                    "fraudulent": {

                        "$sum": {

                            "$cond": [

                                {
                                    "$eq": [
                                        "$prediction",
                                        "Fraudulent"
                                    ]
                                },

                                1,

                                0

                            ]

                        }

                    }

                }

            },


            {
                "$sort": {
                    "_id": -1
                }
            },


            {
                "$limit": 7
            },


            {
                "$sort": {
                    "_id": 1
                }
            }

        ])
    trend = list(detections_collection.aggregate(trend_pipeline))


    trend = [

        {
            "day": item["_id"],
            "safe": item["safe"],
            "suspicious": item["suspicious"],
            "fraudulent": item["fraudulent"]
        }

        for item in trend

    ]


    # --------------------------------------------------------
    # Return statistics
    # --------------------------------------------------------

    return {

        "total": total,

        "safe": safe,

        "suspicious": suspicious,

        "fraudulent": fraudulent,

        "threat_categories": threat_categories,

        "trend": trend

    }


# ============================================================
# TEST DATABASE
# ============================================================

if __name__ == "__main__":

    init_db()

    print("--------------------------------------")
    print("MongoDB Atlas connection successful")
    print("Database: fraud_email_detection")
    print("--------------------------------------")
