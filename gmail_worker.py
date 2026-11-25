"""Run automatic Gmail scans as a separate long-lived worker process."""

import database as db
from app import gmail_scanner_worker


if __name__ == "__main__":
    try:
        db.init_db()
    except db.DatabaseConnectionError as error:
        raise SystemExit(f"Database startup failed: {error}") from None
    gmail_scanner_worker()
