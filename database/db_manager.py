
import sqlite3
import hashlib
import pandas as pd

DB_PATH = "soc_sentinel.db"


def get_connection():
    return sqlite3.connect(DB_PATH)


def initialize_db():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT UNIQUE,
                severity TEXT,
                alert_type TEXT,
                source_ip TEXT,
                count INTEGER,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)


def save_alerts(alerts_df):
    if alerts_df.empty:
        return 0

    saved = 0

    with get_connection() as conn:
        for _, alert in alerts_df.iterrows():
            raw = (
                f"{alert['severity']}|{alert['alert_type']}|"
                f"{alert['source_ip']}|{alert['description']}"
            )
            fingerprint = hashlib.sha256(
                raw.encode("utf-8")
            ).hexdigest()

            cursor = conn.execute("""
                INSERT OR IGNORE INTO alerts
                (fingerprint, severity, alert_type, source_ip, count, description)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                fingerprint,
                alert["severity"],
                alert["alert_type"],
                alert["source_ip"],
                int(alert["count"]),
                alert["description"]
            ))

            saved += cursor.rowcount

    return saved


def get_alert_history():
    with get_connection() as conn:
        return pd.read_sql_query(
            "SELECT * FROM alerts ORDER BY created_at DESC",
            conn
        )
