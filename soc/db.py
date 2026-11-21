"""SQLite storage for events, rules and alerts."""
from __future__ import annotations

import sqlite3

import pandas as pd

SCHEMA = """
CREATE TABLE IF NOT EXISTS log_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL, ts TEXT NOT NULL, ip TEXT, username TEXT,
    event TEXT NOT NULL, method TEXT, path TEXT, status INTEGER, raw TEXT
);
CREATE TABLE IF NOT EXISTS rules (
    rule_id TEXT PRIMARY KEY, name TEXT NOT NULL, type TEXT, severity TEXT NOT NULL, threshold INTEGER, window_minutes INTEGER
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id TEXT NOT NULL, rule_name TEXT NOT NULL, severity TEXT NOT NULL,
    ip TEXT, first_seen TEXT, last_seen TEXT, event_count INTEGER, details TEXT,
    mitre_id TEXT, mitre_name TEXT, tactic TEXT, engine TEXT NOT NULL DEFAULT 'rules'
);
CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(ip);
CREATE INDEX IF NOT EXISTS idx_events_ip ON log_events(ip);
"""


def connect(path: str = "soc_alerts.db") -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()


def save_results(conn, logs: pd.DataFrame, alerts: pd.DataFrame, rules: list) -> None:
    """Replace stored data with the latest run, atomically (all or nothing).
    Plain executemany is used instead of DataFrame.to_sql because to_sql commits on its own,
    which would break the single transaction."""
    with conn:  # one transaction: an error part-way rolls everything back, old data stays intact
        conn.execute("DELETE FROM alerts")
        conn.execute("DELETE FROM log_events")
        conn.execute("DELETE FROM rules")
        conn.executemany("INSERT INTO rules VALUES (?,?,?,?,?,?)",
                         [(r["id"], r["name"], r["type"], r["severity"], r.get("threshold"), r.get("window_minutes"))
                          for r in rules])
        if len(logs):
            rows = [(r.source, str(r.ts), r.ip, r.username, r.event, r.method, r.path,
                     None if pd.isna(r.status) else int(r.status), r.raw) for r in logs.itertuples()]
            conn.executemany("INSERT INTO log_events (source, ts, ip, username, event, method, path, status, raw) "
                             "VALUES (?,?,?,?,?,?,?,?,?)", rows)
        if len(alerts):
            rows = [(a.rule_id, a.rule_name, a.severity, a.ip, str(a.first_seen), str(a.last_seen), int(a.event_count),
                     a.details, a.mitre_id, a.mitre_name, a.tactic, a.engine) for a in alerts.itertuples()]
            conn.executemany("INSERT INTO alerts (rule_id, rule_name, severity, ip, first_seen, last_seen, event_count, "
                             "details, mitre_id, mitre_name, tactic, engine) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)


def load_alerts(conn) -> pd.DataFrame:
    return pd.read_sql_query("SELECT * FROM alerts ORDER BY first_seen", conn)
