import pytest
from soc import anomaly, db, detector, rules as R


def test_roundtrip(sample_logs):
    logs, _ = sample_logs
    alerts = detector.analyze(logs)
    conn = db.connect(":memory:")
    db.init_db(conn)
    db.save_results(conn, logs, alerts, R.load_rules())
    assert conn.execute("SELECT COUNT(*) FROM log_events").fetchone()[0] == len(logs)
    back = db.load_alerts(conn)
    assert len(back) == len(alerts) and set(back.mitre_id) >= {"T1110", "T1078"}


def test_second_run_replaces_first(sample_logs):
    logs, _ = sample_logs
    conn = db.connect(":memory:")
    db.init_db(conn)
    alerts = detector.analyze(logs)
    for _ in range(2):
        db.save_results(conn, logs, alerts, R.load_rules())
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == len(alerts)


def test_failed_save_rolls_back_and_keeps_old_data(sample_logs):
    logs, _ = sample_logs
    alerts = detector.analyze(logs)
    conn = db.connect(":memory:")
    db.init_db(conn)
    db.save_results(conn, logs, alerts, R.load_rules())
    broken = alerts.copy()
    broken["event_count"] = broken["event_count"].astype(object)
    broken.loc[0, "event_count"] = "not a number"          # int() fails after events were already inserted
    with pytest.raises(Exception):
        db.save_results(conn, logs.iloc[:10], broken, R.load_rules())
    assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == len(alerts)
    assert conn.execute("SELECT COUNT(*) FROM log_events").fetchone()[0] == len(logs)


def test_foreign_keys_and_indexes_exist():
    conn = db.connect(":memory:")
    db.init_db(conn)
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert {"idx_alerts_ip", "idx_events_ip"} <= names
