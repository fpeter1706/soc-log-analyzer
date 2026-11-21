import json
import os

import pandas as pd
from soc import anomaly, detector, parser
from conftest import ROOT, failed


def test_too_little_data_returns_empty():
    logs, _ = parser.parse_logs("\n".join(failed(6)), "", 2026)
    assert anomaly.detect_anomalies(logs).empty


def test_empty_logs():
    assert anomaly.detect_anomalies(pd.DataFrame(columns=parser.COLUMNS)).empty


def test_flood_without_any_rule_hit_is_found_by_ml(sample_logs):
    logs, _ = sample_logs
    assert "198.51.100.200" not in set(detector.analyze(logs).ip)       # rules are blind to it
    ml = anomaly.detect_anomalies(logs)
    assert "198.51.100.200" in set(ml.ip)
    row = ml[ml.ip == "198.51.100.200"].iloc[0]
    assert row.engine == "ml" and row.severity == "Medium" and "request rate" in row.details


def test_deterministic(sample_logs):
    logs, _ = sample_logs
    a, b = anomaly.detect_anomalies(logs), anomaly.detect_anomalies(logs)
    assert list(a.ip) == list(b.ip)


def test_combined_recall_is_complete(sample_logs):
    logs, _ = sample_logs
    gt = set(json.load(open(os.path.join(ROOT, "sample_data", "ground_truth.json")))["attacker_ips"])
    found = set(detector.analyze(logs).ip) | set(anomaly.detect_anomalies(logs).ip)
    assert gt <= found


def test_alert_schema_matches_rule_alerts(sample_logs):
    logs, _ = sample_logs
    assert list(anomaly.detect_anomalies(logs).columns) == detector.ALERT_COLUMNS
