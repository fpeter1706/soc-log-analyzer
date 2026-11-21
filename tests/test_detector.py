import json
import os

import pandas as pd
import pytest
from soc import detector, parser
from conftest import ROOT, failed, ssh, web


def run(ssh_lines=(), web_lines=(), rules=None):
    logs, _ = parser.parse_logs("\n".join(ssh_lines), "\n".join(web_lines), 2026)
    return detector.analyze(logs, rules)


def ids(alerts):
    return sorted(set(alerts["rule_id"])) if len(alerts) else []


CASES = [
    ("6 failures in 12 s", failed(6), [], ["R1"]),
    ("5 failures is exactly the threshold", failed(5), [], ["R1"]),
    ("4 failures is below the threshold", failed(4), [], []),
    ("5 failures spread over 30 minutes", [ssh(i * 400, "Failed password for root from 9.9.9.9 port 22 ssh2") for i in range(5)], [], []),
    ("4 failures with 4 usernames", failed(4, users=("a", "b", "c", "d"), gap=20), [], ["R2"]),
    ("success after 6 failures", failed(6) + [ssh(30, "Accepted password for root from 9.9.9.9 port 22 ssh2")], [], ["R1", "R3"]),
    ("success without failures", [ssh(5, "Accepted password for peter from 10.0.0.5 port 22 ssh2")], [], []),
    ("success from a different IP than the failures", failed(6) + [ssh(30, "Accepted password for root from 8.8.8.8 port 22 ssh2")], [], ["R1"]),
    ("12 x 404 in a minute", [], [web(i * 4, "8.8.8.8", f"/p{i}", 404) for i in range(12)], ["R4"]),
    ("9 x 404 is below threshold", [], [web(i * 4, "8.8.8.8", f"/p{i}", 404) for i in range(9)], []),
    ("normal web traffic", [], [web(i, "10.0.0.5", "/index.html", 200) for i in range(20)], []),
    ("SQL injection", [], [web(1, "7.7.7.7", "/products?id=1%20OR%201=1", 200)], ["R5"]),
    ("XSS", [], [web(1, "7.7.7.7", "/s?q=<script>alert(1)</script>", 200)], ["R5"]),
    ("path traversal", [], [web(1, "7.7.7.7", "/get?f=../../etc/passwd", 403)], ["R5"]),
    ("double-encoded path traversal", [], [web(1, "7.7.7.7", "/get?f=%252e%252e%252f%252e%252e%252fetc/passwd", 403)], ["R5"]),
    ("garbage input", ["garbage"], ["more garbage"], []),
]


@pytest.mark.parametrize("name,ssh_lines,web_lines,expected", CASES, ids=[c[0] for c in CASES])
def test_rule_cases(name, ssh_lines, web_lines, expected):
    assert ids(run(ssh_lines, web_lines)) == expected


def test_empty_logs_give_empty_alert_frame():
    a = detector.analyze(pd.DataFrame(columns=parser.COLUMNS))
    assert a.empty and list(a.columns) == detector.ALERT_COLUMNS


def test_one_burst_gives_one_alert_not_many():
    a = run(failed(40, gap=3))
    assert len(a[a.rule_id == "R1"]) == 1 and int(a[a.rule_id == "R1"].event_count.iloc[0]) == 40


def test_two_separate_bursts_give_two_alerts():
    first = failed(6)
    later = [ssh(3000 + i * 2, "Failed password for root from 9.9.9.9 port 22 ssh2") for i in range(6)]
    assert len(run(first + later).query("rule_id == 'R1'")) == 2


def test_alerts_carry_mitre_metadata():
    a = run(failed(6))
    assert a.iloc[0].mitre_id == "T1110" and a.iloc[0].tactic == "Credential Access" and a.iloc[0].engine == "rules"


def test_find_bursts_window_edges():
    logs, _ = parser.parse_logs("\n".join(failed(6, gap=60)), "", 2026)   # one failure per minute, 0..5 min
    assert len(detector.find_bursts(logs, 5, 5)) == 1      # window is inclusive: 6 events span exactly 5 minutes
    assert len(detector.find_bursts(logs, 6, 5)) == 1
    assert detector.find_bursts(logs, 7, 5) == []          # only 6 events exist
    assert detector.find_bursts(logs, 6, 4) == []          # a 4 minute window holds at most 5 of them


def test_sample_logs_flag_only_attackers(sample_logs):
    logs, _ = sample_logs
    gt = set(json.load(open(os.path.join(ROOT, "sample_data", "ground_truth.json")))["attacker_ips"])
    flagged = set(detector.analyze(logs).ip)
    assert flagged <= gt, f"false positives: {flagged - gt}"          # no normal client is flagged by rules
    assert len(flagged) == 6                                          # all rule-detectable attackers found
