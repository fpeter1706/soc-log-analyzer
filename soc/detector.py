"""Rule engine: executes the rules defined in YAML against parsed events."""
from __future__ import annotations

import re
from urllib.parse import unquote_plus

import numpy as np
import pandas as pd

from .rules import load_rules

ALERT_COLUMNS = ["rule_id", "rule_name", "severity", "ip", "first_seen", "last_seen", "event_count",
                 "details", "mitre_id", "mitre_name", "tactic", "engine"]


def find_bursts(df: pd.DataFrame, threshold: int, window_minutes: int, distinct_col: str | None = None) -> list:
    """Non-overlapping windows in which the event count (or number of distinct values of
    distinct_col) reaches the threshold. O(n log n): the window end is found by binary search."""
    if df.empty:
        return []
    df = df.sort_values("ts").reset_index(drop=True)
    ts = df["ts"].to_numpy(dtype="datetime64[ns]")
    ends = np.searchsorted(ts, ts + np.timedelta64(int(window_minutes) * 60, "s"), side="right")
    bursts, i, n = [], 0, len(df)
    while i < n:
        j = int(ends[i])
        if j - i >= threshold:
            chunk = df.iloc[i:j]
            metric = chunk[distinct_col].nunique() if distinct_col else len(chunk)
            if metric >= threshold:
                bursts.append(chunk)
                i = j
                continue
        i += 1
    return bursts


def normalize_path(path: str) -> str:
    """URL-decode twice so %252e%252e%252f style evasion is still seen."""
    return unquote_plus(unquote_plus(path or ""))


def _alert(rule: dict, ip, chunk: pd.DataFrame, details: str, mitre: dict | None = None) -> dict:
    m = mitre or rule.get("mitre", {})
    return dict(rule_id=rule["id"], rule_name=rule["name"], severity=rule["severity"], ip=ip,
                first_seen=chunk["ts"].min(), last_seen=chunk["ts"].max(), event_count=len(chunk), details=details,
                mitre_id=m.get("id", ""), mitre_name=m.get("name", ""), tactic=m.get("tactic", ""), engine="rules")


def _select(logs: pd.DataFrame, rule: dict) -> pd.DataFrame:
    df = logs[logs["source"] == rule["source"]]
    if "event" in rule:
        df = df[df["event"] == rule["event"]]
    if "status" in rule:
        df = df[df["status"] == rule["status"]]
    return df


def _run_threshold(logs, rule):
    out, w = [], rule["window_minutes"]
    for ip, grp in _select(logs, rule).groupby("ip"):
        for chunk in find_bursts(grp, rule["threshold"], w):
            out.append(_alert(rule, ip, chunk, f"{len(chunk)} matching events within {w} minutes"))
    return out


def _run_distinct(logs, rule):
    out, w, col = [], rule["window_minutes"], rule["distinct_field"]
    for ip, grp in _select(logs, rule).groupby("ip"):
        for chunk in find_bursts(grp, rule["threshold"], w, distinct_col=col):
            names = ", ".join(sorted(map(str, chunk[col].unique()))[:6])
            out.append(_alert(rule, ip, chunk, f"{chunk[col].nunique()} different values of {col} tried: {names}"))
    return out


def _run_success_after_failures(logs, rule):
    out, window = [], np.timedelta64(rule["window_minutes"] * 60, "s")
    ssh = logs[logs["source"] == rule["source"]]
    failed = {ip: g["ts"].to_numpy(dtype="datetime64[ns]") for ip, g in ssh[ssh["event"] == "failed_login"].groupby("ip")}
    for _, s in ssh[ssh["event"] == "successful_login"].iterrows():
        times = failed.get(s["ip"])
        if times is None:
            continue
        t = np.datetime64(s["ts"], "ns")
        prior = times[(times <= t) & (times >= t - window)]
        if len(prior) >= rule["threshold"]:
            chunk = pd.DataFrame({"ts": pd.to_datetime(list(prior) + [t])})
            out.append(_alert(rule, s["ip"], chunk, f"Login succeeded for '{s['username']}' after {len(prior)} failures"))
    return out


def _run_pattern(logs, rule):
    out = []
    web = logs[logs["source"] == rule["source"]].copy()
    if web.empty:
        return out
    web["_norm"] = web[rule.get("field", "path")].fillna("").map(normalize_path)
    for label, rx in rule["patterns"].items():
        compiled = re.compile(rx, re.I)
        hits = web[web["_norm"].map(lambda p: bool(compiled.search(p))).astype(bool)]
        for ip, grp in hits.groupby("ip"):
            out.append(_alert(rule, ip, grp, f"{label} pattern in request, e.g. {grp['path'].iloc[0][:80]}"))
    return out


HANDLERS = {"threshold": _run_threshold, "distinct": _run_distinct,
            "success_after_failures": _run_success_after_failures, "pattern": _run_pattern}


def analyze(logs: pd.DataFrame, rules: list | None = None) -> pd.DataFrame:
    rules = rules or load_rules()
    alerts: list = []
    if len(logs):
        for rule in rules:
            alerts.extend(HANDLERS[rule["type"]](logs, rule))
    out = pd.DataFrame(alerts, columns=ALERT_COLUMNS)
    if len(out):
        out["first_seen"] = pd.to_datetime(out["first_seen"])
        out["last_seen"] = pd.to_datetime(out["last_seen"])
        out = out.sort_values("first_seen", kind="stable").reset_index(drop=True)
    return out
