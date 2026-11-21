"""Unsupervised anomaly detection (Isolation Forest) on per-IP behaviour.

Rules catch known patterns; this catches unusual behaviour that has no rule, for
example a very fast burst of perfectly valid requests (scraping or flooding)."""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from .detector import ALERT_COLUMNS

FEATURES = ["events", "fail_ratio", "distinct_users", "distinct_paths", "error_ratio", "events_per_min"]
LABELS = {"events": "event volume", "fail_ratio": "share of failed logins", "distinct_users": "number of usernames tried",
          "distinct_paths": "number of different paths", "error_ratio": "share of error responses",
          "events_per_min": "request rate"}


def build_features(logs: pd.DataFrame, bucket_minutes: int = 5) -> pd.DataFrame:
    """One row per (IP, time bucket) with behavioural features."""
    df = logs.copy()
    df["bucket"] = df["ts"].dt.floor(f"{bucket_minutes}min")
    df["is_fail"] = (df["event"] == "failed_login").astype(int)
    df["is_err"] = (df["status"].fillna(0) >= 400).astype(int)
    feat = (df.groupby(["ip", "bucket"])
              .agg(events=("ts", "size"), fails=("is_fail", "sum"), errs=("is_err", "sum"),
                   distinct_users=("username", "nunique"), distinct_paths=("path", "nunique"),
                   first_seen=("ts", "min"), last_seen=("ts", "max"))
              .reset_index())
    feat["fail_ratio"] = feat["fails"] / feat["events"]
    feat["error_ratio"] = feat["errs"] / feat["events"]
    feat["events_per_min"] = feat["events"] / bucket_minutes
    return feat


def detect_anomalies(logs: pd.DataFrame, contamination: float = 0.01, min_rows: int = 100,
                     random_state: int = 42) -> pd.DataFrame:
    """Return alerts (engine='ml') for the most unusual (IP, time bucket) rows.
    Returns an empty frame if there is too little data for the model to be meaningful."""
    empty = pd.DataFrame(columns=ALERT_COLUMNS)
    if logs.empty:
        return empty
    feat = build_features(logs)
    if len(feat) < min_rows:
        return empty
    X = np.log1p(feat[FEATURES].to_numpy(dtype=float))
    model = IsolationForest(n_estimators=200, contamination=contamination, random_state=random_state)
    flagged = model.fit_predict(X) == -1
    score = -model.score_samples(X)
    med = np.median(X, axis=0)
    mad = np.median(np.abs(X - med), axis=0) + 1e-6  # robust spread; explains *why* a row is odd

    rows = []
    for idx in np.flatnonzero(flagged):
        r = feat.iloc[idx]
        z = (X[idx] - med) / mad
        top = FEATURES[int(np.argmax(z))]
        rows.append(dict(rule_id="ML1", rule_name="Anomalous behaviour (Isolation Forest)", severity="Medium",
                         ip=r["ip"], first_seen=r["first_seen"], last_seen=r["last_seen"], event_count=int(r["events"]),
                         details=f"Unusual {LABELS[top]}: {int(r['events'])} events in 5 minutes, anomaly score {score[idx]:.2f}",
                         mitre_id="", mitre_name="", tactic="", engine="ml"))
    out = pd.DataFrame(rows, columns=ALERT_COLUMNS)
    if len(out):  # merge consecutive buckets of the same IP into one alert
        out = (out.groupby("ip", as_index=False)
                  .agg(rule_id=("rule_id", "first"), rule_name=("rule_name", "first"), severity=("severity", "first"),
                       first_seen=("first_seen", "min"), last_seen=("last_seen", "max"), event_count=("event_count", "sum"),
                       details=("details", "first"), mitre_id=("mitre_id", "first"), mitre_name=("mitre_name", "first"),
                       tactic=("tactic", "first")))
        out["engine"] = "ml"  # 'engine' is a reserved keyword of DataFrame.agg, so it is set afterwards
        # ML alerts are lower precision than rules, so only large volumes are escalated to Medium
        out["severity"] = np.where(out["event_count"] >= 100, "Medium", "Low")
        out = out[ALERT_COLUMNS]
    return out
