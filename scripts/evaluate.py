"""Evaluate detection quality against the ground truth of the synthetic dataset (IP level)."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from soc import anomaly, detector, parser  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sample_data")


def prf(flagged: set, truth: set):
    tp = len(flagged & truth)
    p = tp / len(flagged) if flagged else 0.0
    r = tp / len(truth) if truth else 0.0
    return tp, p, r, (2 * p * r / (p + r) if p + r else 0.0)


def main():
    logs, _ = parser.parse_files(os.path.join(ROOT, "auth.log"), os.path.join(ROOT, "access.log"), 2026)
    truth = set(json.load(open(os.path.join(ROOT, "ground_truth.json")))["attacker_ips"])
    rules_ips = set(detector.analyze(logs).ip)
    ml_ips = set(anomaly.detect_anomalies(logs).ip)
    print(f"Ground truth: {len(truth)} attacker IPs, {logs['ip'].nunique()} IPs in total\n")
    print("| Detector | IPs flagged | True positives | Precision | Recall | F1 |\n|---|---|---|---|---|---|")
    for name, ips in (("Rules only", rules_ips), ("ML only", ml_ips), ("Rules + ML", rules_ips | ml_ips)):
        tp, p, r, f = prf(ips, truth)
        print(f"| {name} | {len(ips)} | {tp} | {p:.2f} | {r:.2f} | {f:.2f} |")
    print("\nMissed by rules:", sorted(truth - rules_ips) or "none")
    print("False positives of ML:", sorted(ml_ips - truth) or "none")


if __name__ == "__main__":
    main()
