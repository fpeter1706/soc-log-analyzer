"""Load and validate detection rules from YAML."""
from __future__ import annotations

import copy
import re
from pathlib import Path

import yaml

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "rules" / "default_rules.yaml"
TYPES = {"threshold", "distinct", "success_after_failures", "pattern"}
SEVERITIES = ("Critical", "High", "Medium", "Low")


class RuleError(ValueError):
    """Raised when a rules file is malformed."""


def _need(rule: dict, key: str, rid: str):
    if key not in rule:
        raise RuleError(f"rule {rid}: missing required field '{key}'")
    return rule[key]


def validate_rules(data) -> list:
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list) or not data["rules"]:
        raise RuleError("rules file must contain a non-empty 'rules' list")
    seen, out = set(), []
    for r in data["rules"]:
        if not isinstance(r, dict):
            raise RuleError("each rule must be a mapping")
        rid = str(_need(r, "id", "?"))
        if rid in seen:
            raise RuleError(f"duplicate rule id {rid}")
        seen.add(rid)
        for key in ("name", "type", "severity", "source"):
            _need(r, key, rid)
        if r["type"] not in TYPES:
            raise RuleError(f"rule {rid}: unknown type '{r['type']}' (allowed: {sorted(TYPES)})")
        if r["severity"] not in SEVERITIES:
            raise RuleError(f"rule {rid}: severity must be one of {SEVERITIES}")
        if r["source"] not in ("ssh", "web"):
            raise RuleError(f"rule {rid}: source must be 'ssh' or 'web'")
        if r["type"] != "pattern":
            for key in ("threshold", "window_minutes"):
                v = _need(r, key, rid)
                if not isinstance(v, int) or isinstance(v, bool) or v < 1:
                    raise RuleError(f"rule {rid}: '{key}' must be a positive integer")
        if r["type"] == "distinct":
            _need(r, "distinct_field", rid)
        if r["type"] == "pattern":
            pats = _need(r, "patterns", rid)
            if not isinstance(pats, dict) or not pats:
                raise RuleError(f"rule {rid}: 'patterns' must be a non-empty mapping")
            for label, rx in pats.items():
                try:
                    re.compile(rx)
                except re.error as exc:
                    raise RuleError(f"rule {rid}: bad regex for '{label}': {exc}") from exc
        r.setdefault("mitre", {})
        r.setdefault("playbook", [])
        out.append(r)
    return out


def load_rules(path=DEFAULT_PATH) -> list:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise RuleError(f"invalid YAML in {path}: {exc}") from exc
    return validate_rules(data)


def with_overrides(rules: list, overrides: dict) -> list:
    """Copy of rules with e.g. {'R1': {'threshold': 8}} applied (used by dashboard sliders)."""
    out = copy.deepcopy(rules)
    for r in out:
        r.update(overrides.get(r["id"], {}))
    return out


def technique_url(technique_id: str) -> str:
    if not technique_id:
        return ""
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"
