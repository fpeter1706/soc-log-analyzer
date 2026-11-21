import copy

import pytest
from soc import rules as R


def test_default_rules_load():
    rules = R.load_rules()
    assert [r["id"] for r in rules] == ["R1", "R2", "R3", "R4", "R5"]
    assert all(r["mitre"].get("id") for r in rules)


def _base():
    return {"rules": [{"id": "X1", "name": "t", "type": "threshold", "source": "ssh", "severity": "High",
                       "threshold": 3, "window_minutes": 5}]}


def test_valid_minimal_rule():
    assert R.validate_rules(_base())[0]["playbook"] == []


@pytest.mark.parametrize("mutate,msg", [
    (lambda d: d["rules"][0].pop("name"), "missing"),
    (lambda d: d["rules"][0].update(type="magic"), "unknown type"),
    (lambda d: d["rules"][0].update(severity="Scary"), "severity"),
    (lambda d: d["rules"][0].update(source="dns"), "source"),
    (lambda d: d["rules"][0].update(threshold=0), "positive integer"),
    (lambda d: d["rules"][0].update(threshold=True), "positive integer"),
    (lambda d: d["rules"][0].update(window_minutes="5"), "positive integer"),
    (lambda d: d["rules"].append(copy.deepcopy(d["rules"][0])), "duplicate"),
])
def test_invalid_rules_rejected(mutate, msg):
    d = _base()
    mutate(d)
    with pytest.raises(R.RuleError, match=msg):
        R.validate_rules(d)


def test_bad_regex_and_missing_distinct_field():
    d = _base()
    d["rules"][0].update(type="pattern", patterns={"x": "(unclosed"})
    with pytest.raises(R.RuleError, match="bad regex"):
        R.validate_rules(d)
    d = _base()
    d["rules"][0]["type"] = "distinct"
    with pytest.raises(R.RuleError, match="distinct_field"):
        R.validate_rules(d)


@pytest.mark.parametrize("data", [None, {}, {"rules": []}, {"rules": "x"}, {"rules": ["x"]}])
def test_structurally_wrong_files_rejected(data):
    with pytest.raises(R.RuleError):
        R.validate_rules(data)


def test_invalid_yaml_file(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("rules: [unclosed")
    with pytest.raises(R.RuleError, match="invalid YAML"):
        R.load_rules(p)


def test_overrides_do_not_mutate_original():
    rules = R.load_rules()
    new = R.with_overrides(rules, {"R1": {"threshold": 9}})
    assert new[0]["threshold"] == 9 and rules[0]["threshold"] == 5


def test_technique_url():
    assert R.technique_url("T1110") == "https://attack.mitre.org/techniques/T1110/"
    assert R.technique_url("T1595.003").endswith("T1595/003/")
    assert R.technique_url("") == ""
