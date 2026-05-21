import json
import pytest
from datetime import datetime
from app.core.rule_engine import RuleEngine, load_rules
from app.models.log_event import LogEvent

RULES = {
    "rules": [
        {
            "name": "invalid_user_attempt",
            "severity": "WARNING",
            "conditions": {
                "source": "auth",
                "action": "invalid_user",
            },
        },
        {
            "name": "http_server_error",
            "severity": "CRITICAL",
            "conditions": {
                "source": "access",
                "status": "500",
            },
        },
        {
            "name": "ssh_brute_force",
            "severity": "CRITICAL",
            "conditions": {
                "source": "auth",
                "action": "failed_login",
                "status": "FAILED",
                "rate": {"threshold": 3, "window_seconds": 60},
            },
        },
        {
            "name": "http_not_found_scan",
            "severity": "WARNING",
            "conditions": {
                "source": "access",
                "status": "404",
                "rate": {"threshold": 3, "window_seconds": 30},
            },
        },
    ]
}


def _write_rules(tmp_path, rules=None):
    f = tmp_path / "rules.json"
    f.write_text(json.dumps(rules or RULES))
    return str(f)


def _event(**kwargs):
    defaults = dict(timestamp=datetime.now(), source="auth", raw="test")
    defaults.update(kwargs)
    return LogEvent(**defaults)


# ---- load_rules ----

def test_load_rules_success(tmp_path, monkeypatch):
    path = _write_rules(tmp_path)
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", path)
    rules = load_rules()
    assert len(rules) == 4


def test_load_rules_file_not_found(monkeypatch):
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", "/nonexistent/rules.json")
    assert load_rules() == []


def test_load_rules_invalid_json(tmp_path, monkeypatch):
    f = tmp_path / "bad.json"
    f.write_text("not valid json")
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", str(f))
    assert load_rules() == []


# ---- simple condition matching ----

def test_evaluate_invalid_user_triggers_rule(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", _write_rules(tmp_path))
    engine = RuleEngine()
    event = _event(source="auth", action="invalid_user")
    result = engine.evaluate(event)
    assert result.rule_triggered == "invalid_user_attempt"
    assert result.severity == "WARNING"


def test_evaluate_http_500_triggers_rule(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", _write_rules(tmp_path))
    engine = RuleEngine()
    event = _event(source="access", status="500")
    result = engine.evaluate(event)
    assert result.rule_triggered == "http_server_error"
    assert result.severity == "CRITICAL"


def test_evaluate_no_match(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", _write_rules(tmp_path))
    engine = RuleEngine()
    event = _event(source="access", action="GET", status="200")
    result = engine.evaluate(event)
    assert result.rule_triggered is None


def test_evaluate_source_mismatch_no_trigger(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", _write_rules(tmp_path))
    engine = RuleEngine()
    # invalid_user rule requires source=auth, but we send access
    event = _event(source="access", action="invalid_user")
    result = engine.evaluate(event)
    assert result.rule_triggered is None


def test_evaluate_action_mismatch_no_trigger(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", _write_rules(tmp_path))
    engine = RuleEngine()
    event = _event(source="auth", action="login")
    result = engine.evaluate(event)
    assert result.rule_triggered is None


def test_evaluate_status_mismatch_no_trigger(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", _write_rules(tmp_path))
    engine = RuleEngine()
    event = _event(source="access", status="404")
    # 404 has a rate condition, single event won't trigger
    result = engine.evaluate(event)
    assert result.rule_triggered is None


# ---- rate-based rules ----

def test_brute_force_under_threshold_no_trigger(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", _write_rules(tmp_path))
    engine = RuleEngine()
    event = _event(source="auth", action="failed_login", status="FAILED", ip="1.1.1.1")
    # 2 attempts < threshold of 3
    engine.evaluate(event)
    result = engine.evaluate(event)
    assert result.rule_triggered is None


def test_brute_force_at_threshold_triggers(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", _write_rules(tmp_path))
    engine = RuleEngine()
    event = _event(source="auth", action="failed_login", status="FAILED", ip="2.2.2.2")
    result = None
    for _ in range(3):
        result = engine.evaluate(event)
    assert result.rule_triggered == "ssh_brute_force"
    assert result.severity == "CRITICAL"


def test_brute_force_different_ips_isolated(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", _write_rules(tmp_path))
    engine = RuleEngine()
    event_a = _event(source="auth", action="failed_login", status="FAILED", ip="3.3.3.3")
    event_b = _event(source="auth", action="failed_login", status="FAILED", ip="4.4.4.4")
    for _ in range(2):
        engine.evaluate(event_a)
    result = engine.evaluate(event_b)
    # ip=4.4.4.4 only has 1 attempt — should NOT trigger
    assert result.rule_triggered is None


def test_http_not_found_rate_triggers(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", _write_rules(tmp_path))
    engine = RuleEngine()
    event = _event(source="access", status="404", ip="5.5.5.5")
    result = None
    for _ in range(3):
        result = engine.evaluate(event)
    assert result.rule_triggered == "http_not_found_scan"


# ---- reload_rules ----

def test_reload_rules(tmp_path, monkeypatch):
    path = _write_rules(tmp_path)
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", path)
    engine = RuleEngine()
    assert len(engine.rules) == 4
    engine.reload_rules()
    assert len(engine.rules) == 4


def test_reload_rules_picks_up_changes(tmp_path, monkeypatch):
    path = _write_rules(tmp_path)
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", path)
    engine = RuleEngine()
    assert len(engine.rules) == 4

    new_rules = {"rules": [RULES["rules"][0]]}
    with open(path, "w") as f:
        json.dump(new_rules, f)

    engine.reload_rules()
    assert len(engine.rules) == 1
