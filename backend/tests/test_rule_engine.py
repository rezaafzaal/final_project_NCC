import json
import pytest
from datetime import datetime
from app.core.rule_engine import RuleEngine, load_rules
from app.models.log_event import LogEvent

RULES = {
    "rules": [
        {
            "rule_id": 5711,
            "name": "invalid_user_attempt",
            "severity": "WARNING",
            "conditions": {
                "source": "auth",
                "action": "invalid_user",
            },
        },
        {
            "rule_id": 31100,
            "name": "http_server_error",
            "severity": "CRITICAL",
            "conditions": {
                "source": "access",
                "status": "500",
            },
        },
        {
            "rule_id": 5710,
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
            "rule_id": 31101,
            "name": "http_not_found_scan",
            "severity": "WARNING",
            "conditions": {
                "source": "access",
                "status": "404",
                "rate": {"threshold": 3, "window_seconds": 30},
            },
        },
        {
            "rule_id": 5712,
            "name": "root_login_success",
            "severity": "WARNING",
            "conditions": {
                "source": "auth",
                "action": "login",
                "user": "root",
            },
        },
        {
            "rule_id": 31103,
            "name": "sql_injection_attempt",
            "severity": "CRITICAL",
            "conditions": {
                "source": "access",
                "action": "sql_injection",
            },
        },
        {
            "rule_id": 4100,
            "name": "firewall_drop_flood",
            "severity": "CRITICAL",
            "conditions": {
                "source": "firewall",
                "action": "DROP",
                "rate": {"threshold": 5, "window_seconds": 30},
            },
        },
        {
            "rule_id": 4102,
            "name": "firewall_outbound_unusual_port",
            "severity": "WARNING",
            "conditions": {
                "source": "firewall",
                "action": "DROP",
                "direction": "outbound",
            },
        },
        {
            "rule_id": 550,
            "name": "fim_critical_file_modified",
            "severity": "CRITICAL",
            "conditions": {
                "source": "fim",
                "action": "modified",
                "path_match": ["/etc/passwd", "/etc/shadow", "/etc/sudoers"],
            },
        },
        {
            "rule_id": 551,
            "name": "fim_file_deleted",
            "severity": "WARNING",
            "conditions": {
                "source": "fim",
                "action": "deleted",
            },
        },
        {
            "rule_id": 552,
            "name": "fim_binary_modified",
            "severity": "CRITICAL",
            "conditions": {
                "source": "fim",
                "action": "modified",
                "path_match": ["/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/"],
            },
        },
        {
            "rule_id": 5500,
            "name": "privilege_escalation_sudo",
            "severity": "INFO",
            "conditions": {
                "source": "syslog",
                "action": "sudo_command",
            },
        },
        {
            "rule_id": 5501,
            "name": "sudo_failed",
            "severity": "WARNING",
            "conditions": {
                "source": "syslog",
                "action": "sudo_failed",
            },
        },
        {
            "rule_id": 5503,
            "name": "user_added",
            "severity": "WARNING",
            "conditions": {
                "source": "syslog",
                "action": "user_added",
            },
        },
        {
            "rule_id": 5720,
            "name": "ssh_login_outside_hours",
            "severity": "WARNING",
            "conditions": {
                "source": "auth",
                "action": "login",
                "time_range": {"start_hour": 0, "end_hour": 6},
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
    assert len(rules) == len(RULES["rules"])


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
    # login action matches root_login_success if user is root, but user is None here
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


# ---- user condition ----

def test_root_login_triggers_rule(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", _write_rules(tmp_path))
    engine = RuleEngine()
    event = _event(source="auth", action="login", user="root")
    result = engine.evaluate(event)
    assert result.rule_triggered == "root_login_success"
    assert result.severity == "WARNING"


def test_non_root_login_no_root_trigger(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", _write_rules(tmp_path))
    engine = RuleEngine()
    event = _event(source="auth", action="login", user="ubuntu")
    result = engine.evaluate(event)
    # ubuntu login should NOT trigger root_login_success
    assert result.rule_triggered is None or result.rule_triggered != "root_login_success"


# ---- SQL injection rule ----

def test_sql_injection_triggers(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", _write_rules(tmp_path))
    engine = RuleEngine()
    event = _event(source="access", action="sql_injection")
    result = engine.evaluate(event)
    assert result.rule_triggered == "sql_injection_attempt"
    assert result.severity == "CRITICAL"


# ---- firewall rules ----

def test_firewall_drop_flood_triggers(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", _write_rules(tmp_path))
    engine = RuleEngine()
    event = _event(source="firewall", action="DROP", ip="10.10.10.10")
    result = None
    for _ in range(5):
        result = engine.evaluate(event)
    assert result.rule_triggered == "firewall_drop_flood"
    assert result.severity == "CRITICAL"


def test_firewall_drop_single_no_flood_trigger(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", _write_rules(tmp_path))
    engine = RuleEngine()
    event = _event(source="firewall", action="DROP", ip="11.11.11.11")
    result = engine.evaluate(event)
    # Single drop should NOT trigger flood rule (but may trigger outbound if direction matches)
    assert result.rule_triggered != "firewall_drop_flood"


def test_firewall_outbound_drop_triggers(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", _write_rules(tmp_path))
    engine = RuleEngine()
    event = _event(
        source="firewall", action="DROP", ip="192.168.1.1",
        extra={"direction": "outbound", "dst_port": "4444"}
    )
    result = engine.evaluate(event)
    assert result.rule_triggered == "firewall_outbound_unusual_port"


def test_firewall_inbound_no_outbound_trigger(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", _write_rules(tmp_path))
    engine = RuleEngine()
    event = _event(
        source="firewall", action="DROP", ip="12.12.12.12",
        extra={"direction": "inbound"}
    )
    result = engine.evaluate(event)
    # Inbound should NOT match outbound rule
    assert result.rule_triggered != "firewall_outbound_unusual_port"


# ---- FIM rules ----

def test_fim_critical_file_modified_triggers(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", _write_rules(tmp_path))
    engine = RuleEngine()
    event = _event(
        source="fim", action="modified",
        extra={"path": "/etc/passwd"}
    )
    result = engine.evaluate(event)
    assert result.rule_triggered == "fim_critical_file_modified"
    assert result.severity == "CRITICAL"


def test_fim_shadow_modified_triggers(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", _write_rules(tmp_path))
    engine = RuleEngine()
    event = _event(
        source="fim", action="modified",
        extra={"path": "/etc/shadow"}
    )
    result = engine.evaluate(event)
    assert result.rule_triggered == "fim_critical_file_modified"


def test_fim_normal_file_no_critical_trigger(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", _write_rules(tmp_path))
    engine = RuleEngine()
    event = _event(
        source="fim", action="modified",
        extra={"path": "/tmp/test.txt"}
    )
    result = engine.evaluate(event)
    # /tmp/test.txt should NOT match critical file or binary paths
    assert result.rule_triggered is None or result.rule_triggered not in (
        "fim_critical_file_modified", "fim_binary_modified"
    )


def test_fim_binary_modified_triggers(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", _write_rules(tmp_path))
    engine = RuleEngine()
    event = _event(
        source="fim", action="modified",
        extra={"path": "/usr/bin/ssh"}
    )
    result = engine.evaluate(event)
    assert result.rule_triggered == "fim_binary_modified"
    assert result.severity == "CRITICAL"


def test_fim_file_deleted_triggers(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", _write_rules(tmp_path))
    engine = RuleEngine()
    event = _event(
        source="fim", action="deleted",
        extra={"path": "/var/log/auth.log"}
    )
    result = engine.evaluate(event)
    assert result.rule_triggered == "fim_file_deleted"
    assert result.severity == "WARNING"


# ---- syslog rules ----

def test_sudo_command_triggers(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", _write_rules(tmp_path))
    engine = RuleEngine()
    event = _event(source="syslog", action="sudo_command", user="ubuntu")
    result = engine.evaluate(event)
    assert result.rule_triggered == "privilege_escalation_sudo"


def test_sudo_failed_triggers(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", _write_rules(tmp_path))
    engine = RuleEngine()
    event = _event(source="syslog", action="sudo_failed", user="admin")
    result = engine.evaluate(event)
    assert result.rule_triggered == "sudo_failed"
    assert result.severity == "WARNING"


def test_user_added_triggers(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", _write_rules(tmp_path))
    engine = RuleEngine()
    event = _event(source="syslog", action="user_added", user="hacker")
    result = engine.evaluate(event)
    assert result.rule_triggered == "user_added"
    assert result.severity == "WARNING"


# ---- time_range condition ----

def test_login_during_off_hours_triggers(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", _write_rules(tmp_path))
    engine = RuleEngine()
    # 3 AM is within 0-6 range
    off_hours_ts = datetime(2026, 5, 23, 3, 0, 0)
    event = _event(
        source="auth", action="login", user="ubuntu",
        timestamp=off_hours_ts,
    )
    result = engine.evaluate(event)
    assert result.rule_triggered == "ssh_login_outside_hours"


def test_login_during_business_hours_no_trigger(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", _write_rules(tmp_path))
    engine = RuleEngine()
    # 10 AM is outside 0-6 range
    business_ts = datetime(2026, 5, 23, 10, 0, 0)
    event = _event(
        source="auth", action="login", user="ubuntu",
        timestamp=business_ts,
    )
    result = engine.evaluate(event)
    assert result.rule_triggered is None or result.rule_triggered != "ssh_login_outside_hours"


# ---- reload_rules ----

def test_reload_rules(tmp_path, monkeypatch):
    path = _write_rules(tmp_path)
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", path)
    engine = RuleEngine()
    assert len(engine.rules) == len(RULES["rules"])
    engine.reload_rules()
    assert len(engine.rules) == len(RULES["rules"])


def test_reload_rules_picks_up_changes(tmp_path, monkeypatch):
    path = _write_rules(tmp_path)
    monkeypatch.setattr("app.core.rule_engine.RULES_PATH", path)
    engine = RuleEngine()
    assert len(engine.rules) == len(RULES["rules"])

    new_rules = {"rules": [RULES["rules"][0]]}
    with open(path, "w") as f:
        json.dump(new_rules, f)

    engine.reload_rules()
    assert len(engine.rules) == 1
