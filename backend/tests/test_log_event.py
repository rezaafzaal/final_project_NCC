from datetime import datetime
from app.models.log_event import LogEvent


def test_log_event_defaults():
    ts = datetime(2026, 5, 21, 10, 0, 0)
    event = LogEvent(timestamp=ts, source="auth", raw="test line")
    assert event.source == "auth"
    assert event.raw == "test line"
    assert event.severity == "INFO"
    assert event.ip is None
    assert event.user is None
    assert event.action is None
    assert event.status is None
    assert event.rule_triggered is None
    assert event.extra == {}


def test_log_event_full_fields():
    ts = datetime(2026, 5, 21, 10, 0, 0)
    event = LogEvent(
        timestamp=ts,
        source="auth",
        raw="May 21 10:00:00 server sshd[1]: Failed password for root from 1.2.3.4",
        ip="1.2.3.4",
        user="root",
        action="failed_login",
        status="FAILED",
        severity="WARNING",
        rule_triggered="ssh_brute_force",
        extra={"port": "22"},
    )
    assert event.ip == "1.2.3.4"
    assert event.user == "root"
    assert event.severity == "WARNING"
    assert event.rule_triggered == "ssh_brute_force"


def test_to_dict_keys():
    ts = datetime(2026, 5, 21, 10, 0, 0)
    event = LogEvent(timestamp=ts, source="auth", raw="test")
    d = event.to_dict()
    for key in ("timestamp", "source", "raw", "ip", "user", "action", "status", "severity", "rule_triggered", "extra"):
        assert key in d


def test_to_dict_values():
    ts = datetime(2026, 5, 21, 10, 0, 0)
    event = LogEvent(
        timestamp=ts,
        source="access",
        raw="log line",
        ip="10.0.0.1",
        user="admin",
        action="GET",
        status="200",
        severity="INFO",
        rule_triggered=None,
        extra={"path": "/api"},
    )
    d = event.to_dict()
    assert d["source"] == "access"
    assert d["ip"] == "10.0.0.1"
    assert d["action"] == "GET"
    assert d["status"] == "200"
    assert d["severity"] == "INFO"
    assert d["rule_triggered"] is None
    assert d["extra"] == {"path": "/api"}
    assert d["timestamp"] == ts.isoformat()


def test_to_dict_extra_default():
    ts = datetime(2026, 5, 21, 10, 0, 0)
    event = LogEvent(timestamp=ts, source="auth", raw="test")
    assert event.to_dict()["extra"] == {}
