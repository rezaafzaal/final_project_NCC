import asyncio
import pytest
from app.core.log_generator import (
    _random_auth_event, _random_access_event,
    _random_firewall_event, _random_syslog_event, _random_fim_event,
    generate_logs,
)
from app.models.log_event import LogEvent

VALID_ACTIONS_AUTH = {"failed_login", "login", "invalid_user"}
VALID_METHODS = {"GET", "POST", "PUT", "DELETE"}
VALID_SEVERITIES = {"INFO", "WARNING", "CRITICAL"}
VALID_SOURCES = {"auth", "access", "firewall", "syslog", "fim"}


# ---- auth event ----

def test_random_auth_event_returns_log_event():
    event = _random_auth_event()
    assert isinstance(event, LogEvent)


def test_random_auth_event_source():
    for _ in range(10):
        assert _random_auth_event().source == "auth"


def test_random_auth_event_has_ip_and_user():
    event = _random_auth_event()
    assert event.ip is not None
    assert event.user is not None


def test_random_auth_event_action_valid():
    for _ in range(20):
        assert _random_auth_event().action in VALID_ACTIONS_AUTH


def test_random_auth_event_status_consistent():
    for _ in range(30):
        event = _random_auth_event()
        if event.action == "login":
            assert event.status == "SUCCESS"
        else:
            assert event.status == "FAILED"


def test_random_auth_event_severity_valid():
    for _ in range(20):
        assert _random_auth_event().severity in {"INFO", "WARNING"}


def test_random_auth_event_raw_not_empty():
    event = _random_auth_event()
    assert len(event.raw) > 0


# ---- access event ----

def test_random_access_event_returns_log_event():
    event = _random_access_event()
    assert isinstance(event, LogEvent)


def test_random_access_event_source():
    for _ in range(10):
        assert _random_access_event().source == "access"


def test_random_access_event_has_ip():
    event = _random_access_event()
    assert event.ip is not None


def test_random_access_event_severity_valid():
    for _ in range(50):
        event = _random_access_event()
        assert event.severity in VALID_SEVERITIES


def test_random_access_event_extra_has_path_and_size():
    event = _random_access_event()
    assert "path" in event.extra
    assert "size" in event.extra


def test_random_access_event_raw_not_empty():
    event = _random_access_event()
    assert len(event.raw) > 0


def test_random_access_event_action_valid():
    valid_actions = VALID_METHODS | {"sql_injection", "xss_attempt", "web_shell"}
    for _ in range(50):
        assert _random_access_event().action in valid_actions


# ---- firewall event ----

def test_random_firewall_event_returns_log_event():
    event = _random_firewall_event()
    assert isinstance(event, LogEvent)


def test_random_firewall_event_source():
    for _ in range(10):
        assert _random_firewall_event().source == "firewall"


def test_random_firewall_event_has_ip():
    event = _random_firewall_event()
    assert event.ip is not None


def test_random_firewall_event_action_valid():
    for _ in range(20):
        assert _random_firewall_event().action in {"DROP", "ACCEPT"}


def test_random_firewall_event_has_extra_fields():
    event = _random_firewall_event()
    assert "dst" in event.extra
    assert "proto" in event.extra
    assert "dst_port" in event.extra
    assert "direction" in event.extra


def test_random_firewall_event_direction_valid():
    for _ in range(20):
        event = _random_firewall_event()
        assert event.extra["direction"] in {"inbound", "outbound"}


def test_random_firewall_event_severity_matches_action():
    for _ in range(30):
        event = _random_firewall_event()
        if event.action == "DROP":
            assert event.severity == "WARNING"
        else:
            assert event.severity == "INFO"


def test_random_firewall_event_raw_not_empty():
    event = _random_firewall_event()
    assert len(event.raw) > 0
    assert "kernel:" in event.raw


# ---- syslog event ----

def test_random_syslog_event_returns_log_event():
    event = _random_syslog_event()
    assert isinstance(event, LogEvent)


def test_random_syslog_event_source():
    for _ in range(10):
        assert _random_syslog_event().source == "syslog"


def test_random_syslog_event_action_valid():
    valid_actions = {
        "sudo_command", "sudo_failed", "service_stopped",
        "service_started", "user_added", "syslog_other",
    }
    for _ in range(50):
        assert _random_syslog_event().action in valid_actions


def test_random_syslog_event_raw_not_empty():
    event = _random_syslog_event()
    assert len(event.raw) > 0


def test_random_syslog_event_has_extra():
    event = _random_syslog_event()
    assert "program" in event.extra
    assert "hostname" in event.extra


def test_random_syslog_sudo_has_command():
    for _ in range(100):
        event = _random_syslog_event()
        if event.action == "sudo_command":
            assert "command" in event.extra
            assert "target_user" in event.extra
            assert event.user is not None
            break


# ---- fim event ----

def test_random_fim_event_returns_log_event():
    event = _random_fim_event()
    assert isinstance(event, LogEvent)


def test_random_fim_event_source():
    for _ in range(10):
        assert _random_fim_event().source == "fim"


def test_random_fim_event_action_valid():
    valid_actions = {"modified", "created", "deleted", "attributes_changed"}
    for _ in range(30):
        assert _random_fim_event().action in valid_actions


def test_random_fim_event_has_extra_fields():
    event = _random_fim_event()
    assert "path" in event.extra
    assert "md5" in event.extra
    assert "sha256" in event.extra
    assert "uid" in event.extra


def test_random_fim_event_severity_matches_action():
    for _ in range(50):
        event = _random_fim_event()
        if event.action in ("modified", "deleted"):
            assert event.severity == "WARNING"
        else:
            assert event.severity == "INFO"


def test_random_fim_event_raw_not_empty():
    event = _random_fim_event()
    assert len(event.raw) > 0
    assert "fim:" in event.raw


# ---- generate_logs ----

@pytest.mark.asyncio
async def test_generate_logs_puts_events_in_queue():
    queue = asyncio.Queue()
    task = asyncio.create_task(generate_logs(queue, interval=0.01))
    await asyncio.sleep(0.08)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    assert not queue.empty()


@pytest.mark.asyncio
async def test_generate_logs_events_are_log_events():
    queue = asyncio.Queue()
    task = asyncio.create_task(generate_logs(queue, interval=0.01))
    await asyncio.sleep(0.05)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    while not queue.empty():
        event = queue.get_nowait()
        assert isinstance(event, LogEvent)
        assert event.source in VALID_SOURCES


@pytest.mark.asyncio
async def test_generate_logs_produces_multiple_sources():
    """Verify that the generator can produce events from different sources."""
    queue = asyncio.Queue()
    task = asyncio.create_task(generate_logs(queue, interval=0.01))
    await asyncio.sleep(0.3)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    sources_seen = set()
    while not queue.empty():
        event = queue.get_nowait()
        sources_seen.add(event.source)

    # With enough events, we should see at least 2 different sources
    assert len(sources_seen) >= 2
