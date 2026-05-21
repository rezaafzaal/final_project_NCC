import asyncio
import pytest
from app.core.log_generator import _random_auth_event, _random_access_event, generate_logs
from app.models.log_event import LogEvent

VALID_ACTIONS_AUTH = {"failed_login", "login", "invalid_user"}
VALID_METHODS = {"GET", "POST", "PUT", "DELETE"}
VALID_SEVERITIES = {"INFO", "WARNING", "CRITICAL"}


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


def test_random_access_event_method_valid():
    for _ in range(20):
        assert _random_access_event().action in VALID_METHODS


def test_random_access_event_has_ip():
    event = _random_access_event()
    assert event.ip is not None


def test_random_access_event_severity_matches_status():
    for _ in range(50):
        event = _random_access_event()
        code = int(event.status)
        if code >= 500:
            assert event.severity == "CRITICAL"
        elif code >= 400:
            assert event.severity == "WARNING"
        else:
            assert event.severity == "INFO"


def test_random_access_event_extra_has_path_and_size():
    event = _random_access_event()
    assert "path" in event.extra
    assert "size" in event.extra


def test_random_access_event_raw_not_empty():
    event = _random_access_event()
    assert len(event.raw) > 0


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
        assert event.source in ("auth", "access")
