import pytest
from app.core.log_parser import parse_auth_line, parse_access_line, parse_line

# --- sample auth log lines ---
FAILED_LOGIN = "May 21 10:23:45 server sshd[1234]: Failed password for root from 1.2.3.4 port 22"
FAILED_INVALID = "May 21 10:23:45 server sshd[1234]: Failed password for invalid user nobody from 5.6.7.8 port 22"
SUCCESS_LOGIN = "May 21 10:23:45 server sshd[1234]: Accepted password for admin from 1.2.3.4 port 22"
INVALID_USER = "May 21 10:23:45 server sshd[1234]: Invalid user testuser from 5.6.7.8"
OTHER_AUTH = "May 21 10:23:45 server sshd[1234]: Server listening on 0.0.0.0 port 22"

# --- sample access log lines ---
ACCESS_200 = '1.2.3.4 - - [21/May/2026:10:23:45 +0000] "GET /index.html HTTP/1.1" 200 512'
ACCESS_301 = '1.2.3.4 - - [21/May/2026:10:23:45 +0000] "GET /old HTTP/1.1" 301 0'
ACCESS_400 = '1.2.3.4 - - [21/May/2026:10:23:45 +0000] "GET /bad HTTP/1.1" 400 50'
ACCESS_404 = '1.2.3.4 - - [21/May/2026:10:23:45 +0000] "GET /missing HTTP/1.1" 404 0'
ACCESS_500 = '1.2.3.4 - - [21/May/2026:10:23:45 +0000] "POST /api HTTP/1.1" 500 100'


# ---- auth tests ----

def test_parse_auth_failed_login():
    event = parse_auth_line(FAILED_LOGIN)
    assert event is not None
    assert event.source == "auth"
    assert event.action == "failed_login"
    assert event.status == "FAILED"
    assert event.severity == "WARNING"
    assert event.user == "root"
    assert event.ip == "1.2.3.4"


def test_parse_auth_failed_login_invalid_user_prefix():
    event = parse_auth_line(FAILED_INVALID)
    assert event is not None
    assert event.action == "failed_login"
    assert event.status == "FAILED"
    assert event.user == "nobody"
    assert event.ip == "5.6.7.8"


def test_parse_auth_success_login():
    event = parse_auth_line(SUCCESS_LOGIN)
    assert event is not None
    assert event.action == "login"
    assert event.status == "SUCCESS"
    assert event.severity == "INFO"
    assert event.user == "admin"
    assert event.ip == "1.2.3.4"


def test_parse_auth_invalid_user():
    event = parse_auth_line(INVALID_USER)
    assert event is not None
    assert event.action == "invalid_user"
    assert event.status == "FAILED"
    assert event.severity == "WARNING"
    assert event.user == "testuser"
    assert event.ip == "5.6.7.8"


def test_parse_auth_other_message():
    event = parse_auth_line(OTHER_AUTH)
    assert event is not None
    assert event.action == "other"
    assert event.severity == "INFO"
    assert event.source == "auth"


def test_parse_auth_invalid_format_returns_none():
    assert parse_auth_line("this is not a valid log line") is None
    assert parse_auth_line("") is None


def test_parse_auth_timestamp_in_event():
    event = parse_auth_line(FAILED_LOGIN)
    assert event is not None
    assert event.timestamp is not None


def test_parse_auth_raw_preserved():
    event = parse_auth_line(FAILED_LOGIN)
    assert event is not None
    assert event.raw == FAILED_LOGIN.strip()


# ---- access tests ----

def test_parse_access_200_is_info():
    event = parse_access_line(ACCESS_200)
    assert event is not None
    assert event.source == "access"
    assert event.severity == "INFO"
    assert event.ip == "1.2.3.4"
    assert event.action == "GET"
    assert event.status == "200"


def test_parse_access_301_is_info():
    event = parse_access_line(ACCESS_301)
    assert event is not None
    assert event.severity == "INFO"
    assert event.status == "301"


def test_parse_access_400_is_warning():
    event = parse_access_line(ACCESS_400)
    assert event is not None
    assert event.severity == "WARNING"
    assert event.status == "400"


def test_parse_access_404_is_warning():
    event = parse_access_line(ACCESS_404)
    assert event is not None
    assert event.severity == "WARNING"
    assert event.status == "404"


def test_parse_access_500_is_critical():
    event = parse_access_line(ACCESS_500)
    assert event is not None
    assert event.severity == "CRITICAL"
    assert event.status == "500"
    assert event.action == "POST"


def test_parse_access_extra_contains_path():
    event = parse_access_line(ACCESS_200)
    assert event is not None
    assert "path" in event.extra
    assert event.extra["path"] == "/index.html"


def test_parse_access_invalid_format_returns_none():
    assert parse_access_line("not an access log") is None
    assert parse_access_line("") is None


# ---- parse_line dispatcher ----

def test_parse_line_auth():
    event = parse_line(FAILED_LOGIN, "auth")
    assert event is not None
    assert event.source == "auth"


def test_parse_line_access():
    event = parse_line(ACCESS_200, "access")
    assert event is not None
    assert event.source == "access"


def test_parse_line_unknown_source_returns_none():
    assert parse_line("anything", "unknown") is None
    assert parse_line("anything", "") is None
