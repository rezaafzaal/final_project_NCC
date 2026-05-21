import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime
from app.models.log_event import LogEvent
from app.services.email_service import send_alert_email


def _critical_event():
    return LogEvent(
        timestamp=datetime.now(),
        source="auth",
        raw="test",
        ip="1.2.3.4",
        user="admin",
        action="failed_login",
        status="FAILED",
        severity="CRITICAL",
        rule_triggered="ssh_brute_force",
    )


# ---- missing env vars ----

def test_missing_all_env_vars_returns_early(capsys):
    event = _critical_event()
    with patch.dict("os.environ", {}, clear=True):
        send_alert_email(event)
    out = capsys.readouterr().out
    assert "Missing environment variables" in out


def test_missing_email_pass_returns_early(capsys):
    event = _critical_event()
    env = {"EMAIL_USER": "u@example.com", "ALERT_RECEIVER": "r@example.com"}
    with patch.dict("os.environ", env, clear=True):
        send_alert_email(event)
    out = capsys.readouterr().out
    assert "Missing environment variables" in out


def test_missing_alert_receiver_returns_early(capsys):
    event = _critical_event()
    env = {"EMAIL_USER": "u@example.com", "EMAIL_PASS": "pass"}
    with patch.dict("os.environ", env, clear=True):
        send_alert_email(event)
    out = capsys.readouterr().out
    assert "Missing environment variables" in out


# ---- successful send ----

def test_send_success(capsys):
    event = _critical_event()
    env = {
        "EMAIL_USER": "u@example.com",
        "EMAIL_PASS": "pass",
        "ALERT_RECEIVER": "r@example.com",
    }
    mock_smtp = MagicMock()
    mock_smtp.__enter__ = MagicMock(return_value=mock_smtp)
    mock_smtp.__exit__ = MagicMock(return_value=False)

    with patch.dict("os.environ", env, clear=True):
        with patch("smtplib.SMTP", return_value=mock_smtp):
            send_alert_email(event)

    out = capsys.readouterr().out
    assert "Alert sent successfully" in out


def test_send_calls_starttls_and_login(capsys):
    event = _critical_event()
    env = {
        "EMAIL_USER": "u@example.com",
        "EMAIL_PASS": "pass",
        "ALERT_RECEIVER": "r@example.com",
    }
    mock_smtp = MagicMock()
    mock_smtp.__enter__ = MagicMock(return_value=mock_smtp)
    mock_smtp.__exit__ = MagicMock(return_value=False)

    with patch.dict("os.environ", env, clear=True):
        with patch("smtplib.SMTP", return_value=mock_smtp):
            send_alert_email(event)

    mock_smtp.starttls.assert_called_once()
    mock_smtp.login.assert_called_once_with("u@example.com", "pass")


# ---- smtp failure ----

def test_smtp_exception_handled(capsys):
    event = _critical_event()
    env = {
        "EMAIL_USER": "u@example.com",
        "EMAIL_PASS": "pass",
        "ALERT_RECEIVER": "r@example.com",
    }
    mock_smtp = MagicMock()
    mock_smtp.__enter__ = MagicMock(side_effect=Exception("connection refused"))
    mock_smtp.__exit__ = MagicMock(return_value=False)

    with patch.dict("os.environ", env, clear=True):
        with patch("smtplib.SMTP", return_value=mock_smtp):
            send_alert_email(event)

    out = capsys.readouterr().out
    assert "Failed" in out
