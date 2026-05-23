import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime
from app.models.log_event import LogEvent
from app.services.discord_webhook import send_alert_dc


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


def test_missing_webhook_returns_early(capsys):
    event = _critical_event()

    with patch.dict("os.environ", {}, clear=True):
        send_alert_dc(event)

    out = capsys.readouterr().out
    assert "[DISCORD] Missing webhook URL" in out

# success post

@patch("requests.post")
def test_send_success(mock_post, capsys):
    event = _critical_event()

    mock_post.return_value.status_code = 204

    env = {"DISCORD_WEBHOOK": "https://discord.com/api/webhook/test"}

    with patch.dict("os.environ", env, clear=True):
        send_alert_dc(event)

    out = capsys.readouterr().out
    assert "[DISCORD] Alert sent successfully" in out


# request

@patch("requests.post")
def test_webhook_called(mock_post):
    event = _critical_event()

    mock_post.return_value.status_code = 204

    env = {"DISCORD_WEBHOOK": "https://discord.com/api/webhook/test"}

    with patch.dict("os.environ", env, clear=True):
        send_alert_dc(event)

    mock_post.assert_called_once()


# fail

@patch("requests.post")
def test_webhook_failed_response(mock_post, capsys):
    event = _critical_event()

    mock_post.return_value.status_code = 400
    mock_post.return_value.text = "Bad Request"

    env = {"DISCORD_WEBHOOK": "https://discord.com/api/webhook/test"}

    with patch.dict("os.environ", env, clear=True):
        send_alert_dc(event)

    out = capsys.readouterr().out
    assert "[DISCORD] Failed" in out


# exception

@patch("requests.post")
def test_webhook_exception(mock_post, capsys):
    event = _critical_event()

    mock_post.side_effect = Exception("connection error")

    env = {"DISCORD_WEBHOOK": "https://discord.com/api/webhook/test"}

    with patch.dict("os.environ", env, clear=True):
        send_alert_dc(event)

    out = capsys.readouterr().out
    assert "[DISCORD] Error" in out