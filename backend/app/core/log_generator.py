import asyncio
import random
from datetime import datetime
from app.models.log_event import LogEvent

_IPS = ["192.168.1.10", "10.0.0.5", "172.16.0.3", "203.0.113.42", "198.51.100.7"]
_USERS = ["root", "admin", "ubuntu", "pi", "test", "guest"]
_PATHS = ["/", "/admin", "/login", "/api/data", "/.env", "/wp-admin", "/phpmyadmin"]
_METHODS = ["GET", "POST", "PUT", "DELETE"]

_AUTH_TEMPLATES = [
    ("failed_login",  "WARNING",  lambda ip, user: f"May {datetime.now().day:02d} {datetime.now().strftime('%H:%M:%S')} server sshd[{random.randint(1000,9999)}]: Failed password for {user} from {ip} port 22"),
    ("login",         "INFO",     lambda ip, user: f"May {datetime.now().day:02d} {datetime.now().strftime('%H:%M:%S')} server sshd[{random.randint(1000,9999)}]: Accepted password for {user} from {ip} port 22"),
    ("invalid_user",  "WARNING",  lambda ip, user: f"May {datetime.now().day:02d} {datetime.now().strftime('%H:%M:%S')} server sshd[{random.randint(1000,9999)}]: Invalid user {user} from {ip}"),
]


def _random_auth_event() -> LogEvent:
    action, severity, template = random.choices(
        _AUTH_TEMPLATES, weights=[60, 25, 15]
    )[0]
    ip = random.choice(_IPS)
    user = random.choice(_USERS)
    raw = template(ip, user)
    return LogEvent(
        timestamp=datetime.now(),
        source="auth",
        raw=raw,
        ip=ip,
        user=user,
        action=action,
        status="FAILED" if action != "login" else "SUCCESS",
        severity=severity,
    )


def _random_access_event() -> LogEvent:
    ip = random.choice(_IPS)
    method = random.choice(_METHODS)
    path = random.choice(_PATHS)
    status = random.choices([200, 301, 400, 403, 404, 500], weights=[50, 5, 5, 10, 20, 10])[0]
    size = random.randint(100, 5000)
    now = datetime.now()
    raw = f'{ip} - - [{now.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "{method} {path} HTTP/1.1" {status} {size}'

    severity = "INFO"
    if status >= 500:
        severity = "CRITICAL"
    elif status >= 400:
        severity = "WARNING"

    return LogEvent(
        timestamp=now,
        source="access",
        raw=raw,
        ip=ip,
        action=method,
        status=str(status),
        severity=severity,
        extra={"path": path, "size": str(size)},
    )


async def generate_logs(queue: asyncio.Queue, interval: float = 2.0):
    """Terus-menerus generate log event ke queue dengan interval tertentu."""
    while True:
        source = random.choice(["auth", "access"])
        event = _random_auth_event() if source == "auth" else _random_access_event()
        await queue.put(event)
        await asyncio.sleep(interval)
