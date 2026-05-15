import re
from datetime import datetime
from app.models.log_event import LogEvent

# Format: May 14 10:23:45 hostname sshd[1234]: Failed password for root from 1.2.3.4 port 22
_AUTH_PATTERN = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+\S+\s+\S+:\s+(?P<message>.+)"
)
_AUTH_FAILED = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)")
_AUTH_ACCEPTED = re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+)")
_AUTH_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)")

# Format: 1.2.3.4 - - [14/May/2026:10:23:45 +0000] "GET /path HTTP/1.1" 200 512
_ACCESS_PATTERN = re.compile(
    r'(?P<ip>[\d.]+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) (?P<size>\d+)'
)


def parse_auth_line(line: str) -> LogEvent | None:
    m = _AUTH_PATTERN.match(line.strip())
    if not m:
        return None

    try:
        year = datetime.now().year
        ts = datetime.strptime(f"{m.group('month')} {m.group('day')} {year} {m.group('time')}", "%b %d %Y %H:%M:%S")
    except ValueError:
        ts = datetime.now()

    msg = m.group("message")
    event = LogEvent(timestamp=ts, source="auth", raw=line.strip())

    if failed := _AUTH_FAILED.search(msg):
        event.user = failed.group("user")
        event.ip = failed.group("ip")
        event.action = "failed_login"
        event.status = "FAILED"
        event.severity = "WARNING"
    elif accepted := _AUTH_ACCEPTED.search(msg):
        event.user = accepted.group("user")
        event.ip = accepted.group("ip")
        event.action = "login"
        event.status = "SUCCESS"
        event.severity = "INFO"
    elif invalid := _AUTH_INVALID.search(msg):
        event.user = invalid.group("user")
        event.ip = invalid.group("ip")
        event.action = "invalid_user"
        event.status = "FAILED"
        event.severity = "WARNING"
    else:
        event.action = "other"
        event.severity = "INFO"

    return event


def parse_access_line(line: str) -> LogEvent | None:
    m = _ACCESS_PATTERN.match(line.strip())
    if not m:
        return None

    try:
        ts = datetime.strptime(m.group("time"), "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
    except ValueError:
        ts = datetime.now()

    status_code = int(m.group("status"))
    severity = "INFO"
    if status_code >= 500:
        severity = "CRITICAL"
    elif status_code >= 400:
        severity = "WARNING"

    return LogEvent(
        timestamp=ts,
        source="access",
        raw=line.strip(),
        ip=m.group("ip"),
        action=m.group("method"),
        status=m.group("status"),
        severity=severity,
        extra={"path": m.group("path"), "size": m.group("size")},
    )


def parse_line(line: str, source: str) -> LogEvent | None:
    if source == "auth":
        return parse_auth_line(line)
    if source == "access":
        return parse_access_line(line)
    return None
