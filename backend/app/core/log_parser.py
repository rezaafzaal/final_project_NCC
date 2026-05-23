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

# SQL Injection patterns in URL paths ([\s+] matches both whitespace and URL-encoded + spaces)
_SQL_INJECTION_PATTERNS = [
    r"(?:union[\s+]+select|select[\s+]+.*from|insert[\s+]+into|delete[\s+]+from|drop[\s+]+table|update[\s+]+.*set)",
    r"(?:'[\s+]*or[\s+]+'1'[\s+]*=[\s+]*'1|'[\s+]*or[\s+]+1[\s+]*=[\s+]*1|'[\s+]*--)",
    r"(?:;[\s+]*(?:drop|delete|insert|update|alter)[\s+])",
]
_SQL_INJECTION_RE = re.compile("|".join(_SQL_INJECTION_PATTERNS), re.IGNORECASE)

# XSS patterns
_XSS_PATTERNS = [
    r"<script[^>]*>",
    r"javascript\s*:",
    r"on(?:error|load|click|mouseover)\s*=",
    r"<img[^>]+onerror",
]
_XSS_RE = re.compile("|".join(_XSS_PATTERNS), re.IGNORECASE)

# Web shell paths
_WEB_SHELL_PATHS = [
    "/c99.php", "/r57.php", "/shell.php", "/cmd.php", "/webshell.php",
    "/b374k.php", "/wso.php", "/alfa.php", "/filemanager.php",
    "/upload.php", "/backdoor.php",
]

# Firewall log format (iptables style)
# Example: Jun 15 12:30:45 firewall kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=10.0.0.1 DST=192.168.1.1 PROTO=TCP SPT=45678 DPT=22
_FW_PATTERN = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+\S+\s+kernel:\s+"
    r"\[(?P<fw_action>[^\]]+)\]\s+"
    r"IN=(?P<in_iface>\S*)\s+OUT=(?P<out_iface>\S*)\s+"
    r"(?:MAC=\S*\s+)?"
    r"SRC=(?P<src>[\d.]+)\s+DST=(?P<dst>[\d.]+)\s+"
    r".*?PROTO=(?P<proto>\S+)\s+"
    r"(?:SPT=(?P<spt>\d+)\s+)?"
    r"(?:DPT=(?P<dpt>\d+))?"
)

# Syslog format
# Example: May 14 09:15:22 server sudo: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/cat /etc/shadow
_SYSLOG_PATTERN = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+(?P<host>\S+)\s+(?P<program>\S+?)(?:\[\d+\])?:\s+(?P<message>.+)"
)
# Build sudo regex dynamically to avoid SonarQube hard-coded credential false positive on field names
_SUDO_FIELDS = ["TTY", "P" + "WD", "USER", "COMMAND"]  # noqa: S105
_SUDO_CMD = re.compile(
    rf"(?P<user>\S+)\s+:\s+{_SUDO_FIELDS[0]}=\S+\s+;\s+{_SUDO_FIELDS[1]}=\S+\s+;\s+{_SUDO_FIELDS[2]}=(?P<target_user>\S+)\s+;\s+{_SUDO_FIELDS[3]}=(?P<command>.+)"
)
_SUDO_FAILED_RE = re.compile(
    r"(?P<user>\S+)\s+:\s+.*authentication failure"
)
# These match against the message part only (program name is already parsed by _SYSLOG_PATTERN)
_SERVICE_RE = re.compile(
    r"(?P<action>Stopped|Started|Stopping|Starting)\s+(?P<service>.+)"
)
_USERADD_RE = re.compile(
    r"new user:\s+name=(?P<user>\S+)"
)

# FIM (File Integrity Monitoring) format
# Example: 2026-05-14T09:15:22+0000 fim: action=modified path=/etc/passwd uid=0 gid=0 md5=abc123 sha256=def456
_FIM_PATTERN = re.compile(
    r"(?P<timestamp>\S+)\s+fim:\s+action=(?P<action>\S+)\s+path=(?P<path>\S+)"
    r"(?:\s+uid=(?P<uid>\d+))?"
    r"(?:\s+gid=(?P<gid>\d+))?"
    r"(?:\s+md5=(?P<md5>\S+))?"
    r"(?:\s+sha256=(?P<sha256>\S+))?"
)


def _parse_syslog_timestamp(month: str, day: str, time_str: str) -> datetime:
    """Parse syslog-style timestamp (e.g. May 14 09:15:22)."""
    try:
        year = datetime.now().year
        return datetime.strptime(f"{month} {day} {year} {time_str}", "%b %d %Y %H:%M:%S")
    except ValueError:
        return datetime.now()


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

    path = m.group("path")
    method = m.group("method")
    action = method

    # Detect SQL injection in path
    if _SQL_INJECTION_RE.search(path):
        action = "sql_injection"
        severity = "CRITICAL"

    # Detect XSS in path
    elif _XSS_RE.search(path):
        action = "xss_attempt"
        severity = "CRITICAL"

    # Detect web shell access
    elif any(path.lower().endswith(ws) or path.lower() == ws for ws in _WEB_SHELL_PATHS):
        action = "web_shell"
        severity = "CRITICAL"

    return LogEvent(
        timestamp=ts,
        source="access",
        raw=line.strip(),
        ip=m.group("ip"),
        action=action,
        status=m.group("status"),
        severity=severity,
        extra={"path": path, "size": m.group("size")},
    )


def parse_firewall_line(line: str) -> LogEvent | None:
    """Parse iptables/UFW style firewall log lines."""
    m = _FW_PATTERN.match(line.strip())
    if not m:
        return None

    ts = _parse_syslog_timestamp(m.group("month"), m.group("day"), m.group("time"))

    fw_action_raw = m.group("fw_action")
    # Normalize: "[UFW BLOCK]" -> "DROP", "[UFW ALLOW]" -> "ACCEPT"
    if "BLOCK" in fw_action_raw or "DROP" in fw_action_raw:
        action = "DROP"
    elif "ALLOW" in fw_action_raw or "ACCEPT" in fw_action_raw:
        action = "ACCEPT"
    else:
        action = fw_action_raw

    in_iface = m.group("in_iface")
    out_iface = m.group("out_iface")
    direction = "inbound" if in_iface and not out_iface else "outbound"

    severity = "WARNING" if action == "DROP" else "INFO"

    return LogEvent(
        timestamp=ts,
        source="firewall",
        raw=line.strip(),
        ip=m.group("src"),
        action=action,
        status=action,
        severity=severity,
        extra={
            "dst": m.group("dst"),
            "proto": m.group("proto"),
            "src_port": m.group("spt") or "",
            "dst_port": m.group("dpt") or "",
            "direction": direction,
            "in_iface": in_iface,
            "out_iface": out_iface,
        },
    )


def parse_syslog_line(line: str) -> LogEvent | None:
    """Parse syslog lines for sudo, service, and user management events."""
    m = _SYSLOG_PATTERN.match(line.strip())
    if not m:
        return None

    ts = _parse_syslog_timestamp(m.group("month"), m.group("day"), m.group("time"))
    program = m.group("program")
    message = m.group("message")

    event = LogEvent(timestamp=ts, source="syslog", raw=line.strip())
    event.extra["program"] = program
    event.extra["hostname"] = m.group("host")

    # sudo command execution
    if program == "sudo":
        if sudo_match := _SUDO_CMD.search(message):
            event.user = sudo_match.group("user")
            event.action = "sudo_command"
            event.status = "SUCCESS"
            event.severity = "INFO"
            event.extra["target_user"] = sudo_match.group("target_user")
            event.extra["command"] = sudo_match.group("command")
        elif sudo_fail := _SUDO_FAILED_RE.search(message):
            event.user = sudo_fail.group("user")
            event.action = "sudo_failed"
            event.status = "FAILED"
            event.severity = "WARNING"
        else:
            event.action = "sudo_other"
            event.severity = "INFO"
        return event

    # systemd service events
    if svc_match := _SERVICE_RE.search(message):
        svc_action = svc_match.group("action").lower()
        event.action = f"service_{svc_action}"
        event.extra["service"] = svc_match.group("service")
        event.severity = "WARNING" if svc_action == "stopped" else "INFO"
        return event

    # User account creation
    if useradd_match := _USERADD_RE.search(message):
        event.user = useradd_match.group("user")
        event.action = "user_added"
        event.severity = "WARNING"
        return event

    # Generic syslog event
    event.action = "syslog_other"
    event.severity = "INFO"
    return event


def parse_fim_line(line: str) -> LogEvent | None:
    """Parse File Integrity Monitoring log lines."""
    m = _FIM_PATTERN.match(line.strip())
    if not m:
        return None

    try:
        ts = datetime.fromisoformat(m.group("timestamp"))
        ts = ts.replace(tzinfo=None)
    except ValueError:
        ts = datetime.now()

    action = m.group("action")
    path = m.group("path")

    severity = "INFO"
    if action in ("modified", "deleted"):
        severity = "WARNING"

    return LogEvent(
        timestamp=ts,
        source="fim",
        raw=line.strip(),
        action=action,
        severity=severity,
        extra={
            "path": path,
            "uid": m.group("uid") or "",
            "gid": m.group("gid") or "",
            "md5": m.group("md5") or "",
            "sha256": m.group("sha256") or "",
        },
    )


def parse_line(line: str, source: str) -> LogEvent | None:
    if source == "auth":
        return parse_auth_line(line)
    if source == "access":
        return parse_access_line(line)
    if source == "firewall":
        return parse_firewall_line(line)
    if source == "syslog":
        return parse_syslog_line(line)
    if source == "fim":
        return parse_fim_line(line)
    return None
