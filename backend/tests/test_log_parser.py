import pytest
from app.core.log_parser import (
    parse_auth_line, parse_access_line, parse_firewall_line,
    parse_syslog_line, parse_fim_line, parse_line,
)

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

# --- SQL injection / XSS / web shell access log lines ---
ACCESS_SQLI = '1.2.3.4 - - [21/May/2026:10:23:45 +0000] "GET /api/users?id=1\'+OR+\'1\'=\'1 HTTP/1.1" 200 512'
ACCESS_XSS = '1.2.3.4 - - [21/May/2026:10:23:45 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 256'
ACCESS_WEBSHELL = '1.2.3.4 - - [21/May/2026:10:23:45 +0000] "GET /c99.php HTTP/1.1" 200 1024'

# --- sample firewall log lines ---
FW_BLOCK_INBOUND = "May 23 10:15:30 firewall kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:0c:29:68:a1:b2 SRC=45.33.32.156 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=54321 PROTO=TCP SPT=45678 DPT=22"
FW_ALLOW_INBOUND = "May 23 10:16:00 firewall kernel: [UFW ALLOW] IN=eth0 OUT= SRC=10.0.0.5 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 PROTO=TCP SPT=52000 DPT=80"
FW_BLOCK_OUTBOUND = "May 23 10:17:00 firewall kernel: [UFW BLOCK] IN= OUT=eth0 SRC=192.168.1.1 DST=91.219.237.0 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=33333 PROTO=TCP SPT=45000 DPT=4444"

# --- sample syslog lines ---
SYSLOG_SUDO = "May 23 09:15:22 server sudo: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/cat /etc/shadow"
SYSLOG_SUDO_FAIL = "May 23 09:16:00 server sudo: admin : authentication failure ; logname= ; uid=1000 ; euid=0 ; tty=/dev/pts/0 ; ruser=admin ; rhost= ; user=root"
SYSLOG_SERVICE_STOP = "May 23 09:20:00 server systemd[1]: Stopped nginx.service"
SYSLOG_SERVICE_START = "May 23 09:20:05 server systemd[1]: Started nginx.service"
SYSLOG_USERADD = "May 23 09:25:10 server useradd[5432]: new user: name=deploy, UID=1001, GID=1001, home=/home/deploy, shell=/bin/bash"
SYSLOG_CRON = "May 23 09:35:00 server cron[2345]: (root) CMD (/usr/local/bin/cleanup.sh)"

# --- sample FIM lines ---
FIM_MODIFIED = "2026-05-23T09:15:22+00:00 fim: action=modified path=/etc/passwd uid=0 gid=0 md5=abc123def456789012345678 sha256=abc123def456789012345678901234567890123456789012345678901234"
FIM_CREATED = "2026-05-23T09:16:00+00:00 fim: action=created path=/tmp/test.txt uid=1000 gid=1000 md5=def456abc789012345678901 sha256=def456abc789012345678901234567890123456789012345678901234567"
FIM_DELETED = "2026-05-23T09:25:00+00:00 fim: action=deleted path=/var/log/auth.log uid=0 gid=0"


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


# ---- SQL injection detection ----

def test_parse_access_sql_injection_detected():
    event = parse_access_line(ACCESS_SQLI)
    assert event is not None
    assert event.action == "sql_injection"
    assert event.severity == "CRITICAL"


# ---- XSS detection ----

def test_parse_access_xss_detected():
    event = parse_access_line(ACCESS_XSS)
    assert event is not None
    assert event.action == "xss_attempt"
    assert event.severity == "CRITICAL"


# ---- web shell detection ----

def test_parse_access_webshell_detected():
    event = parse_access_line(ACCESS_WEBSHELL)
    assert event is not None
    assert event.action == "web_shell"
    assert event.severity == "CRITICAL"


# ---- firewall tests ----

def test_parse_firewall_block_inbound():
    event = parse_firewall_line(FW_BLOCK_INBOUND)
    assert event is not None
    assert event.source == "firewall"
    assert event.action == "DROP"
    assert event.ip == "45.33.32.156"
    assert event.extra["dst"] == "192.168.1.1"
    assert event.extra["proto"] == "TCP"
    assert event.extra["dst_port"] == "22"
    assert event.extra["direction"] == "inbound"
    assert event.severity == "WARNING"


def test_parse_firewall_allow_inbound():
    event = parse_firewall_line(FW_ALLOW_INBOUND)
    assert event is not None
    assert event.action == "ACCEPT"
    assert event.ip == "10.0.0.5"
    assert event.severity == "INFO"


def test_parse_firewall_block_outbound():
    event = parse_firewall_line(FW_BLOCK_OUTBOUND)
    assert event is not None
    assert event.action == "DROP"
    assert event.extra["direction"] == "outbound"
    assert event.extra["dst_port"] == "4444"
    assert event.ip == "192.168.1.1"


def test_parse_firewall_raw_preserved():
    event = parse_firewall_line(FW_BLOCK_INBOUND)
    assert event is not None
    assert event.raw == FW_BLOCK_INBOUND.strip()


def test_parse_firewall_invalid_returns_none():
    assert parse_firewall_line("not a firewall log") is None
    assert parse_firewall_line("") is None


# ---- syslog tests ----

def test_parse_syslog_sudo_command():
    event = parse_syslog_line(SYSLOG_SUDO)
    assert event is not None
    assert event.source == "syslog"
    assert event.action == "sudo_command"
    assert event.user == "ubuntu"
    assert event.status == "SUCCESS"
    assert event.extra["target_user"] == "root"
    assert event.extra["command"] == "/bin/cat /etc/shadow"


def test_parse_syslog_sudo_failed():
    event = parse_syslog_line(SYSLOG_SUDO_FAIL)
    assert event is not None
    assert event.action == "sudo_failed"
    assert event.status == "FAILED"
    assert event.severity == "WARNING"


def test_parse_syslog_service_stopped():
    event = parse_syslog_line(SYSLOG_SERVICE_STOP)
    assert event is not None
    assert event.action == "service_stopped"
    assert event.severity == "WARNING"
    assert event.extra["service"] == "nginx.service"


def test_parse_syslog_service_started():
    event = parse_syslog_line(SYSLOG_SERVICE_START)
    assert event is not None
    assert event.action == "service_started"
    assert event.severity == "INFO"
    assert event.extra["service"] == "nginx.service"


def test_parse_syslog_useradd():
    event = parse_syslog_line(SYSLOG_USERADD)
    assert event is not None
    assert event.action == "user_added"
    assert event.user == "deploy"
    assert event.severity == "WARNING"


def test_parse_syslog_cron_generic():
    event = parse_syslog_line(SYSLOG_CRON)
    assert event is not None
    assert event.source == "syslog"
    assert event.action == "syslog_other"
    assert event.severity == "INFO"


def test_parse_syslog_invalid_returns_none():
    assert parse_syslog_line("not a syslog line") is None
    assert parse_syslog_line("") is None


def test_parse_syslog_raw_preserved():
    event = parse_syslog_line(SYSLOG_SUDO)
    assert event is not None
    assert event.raw == SYSLOG_SUDO.strip()


# ---- FIM tests ----

def test_parse_fim_modified():
    event = parse_fim_line(FIM_MODIFIED)
    assert event is not None
    assert event.source == "fim"
    assert event.action == "modified"
    assert event.extra["path"] == "/etc/passwd"
    assert event.extra["uid"] == "0"
    assert event.severity == "WARNING"


def test_parse_fim_created():
    event = parse_fim_line(FIM_CREATED)
    assert event is not None
    assert event.action == "created"
    assert event.extra["path"] == "/tmp/test.txt"
    assert event.severity == "INFO"


def test_parse_fim_deleted():
    event = parse_fim_line(FIM_DELETED)
    assert event is not None
    assert event.action == "deleted"
    assert event.extra["path"] == "/var/log/auth.log"
    assert event.severity == "WARNING"


def test_parse_fim_has_hashes():
    event = parse_fim_line(FIM_MODIFIED)
    assert event is not None
    assert event.extra["md5"] != ""
    assert event.extra["sha256"] != ""


def test_parse_fim_invalid_returns_none():
    assert parse_fim_line("not a fim line") is None
    assert parse_fim_line("") is None


def test_parse_fim_raw_preserved():
    event = parse_fim_line(FIM_MODIFIED)
    assert event is not None
    assert event.raw == FIM_MODIFIED.strip()


# ---- parse_line dispatcher ----

def test_parse_line_auth():
    event = parse_line(FAILED_LOGIN, "auth")
    assert event is not None
    assert event.source == "auth"


def test_parse_line_access():
    event = parse_line(ACCESS_200, "access")
    assert event is not None
    assert event.source == "access"


def test_parse_line_firewall():
    event = parse_line(FW_BLOCK_INBOUND, "firewall")
    assert event is not None
    assert event.source == "firewall"


def test_parse_line_syslog():
    event = parse_line(SYSLOG_SUDO, "syslog")
    assert event is not None
    assert event.source == "syslog"


def test_parse_line_fim():
    event = parse_line(FIM_MODIFIED, "fim")
    assert event is not None
    assert event.source == "fim"


def test_parse_line_unknown_source_returns_none():
    assert parse_line("anything", "unknown") is None
    assert parse_line("anything", "") is None
