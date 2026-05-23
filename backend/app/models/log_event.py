from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class LogEvent:
    timestamp: datetime
    source: str          # "auth" | "access" | "firewall" | "syslog" | "fim"
    raw: str             # baris log asli
    ip: Optional[str] = None
    user: Optional[str] = None
    action: Optional[str] = None
    status: Optional[str] = None
    severity: str = "INFO"   # INFO | WARNING | CRITICAL
    rule_triggered: Optional[str] = None
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "raw": self.raw,
            "ip": self.ip,
            "user": self.user,
            "action": self.action,
            "status": self.status,
            "severity": self.severity,
            "rule_triggered": self.rule_triggered,
            "extra": self.extra,
        }
