import json
from collections import defaultdict, deque
from datetime import datetime, timedelta
from app.config import RULES_PATH
from app.models.log_event import LogEvent


def load_rules() -> list:
    try:
        with open(RULES_PATH) as f:
            return json.load(f).get("rules", [])
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _check_basic_fields(conditions: dict, event: LogEvent) -> bool:
    """Check simple equality conditions: source, action, status, user."""
    if "source" in conditions and event.source != conditions["source"]:
        return False
    if "action" in conditions and event.action != conditions["action"]:
        return False
    if "status" in conditions and event.status != conditions["status"]:
        return False
    if "user" in conditions and event.user != conditions["user"]:
        return False
    if "direction" in conditions:
        if event.extra.get("direction") != conditions["direction"]:
            return False
    return True


def _check_path_match(conditions: dict, event: LogEvent) -> bool:
    """Check if event path matches any prefix/exact pattern in path_match list."""
    if "path_match" not in conditions:
        return True
    event_path = event.extra.get("path", "")
    if not event_path:
        return False
    return any(
        event_path == pattern or event_path.startswith(pattern)
        for pattern in conditions["path_match"]
    )


def _check_time_range(conditions: dict, event: LogEvent) -> bool:
    """Check if event timestamp falls within the specified hour range."""
    if "time_range" not in conditions:
        return True
    tr = conditions["time_range"]
    hour = event.timestamp.hour
    start_h = tr.get("start_hour", 0)
    end_h = tr.get("end_hour", 6)
    if start_h <= end_h:
        return start_h <= hour < end_h
    # Wraps around midnight, e.g. start=22, end=6
    return hour >= start_h or hour < end_h


class RuleEngine:
    def __init__(self):
        self.rules = load_rules()
        # Track event counts per IP untuk rate-based rules
        self._counters: dict[str, deque] = defaultdict(deque)

    def reload_rules(self):
        self.rules = load_rules()

    def evaluate(self, event: LogEvent) -> LogEvent:
        for rule in self.rules:
            if self._matches(rule, event):
                event.rule_triggered = rule["name"]
                event.severity = rule.get("severity", event.severity)
        return event

    def _matches(self, rule: dict, event: LogEvent) -> bool:
        conditions = rule.get("conditions", {})

        if not _check_basic_fields(conditions, event):
            return False
        if not _check_path_match(conditions, event):
            return False
        if not _check_time_range(conditions, event):
            return False
        if not self._check_rate(rule, conditions, event):
            return False

        return True

    def _check_rate(self, rule: dict, conditions: dict, event: LogEvent) -> bool:
        """Check rate-based conditions (e.g. N events within M seconds from same IP)."""
        if "rate" not in conditions:
            return True
        rate = conditions["rate"]
        key = f"{rule['name']}:{event.ip}"
        window = timedelta(seconds=rate.get("window_seconds", 60))
        now = datetime.now()
        dq = self._counters[key]
        dq.append(now)
        # buang timestamp yang sudah di luar window
        while dq and dq[0] < now - window:
            dq.popleft()
        return len(dq) >= rate.get("threshold", 5)
