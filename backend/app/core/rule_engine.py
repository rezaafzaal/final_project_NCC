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

        if "source" in conditions and event.source != conditions["source"]:
            return False
        if "action" in conditions and event.action != conditions["action"]:
            return False
        if "status" in conditions and event.status != conditions["status"]:
            return False

        # User match: e.g. root_login_success requires user == "root"
        if "user" in conditions and event.user != conditions["user"]:
            return False

        # Direction match (for firewall rules): check extra.direction
        if "direction" in conditions:
            if event.extra.get("direction") != conditions["direction"]:
                return False

        # Path match: check if event path matches any prefix/exact in the list
        if "path_match" in conditions:
            event_path = event.extra.get("path", "")
            if not event_path:
                return False
            matched = False
            for pattern in conditions["path_match"]:
                if event_path == pattern or event_path.startswith(pattern):
                    matched = True
                    break
            if not matched:
                return False

        # Time range match: event timestamp must be within the given hour range
        if "time_range" in conditions:
            tr = conditions["time_range"]
            hour = event.timestamp.hour
            start_h = tr.get("start_hour", 0)
            end_h = tr.get("end_hour", 6)
            if start_h <= end_h:
                if not (start_h <= hour < end_h):
                    return False
            else:
                # Wraps around midnight, e.g. start=22, end=6
                if not (hour >= start_h or hour < end_h):
                    return False

        # Rate-based: misal "failed_login >= 5 kali dalam 60 detik dari IP yang sama"
        if "rate" in conditions:
            rate = conditions["rate"]
            key = f"{rule['name']}:{event.ip}"
            window = timedelta(seconds=rate.get("window_seconds", 60))
            now = datetime.now()
            dq = self._counters[key]
            dq.append(now)
            # buang timestamp yang sudah di luar window
            while dq and dq[0] < now - window:
                dq.popleft()
            if len(dq) < rate.get("threshold", 5):
                return False

        return True
