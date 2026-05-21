from prometheus_client import Counter, Gauge

events_total = Counter(
    "siem_events_total",
    "Total log events processed",
    ["severity", "source"],
)

rules_triggered_total = Counter(
    "siem_rules_triggered_total",
    "Total rule triggers",
    ["rule"],
)

active_websocket_connections = Gauge(
    "siem_active_websocket_connections",
    "Number of active WebSocket connections",
)
