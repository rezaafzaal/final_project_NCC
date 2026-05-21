from app.metrics import events_total, rules_triggered_total, active_websocket_connections


def test_metrics_are_defined():
    assert events_total is not None
    assert rules_triggered_total is not None
    assert active_websocket_connections is not None


def test_events_total_labels():
    events_total.labels(severity="INFO", source="auth").inc()
    events_total.labels(severity="WARNING", source="access").inc()
    events_total.labels(severity="CRITICAL", source="auth").inc()


def test_rules_triggered_total_labels():
    rules_triggered_total.labels(rule="ssh_brute_force").inc()
    rules_triggered_total.labels(rule="http_not_found_scan").inc()


def test_active_websocket_connections_gauge():
    active_websocket_connections.inc()
    active_websocket_connections.dec()
