import requests
import os

def send_alert_dc(event):
    DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK")

    if not DISCORD_WEBHOOK:
        print("[DISCORD] Missing webhook URL")
        return

    message = f"""
 **SIEM ALERT TRIGGERED**

**Rule:** {event.rule_triggered}
**Severity:** {event.severity}
**Source:** {event.source}
**IP:** {event.ip}
**User:** {event.user}
**Action:** {event.action}
**Status:** {event.status}
**Time:** {event.timestamp}
"""

    payload = {
        "content": message
    }

    try:
        r = requests.post(DISCORD_WEBHOOK, json=payload)

        if r.status_code == 204:
            print("[DISCORD] Alert sent successfully")
        else:
            print("[DISCORD] Failed:", r.text)

    except Exception as e:
        print("[DISCORD] Error:", str(e))