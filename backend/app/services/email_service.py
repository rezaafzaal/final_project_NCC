import os
import smtplib
from email.message import EmailMessage


def send_alert_email(event):
    EMAIL_USER = os.getenv("EMAIL_USER")
    EMAIL_PASS = os.getenv("EMAIL_PASS")
    ALERT_RECEIVER = os.getenv("ALERT_RECEIVER")

    # safety check
    if not EMAIL_USER or not EMAIL_PASS or not ALERT_RECEIVER:
        print("[EMAIL] Missing environment variables")
        return

    msg = EmailMessage()
    msg["Subject"] = f"[SIEM ALERT] {event.severity} - {event.rule_triggered}"
    msg["From"] = EMAIL_USER
    msg["To"] = ALERT_RECEIVER

    msg.set_content(f"""
SIEM ALERT TRIGGERED

Rule: {event.rule_triggered}
Severity: {event.severity}
Source: {event.source}
IP: {event.ip}
User: {event.user}
Action: {event.action}
Status: {event.status}
Time: {event.timestamp}
""")

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
            smtp.starttls()
            smtp.login(EMAIL_USER, EMAIL_PASS)
            smtp.send_message(msg)

        print("[EMAIL] Alert sent successfully")

    except Exception as e:
        print("[EMAIL] Failed:", str(e))