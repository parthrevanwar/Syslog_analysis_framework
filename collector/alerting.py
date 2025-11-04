"""
Alerting: send email & Slack webhook. Keep configuration via env vars or simple constants here for demo.
"""
import os
import smtplib
import json
import logging
import requests
from email.message import EmailMessage

logger = logging.getLogger('alerting')

# Configure via environment variables
ALERT_EMAIL_FROM = os.getenv('ALERT_EMAIL_FROM', 'alert@example.com')
ALERT_EMAIL_TO = os.getenv('ALERT_EMAIL_TO', 'itsec@example.com')
SMTP_HOST = os.getenv('SMTP_HOST', 'localhost')
SMTP_PORT = int(os.getenv('SMTP_PORT', '25'))
SLACK_WEBHOOK = os.getenv('SLACK_WEBHOOK')

class Alerting:
    def __init__(self):
        pass

    def send(self, alert):
        text = json.dumps(alert, indent=2)
        logger.info('ALERT: %s', text)
        # send email
        try:
            self._send_email('Syslog Alert: ' + alert.get('type'), text)
        except Exception as e:
            logger.exception('Email alert failed: %s', e)
        # send slack
        if SLACK_WEBHOOK:
            try:
                requests.post(SLACK_WEBHOOK, json={'text': '*' + alert.get('type') + '*\n' + alert.get('message')})
            except Exception as e:
                logger.exception('Slack notify failed: %s', e)

    def _send_email(self, subject, body):
        msg = EmailMessage()
        msg['From'] = ALERT_EMAIL_FROM
        msg['To'] = ALERT_EMAIL_TO
        msg['Subject'] = subject
        msg.set_content(body)
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
            s.send_message(msg)
