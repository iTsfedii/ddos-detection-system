import json
import threading
from datetime import datetime
import requests
import os
from pathlib import Path

class AlertSystem:
    def __init__(self, slack_webhook_url=None, log_file='alerts.log'):
        self.slack_webhook_url = slack_webhook_url or os.getenv('SLACK_WEBHOOK_URL')
        self.log_file = log_file
        self.lock = threading.Lock()
        self.sent_alerts = set()
        
        Path(self.log_file).touch(exist_ok=True)

    def send_alert(self, alert):
        try:
            self._log_alert(alert)
            
            if self.slack_webhook_url:
                self._send_slack_alert(alert)
            
            print(f"[ALERT] {alert['severity']}: {alert['message']}")
        except Exception as e:
            print(f"[ERROR] Failed to send alert: {e}")

    def _log_alert(self, alert):
        try:
            with self.lock:
                with open(self.log_file, 'a') as f:
                    f.write(json.dumps(alert) + '\n')
        except Exception as e:
            print(f"[ERROR] Failed to log alert: {e}")

    def _send_slack_alert(self, alert):
        try:
            severity = alert['severity']
            color = '#FF0000' if severity == 'CRITICAL' else '#FFAA00'
            emoji = '🚨' if severity == 'CRITICAL' else '⚠️'
            
            payload = {
                'attachments': [
                    {
                        'color': color,
                        'title': f'{emoji} {severity}: {alert["type"]}',
                        'text': alert['message'],
                        'fields': [
                            {
                                'title': 'Time',
                                'value': alert['timestamp'],
                                'short': True
                            }
                        ],
                        'footer': 'DDoS Detection System'
                    }
                ]
            }
            
            response = requests.post(self.slack_webhook_url, json=payload, timeout=5)
            if response.status_code != 200:
                print(f"[WARNING] Slack API returned {response.status_code}")
        except Exception as e:
            print(f"[WARNING] Failed to send Slack alert: {e}")

    def get_recent_alerts(self, limit=50):
        alerts = []
        try:
            with open(self.log_file, 'r') as f:
                lines = f.readlines()
                for line in lines[-limit:]:
                    alerts.append(json.loads(line))
        except:
            pass
        
        return alerts