from datetime import datetime

class AlertSystem:
    """Alert system for logging and tracking attacks"""
    
    def __init__(self):
        self.alerts = []
        self.log_file = 'alerts.log'
    
    def send_alert(self, alert):
        """Send and log an alert"""
        alert['timestamp'] = datetime.now().strftime('%H:%M:%S')
        self.alerts.append(alert)
        
        # Print to console
        severity_color = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }
        
        icon = severity_color.get(alert.get('severity', 'UNKNOWN'), '⚪')
        
        print(f"\n{icon} [ALERT] {alert['type']}")
        print(f"   Severity: {alert.get('severity', 'N/A')}")
        print(f"   Message: {alert.get('message', 'N/A')}")
        if alert.get('ip'):
            print(f"   IP: {alert['ip']}")
        print()
    
    def get_alerts(self):
        """Get all alerts"""
        return self.alerts
    
    def get_recent_alerts(self, limit=10):
        """Get recent alerts"""
        return self.alerts[-limit:]
    
    def clear_alerts(self):
        """Clear all alerts"""
        self.alerts = []