import threading
from datetime import datetime, timedelta
from collections import defaultdict

class ResponseManager:
    def __init__(self, blocker):
        self.blocker = blocker
        self.attack_threshold = {
            'RPS_ANOMALY': {'CRITICAL': 1, 'HIGH': 3},
            'SINGLE_IP_FLOODING': {'CRITICAL': 1},
            'PORT_SCANNING': {'HIGH': 2}
        }
        self.alert_window = 60  # seconds
        self.recent_alerts = defaultdict(list)
        self.responses_taken = []
        self.lock = threading.Lock()

    def handle_alert(self, alert):
        """Handle an alert and take appropriate action"""
        alert_type = alert['type']
        severity = alert['severity']
        
        with self.lock:
            # Track alert in window
            self.recent_alerts[alert_type].append({
                'timestamp': datetime.now(),
                'severity': severity,
                'alert': alert
            })
            
            # Clean old alerts (older than window)
            cutoff_time = datetime.now() - timedelta(seconds=self.alert_window)
            self.recent_alerts[alert_type] = [
                a for a in self.recent_alerts[alert_type]
                if a['timestamp'] > cutoff_time
            ]
        
        # Decide response
        return self._decide_response(alert)

    def _decide_response(self, alert):
        """Decide what action to take"""
        alert_type = alert['type']
        severity = alert['severity']
        
        response = {
            'alert_type': alert_type,
            'action': 'NONE',
            'ips_blocked': [],
            'timestamp': datetime.now().isoformat()
        }
        
        # Response 1: Block single IP flooding
        if alert_type == 'SINGLE_IP_FLOODING':
            ip = alert.get('ip')
            if ip and severity == 'CRITICAL':
                if self.blocker.block_ip(ip, f"DDoS Flooding from {ip}"):
                    response['action'] = 'BLOCK_IP'
                    response['ips_blocked'] = [ip]
        
        # Response 2: Block top IPs on RPS anomaly
        elif alert_type == 'RPS_ANOMALY':
            if severity == 'CRITICAL':
                # Block top 3 IPs (if available)
                response['action'] = 'MONITOR'
                response['reason'] = 'High RPS detected - monitoring'
        
        # Response 3: Block port scanner
        elif alert_type == 'PORT_SCANNING':
            if severity == 'HIGH':
                response['action'] = 'ALERT'
                response['reason'] = 'Port scanning detected'
        
        with self.lock:
            self.responses_taken.append(response)
            if len(self.responses_taken) > 1000:
                self.responses_taken.pop(0)
        
        return response

    def get_responses(self, limit=50):
        """Get recent responses"""
        with self.lock:
            return self.responses_taken[-limit:]

    def get_blocked_ips(self):
        """Get blocked IPs"""
        return self.blocker.get_blocked_ips()