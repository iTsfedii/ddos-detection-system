import threading
from datetime import datetime
from collections import defaultdict

class BlockingMetrics:
    def __init__(self):
        self.total_blocked = 0
        self.blocked_by_type = defaultdict(int)
        self.blocked_by_severity = defaultdict(int)
        self.ips_blocked_today = set()
        self.lock = threading.Lock()
        self.metrics_history = []

    def record_block(self, alert_type, severity, ip):
        """Record a block event"""
        with self.lock:
            self.total_blocked += 1
            self.blocked_by_type[alert_type] += 1
            self.blocked_by_severity[severity] += 1
            self.ips_blocked_today.add(ip)
            
            metric = {
                'timestamp': datetime.now().isoformat(),
                'alert_type': alert_type,
                'severity': severity,
                'ip': ip,
                'total_blocked': self.total_blocked
            }
            self.metrics_history.append(metric)
            
            if len(self.metrics_history) > 10000:
                self.metrics_history.pop(0)

    def get_metrics(self):
        """Get current metrics"""
        with self.lock:
            return {
                'total_blocked': self.total_blocked,
                'blocked_today': len(self.ips_blocked_today),
                'by_type': dict(self.blocked_by_type),
                'by_severity': dict(self.blocked_by_severity),
                'timestamp': datetime.now().isoformat()
            }

    def get_metrics_history(self, limit=100):
        """Get metrics history"""
        with self.lock:
            return self.metrics_history[-limit:]