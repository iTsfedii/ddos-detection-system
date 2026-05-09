import time
from datetime import datetime
from collections import defaultdict
import threading

class AnomalyDetector:
    def __init__(self, baseline_rps=None):
        self.baseline_rps = baseline_rps or 100
        self.alert_history = []
        self.suspicious_ips = set()
        self.lock = threading.Lock()
        
        self.rps_normal_threshold = 500
        self.rps_critical_threshold = 1000
        self.rps_anomaly_multiplier = 5
        
        self.single_ip_threshold = 500
        self.port_scanning_threshold = 50

    def detect_anomalies(self, stats):
        alerts = []
        
        rps_alert = self._detect_rps_anomaly(stats)
        if rps_alert:
            alerts.append(rps_alert)
        
        ip_alerts = self._detect_single_ip_flooding(stats)
        alerts.extend(ip_alerts)
        
        port_alert = self._detect_port_scanning(stats)
        if port_alert:
            alerts.append(port_alert)
        
        for alert in alerts:
            with self.lock:
                self.alert_history.append(alert)
                if len(self.alert_history) > 100:
                    self.alert_history.pop(0)
        
        return alerts

    def _detect_rps_anomaly(self, stats):
        current_rps = stats['rps']
        baseline = stats.get('baseline_rps') or self.baseline_rps
        
        if current_rps > self.rps_critical_threshold:
            severity = 'CRITICAL' if current_rps > baseline * self.rps_anomaly_multiplier else 'HIGH'
            
            return {
                'type': 'RPS_ANOMALY',
                'severity': severity,
                'message': f'Requests/sec abnormally high: {current_rps:.2f} req/sec (baseline: {baseline:.2f})',
                'current_rps': current_rps,
                'baseline_rps': baseline,
                'timestamp': datetime.now().isoformat(),
                'ips_involved': []
            }
        
        return None

    def _detect_single_ip_flooding(self, stats):
        alerts = []
        top_ips = stats.get('top_ips', [])
        
        for ip, packet_count in top_ips:
            if packet_count > self.single_ip_threshold:
                alert = {
                    'type': 'SINGLE_IP_FLOODING',
                    'severity': 'CRITICAL',
                    'message': f'Single IP flooding detected: {ip} sent {packet_count} packets',
                    'ip': ip,
                    'packet_count': packet_count,
                    'timestamp': datetime.now().isoformat(),
                    'ips_involved': [ip]
                }
                alerts.append(alert)
                
                with self.lock:
                    self.suspicious_ips.add(ip)
        
        return alerts

    def _detect_port_scanning(self, stats):
        unique_ports = stats.get('unique_ports', 0)
        
        if unique_ports > self.port_scanning_threshold:
            return {
                'type': 'PORT_SCANNING',
                'severity': 'HIGH',
                'message': f'Port scanning detected: {unique_ports} unique ports accessed',
                'unique_ports': unique_ports,
                'timestamp': datetime.now().isoformat(),
                'ips_involved': []
            }
        
        return None

    def get_alert_history(self, limit=50):
        with self.lock:
            return self.alert_history[-limit:]

    def get_suspicious_ips(self):
        with self.lock:
            return list(self.suspicious_ips)