import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

print("=" * 60)
print("Sprint 3 - Safe Mock Test (No Actual Blocking)")
print("=" * 60)

# Just test the logic without firewall calls
from response_manager import ResponseManager
from metrics import BlockingMetrics

# Mock blocker
class MockBlocker:
    def __init__(self):
        self.blocked_ips = set()
    
    def block_ip(self, ip, reason=""):
        self.blocked_ips.add(ip)
        print(f"[MOCK BLOCKER] Would block IP: {ip}")
        return True
    
    def get_blocked_ips(self):
        return list(self.blocked_ips)

print("\n[TEST] Initializing mock modules...")
blocker = MockBlocker()
response_manager = ResponseManager(blocker)
metrics = BlockingMetrics()
print("[TEST] ✅ All modules ready (mock mode)")

# Test alerts
print("\n[TEST] Simulating attacks...\n")

alert1 = {
    'type': 'SINGLE_IP_FLOODING',
    'severity': 'CRITICAL',
    'ip': '192.168.1.100',
    'message': 'Single IP flooding detected'
}

print("[TEST] Alert 1: Single IP Flooding")
response1 = response_manager.handle_alert(alert1)
print(f"[TEST] Response: {response1['action']}")
print(f"[TEST] IPs Blocked: {response1['ips_blocked']}\n")

alert2 = {
    'type': 'RPS_ANOMALY',
    'severity': 'CRITICAL',
    'message': 'High RPS detected'
}

print("[TEST] Alert 2: RPS Anomaly")
response2 = response_manager.handle_alert(alert2)
print(f"[TEST] Response: {response2['action']}\n")

alert3 = {
    'type': 'PORT_SCANNING',
    'severity': 'HIGH',
    'message': 'Port scanning detected'
}

print("[TEST] Alert 3: Port Scanning")
response3 = response_manager.handle_alert(alert3)
print(f"[TEST] Response: {response3['action']}\n")

# Results
print("=" * 60)
print("Results:")
print("=" * 60)

blocked = blocker.get_blocked_ips()
print(f"\n✅ Blocked IPs: {blocked}")

metrics_data = metrics.get_metrics()
print(f"\n✅ Metrics:")
print(f"   - Total Blocked: {metrics_data['total_blocked']}")
print(f"   - Blocked Today: {metrics_data['blocked_today']}")
print(f"   - By Type: {metrics_data['by_type']}")
print(f"   - By Severity: {metrics_data['by_severity']}")

print("\n[TEST] ✅ Sprint 3 Logic Test Complete!")
print("=" * 60)
print("\n✅ NO FIREWALL RULES WERE ACTUALLY CREATED")
print("✅ YOUR SYSTEM IS SAFE")