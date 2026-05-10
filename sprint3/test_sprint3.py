import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from blocker import IPBlocker
from response_manager import ResponseManager
from metrics import BlockingMetrics

print("=" * 60)
print("Sprint 3 - Blocker & Response Manager Test")
print("=" * 60)

# Initialize modules
blocker = IPBlocker()
response_manager = ResponseManager(blocker)
metrics = BlockingMetrics()

print("\n[TEST] Initializing modules...")
print("[TEST] Blocker ready")
print("[TEST] Response Manager ready")
print("[TEST] Metrics tracker ready")

# Simulate alerts
print("\n[TEST] Simulating attacks...")

# Test 1: Single IP flooding
alert1 = {
    'type': 'SINGLE_IP_FLOODING',
    'severity': 'CRITICAL',
    'ip': '192.168.1.100',
    'message': 'Single IP flooding detected',
    'timestamp': '2026-05-10T10:30:00',
    'ips_involved': ['192.168.1.100']
}

print("\n[TEST] Alert 1: Single IP Flooding")
response1 = response_manager.handle_alert(alert1)
print(f"[TEST] Response: {response1['action']}")
print(f"[TEST] IPs Blocked: {response1['ips_blocked']}")

if response1['ips_blocked']:
    for ip in response1['ips_blocked']:
        metrics.record_block(alert1['type'], alert1['severity'], ip)

# Test 2: RPS Anomaly
alert2 = {
    'type': 'RPS_ANOMALY',
    'severity': 'CRITICAL',
    'message': 'High RPS detected',
    'timestamp': '2026-05-10T10:31:00',
    'ips_involved': []
}

print("\n[TEST] Alert 2: RPS Anomaly")
response2 = response_manager.handle_alert(alert2)
print(f"[TEST] Response: {response2['action']}")

# Test 3: Port Scanning
alert3 = {
    'type': 'PORT_SCANNING',
    'severity': 'HIGH',
    'message': 'Port scanning detected',
    'timestamp': '2026-05-10T10:32:00',
    'ips_involved': []
}

print("\n[TEST] Alert 3: Port Scanning")
response3 = response_manager.handle_alert(alert3)
print(f"[TEST] Response: {response3['action']}")

# Show results
print("\n" + "=" * 60)
print("Results:")
print("=" * 60)

blocked = blocker.get_blocked_ips()
print(f"\n[RESULTS] Blocked IPs: {blocked}")

metrics_data = metrics.get_metrics()
print(f"\n[RESULTS] Metrics:")
print(f"  - Total Blocked: {metrics_data['total_blocked']}")
print(f"  - Blocked Today: {metrics_data['blocked_today']}")
print(f"  - By Type: {metrics_data['by_type']}")
print(f"  - By Severity: {metrics_data['by_severity']}")

responses = response_manager.get_responses()
print(f"\n[RESULTS] Responses Taken: {len(responses)}")
for r in responses:
    print(f"  - {r['action']}: {r['ips_blocked']}")

print("\n[TEST] Sprint 3 Test Complete!")
print("=" * 60)