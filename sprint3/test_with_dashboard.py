import sys
import os
import json
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'sprint1'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'sprint2'))

from response_manager import ResponseManager
from metrics import BlockingMetrics
from blocker import IPBlocker
from alerter import AlertSystem
import time
from datetime import datetime

SHARED_FILE = os.path.join(os.path.dirname(__file__), 'shared_data.json')

def save_shared_data(alerts, blocked_ips):
    """Save data to shared file (read by dashboard)"""
    try:
        with open(SHARED_FILE, 'w') as f:
            json.dump({
                'alerts': alerts,
                'blocked_ips': blocked_ips
            }, f)
    except Exception as e:
        print(f"[ERROR] Failed to save shared data: {e}")

print("="*70)
print("🛡️  SPRINT 3 TEST - INJECT DATA INTO DASHBOARD")
print("="*70)

print("\n⚠️  MAKE SURE DASHBOARD IS RUNNING FIRST!")
print("   Terminal 1: cd sprint2 && python dashboard.py")
print("   Then run this script in Terminal 2\n")

input("Press ENTER when dashboard is running...")

print("\n" + "="*70)
print("Initializing components...")
print("="*70 + "\n")

# Initialize
blocker = IPBlocker()
response_manager = ResponseManager(blocker)
metrics = BlockingMetrics()
alerter = AlertSystem()

print("✅ All components initialized\n")

time.sleep(1)

# Storage for alerts and blocked IPs
all_alerts = []
blocked_ips = []

# ===== ATTACK 1 =====
print("="*70)
print("TEST 1: SINGLE IP FLOODING ATTACK")
print("="*70 + "\n")

alert1 = {
    'type': 'SINGLE_IP_FLOODING',
    'severity': 'CRITICAL',
    'ip': '192.168.1.100',
    'message': 'Single IP flooding detected: 3861 packets',
    'timestamp': datetime.now().strftime('%H:%M:%S')
}

print(f"🔴 Alert: {alert1['type']}")
print(f"   Severity: {alert1['severity']}")
print(f"   IP: {alert1['ip']}")
print(f"   Message: {alert1['message']}\n")

all_alerts.append(alert1)

print("📤 Sending to alerter...")
alerter.send_alert(alert1)

print("🧠 Making response decision...")
response1 = response_manager.handle_alert(alert1)
print(f"   Decision: {response1['action']}")
print(f"   IPs to block: {response1['ips_blocked']}\n")

if response1['ips_blocked']:
    for ip in response1['ips_blocked']:
        print(f"🔒 Blocking IP: {ip}")
        blocker.block_ip(ip)
        metrics.record_block(alert1['type'], alert1['severity'], ip)
        blocked_ips.append(ip)

# Save to shared file
save_shared_data(all_alerts, blocked_ips)
print(f"💾 Saved to shared file\n")

print("⏳ Waiting 5 seconds... Check dashboard!\n")
time.sleep(5)

# ===== ATTACK 2 =====
print("="*70)
print("TEST 2: RPS ANOMALY")
print("="*70 + "\n")

alert2 = {
    'type': 'RPS_ANOMALY',
    'severity': 'CRITICAL',
    'message': 'High RPS detected: 5000 req/s (normal: 15 req/s)',
    'timestamp': datetime.now().strftime('%H:%M:%S')
}

print(f"🔴 Alert: {alert2['type']}")
print(f"   Severity: {alert2['severity']}")
print(f"   Message: {alert2['message']}\n")

all_alerts.insert(0, alert2)

print("📤 Sending to alerter...")
alerter.send_alert(alert2)

print("🧠 Making response decision...")
response2 = response_manager.handle_alert(alert2)
print(f"   Decision: {response2['action']}")
print(f"   IPs to block: {response2['ips_blocked']}\n")

# Save to shared file
save_shared_data(all_alerts, blocked_ips)
print(f"💾 Saved to shared file\n")

print("⏳ Waiting 5 seconds... Check dashboard!\n")
time.sleep(5)

# ===== ATTACK 3 =====
print("="*70)
print("TEST 3: PORT SCANNING")
print("="*70 + "\n")

alert3 = {
    'type': 'PORT_SCANNING',
    'severity': 'HIGH',
    'ip': '10.0.0.50',
    'message': 'Port scanning detected: 282 unique ports',
    'timestamp': datetime.now().strftime('%H:%M:%S')
}

print(f"🔴 Alert: {alert3['type']}")
print(f"   Severity: {alert3['severity']}")
print(f"   IP: {alert3['ip']}")
print(f"   Message: {alert3['message']}\n")

all_alerts.insert(0, alert3)

print("📤 Sending to alerter...")
alerter.send_alert(alert3)

print("🧠 Making response decision...")
response3 = response_manager.handle_alert(alert3)
print(f"   Decision: {response3['action']}")
print(f"   IPs to block: {response3['ips_blocked']}\n")

# Save to shared file
save_shared_data(all_alerts, blocked_ips)
print(f"💾 Saved to shared file\n")

print("⏳ Waiting 5 seconds... Check dashboard!\n")
time.sleep(5)

# ===== RESULTS =====
print("="*70)
print("✅ TEST COMPLETE!")
print("="*70 + "\n")

blocked = blocker.get_blocked_ips()
metrics_data = metrics.get_metrics()

print(f"📊 Results:")
print(f"   Blocked IPs: {blocked}")
print(f"   Total Blocked: {metrics_data['total_blocked']}")
print(f"   By Type: {metrics_data['by_type']}")
print(f"   By Severity: {metrics_data['by_severity']}\n")

print("✅ Check your dashboard:")
print("   ✅ Alerts should appear in 'Recent Alerts' table")
print("   ✅ Blocked IPs should appear in 'Blocked IPs' section")
print("   ✅ Stats should update")
print("\n" + "="*70)