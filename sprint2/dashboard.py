import sys
import os
import json

# Add paths for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'sprint1'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'sprint3'))

from flask import Flask, render_template, jsonify
from sniffer import NetworkSniffer
from detector import AnomalyDetector
from alerter import AlertSystem
import threading
import time
from datetime import datetime

app = Flask(__name__)

# File path for shared data
SHARED_FILE = os.path.join(os.path.dirname(__file__), '..', 'sprint3', 'shared_data.json')

# Initialize components
print("="*70)
print("🛡️  DDoS Detection System - Dashboard")
print("="*70)
print("\n[INIT] Initializing components...\n")

sniffer = NetworkSniffer()
detector = AnomalyDetector()
alerter = AlertSystem()

print("  ✅ Sniffer initialized")
print("  ✅ Detector initialized")
print("  ✅ Alerter initialized\n")

# Global data storage
alerts = []
blocked_ips = []

def load_shared_data():
    """Load data from shared file written by test"""
    global blocked_ips, alerts
    try:
        if os.path.exists(SHARED_FILE):
            with open(SHARED_FILE, 'r') as f:
                data = json.load(f)
                blocked_ips = data.get('blocked_ips', [])
                # Keep alerts from both sources
                test_alerts = data.get('alerts', [])
                if test_alerts:
                    for alert in test_alerts:
                        if alert not in alerts:
                            alerts.insert(0, alert)
                            if len(alerts) > 100:
                                alerts.pop()
    except Exception as e:
        print(f"[ERROR] Failed to load shared data: {e}")

def monitoring_loop():
    """Main monitoring loop"""
    global alerts
    
    while True:
        try:
            # Load shared data from test
            load_shared_data()
            
            stats = sniffer.calculate_stats()
            
            # Detect anomalies
            new_alerts = detector.detect_anomalies(stats)
            
            # Process each alert
            for alert in new_alerts:
                # Send alert
                alerter.send_alert(alert)
                
                # Add to alerts list
                alert['timestamp'] = datetime.now().strftime('%H:%M:%S')
                alerts.insert(0, alert)
                if len(alerts) > 100:
                    alerts.pop()
            
            time.sleep(1)
        
        except Exception as e:
            print(f"[ERROR] {e}")
            time.sleep(1)

@app.route('/')
def index():
    """Serve main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get network statistics"""
    try:
        stats = sniffer.calculate_stats()
        return jsonify({
            'status': 'success',
            'rps': round(stats.get('rps', 0), 2),
            'unique_ips': stats.get('unique_ips', 0),
            'total_packets': stats.get('total_packets', 0),
            'protocols': stats.get('protocols', {}),
            'top_ips': [{'ip': ip, 'packets': count} for ip, count in stats.get('top_ips', [])],
            'top_ports': [{'port': port, 'packets': count} for port, count in stats.get('top_ports', [])],
            'blocked_count': len(blocked_ips),
            'baseline_rps': round(stats.get('baseline_rps', 0), 2) if stats.get('baseline_rps') else 0,
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get recent alerts"""
    try:
        load_shared_data()
        return jsonify({
            'status': 'success',
            'alerts': alerts,
            'total': len(alerts)
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    """Get blocking metrics"""
    try:
        load_shared_data()
        return jsonify({
            'status': 'success',
            'metrics': {
                'total_blocked': len(blocked_ips),
                'blocked_today': len(blocked_ips),
                'by_type': {'SINGLE_IP_FLOODING': len([ip for ip in blocked_ips])},
                'by_severity': {'CRITICAL': len([ip for ip in blocked_ips])}
            }
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/blocked-ips', methods=['GET'])
def get_blocked_ips_endpoint():
    """Get list of blocked IPs"""
    try:
        load_shared_data()
        return jsonify({
            'status': 'success',
            'blocked_ips': blocked_ips,
            'total_blocked': len(blocked_ips)
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/system-status', methods=['GET'])
def system_status():
    """Get system status"""
    try:
        load_shared_data()
        if len(alerts) > 10:
            status = 'ATTACK'
            color = 'red'
        elif len(alerts) > 3:
            status = 'WARNING'
            color = 'orange'
        else:
            status = 'NORMAL'
            color = 'green'
        
        return jsonify({
            'status': status,
            'color': color,
            'alert_count': len(alerts),
            'blocked_count': len(blocked_ips)
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    print("[MONITORING] Starting monitoring thread...")
    
    # Start sniffer
    try:
        sniffer.start()
        time.sleep(2)
    except Exception as e:
        print(f"[WARNING] Sniffer error: {e}")
    
    # Start monitoring in background
    monitor_thread = threading.Thread(target=monitoring_loop, daemon=True)
    monitor_thread.start()
    
    print("[MONITORING] ✅ Thread started\n")
    print("="*70)
    print("[DASHBOARD] 🌐 Web server starting...")
    print("[DASHBOARD] 📱 Open browser: http://localhost:5000")
    print("="*70 + "\n")
    
    app.run(debug=False, host='localhost', port=5000, use_reloader=False)