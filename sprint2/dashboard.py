from flask import Flask, render_template, jsonify
import sys
import os

# Fix the import path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sprint1_folder = os.path.join(project_root, 'sprint1')
sys.path.insert(0, sprint1_folder)

# Import Sprint 3 modules
sprint3_path = os.path.join(project_root, 'sprint3')
sys.path.insert(0, sprint3_path)
from blocker import IPBlocker
from response_manager import ResponseManager
from metrics import BlockingMetrics

# Now import from sprint1
from sniffer import NetworkSniffer
from detector import AnomalyDetector
from alerter import AlertSystem

import threading
import time

app = Flask(__name__, template_folder='templates')

# Global variables
sniffer = None
detector = None
alerter = None
blocker = None
response_manager = None
metrics = None
blocked_ips = []

# ============= ROUTES =============

@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get network statistics"""
    if not sniffer:
        return jsonify({'error': 'Not ready'}), 500
    
    stats = sniffer.calculate_stats()
    # Convert tuples to lists for JSON
    stats['top_ips'] = [(ip, count) for ip, count in stats['top_ips']]
    stats['top_ports'] = [(port, count) for port, count in stats['top_ports']]
    
    return jsonify(stats)

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get recent alerts"""
    if not alerter:
        return jsonify({'alerts': []})
    
    alerts = alerter.get_recent_alerts(limit=50)
    return jsonify({'alerts': alerts})

@app.route('/api/blocked-ips', methods=['GET'])
def get_blocked_ips():
    """Get list of blocked IPs"""
    if not blocker:
        return jsonify({'blocked_ips': []})
    return jsonify({'blocked_ips': blocker.get_blocked_ips()})

@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    """Get blocking metrics"""
    if not metrics:
        return jsonify({'metrics': {}})
    return jsonify({'metrics': metrics.get_metrics()})

@app.route('/api/responses', methods=['GET'])
def get_responses():
    """Get response history"""
    if not response_manager:
        return jsonify({'responses': []})
    responses = response_manager.get_responses(limit=50)
    return jsonify({'responses': responses})

@app.route('/api/system-status', methods=['GET'])
def get_system_status():
    """Get overall system status"""
    alerts = alerter.get_recent_alerts(limit=10) if alerter else []
    
    status = 'MONITORING'
    if any(a['severity'] == 'CRITICAL' for a in alerts[-5:]):
        status = 'ATTACK'
    elif any(a['severity'] == 'HIGH' for a in alerts[-5:]):
        status = 'WARNING'
    
    blocked_count = blocker.get_blocked_ips() if blocker else []
    
    return jsonify({
        'status': status,
        'blocked_ips_count': len(blocked_count),
        'recent_alerts_count': len(alerts)
    })

# ============= BACKGROUND TASKS =============

def monitoring_loop():
    """Background thread that monitors traffic and detects anomalies"""
    print("[MONITORING] Starting monitoring loop...")
    
    while True:
        try:
            # Get current statistics from sniffer
            stats = sniffer.calculate_stats()
            
            # Detect anomalies
            alerts = detector.detect_anomalies(stats)
            
            # Send alerts and take response actions
            for alert in alerts:
                alerter.send_alert(alert)
                
                # Handle response (Sprint 3)
                response = response_manager.handle_alert(alert)
                
                # Record metrics
                if response['ips_blocked']:
                    for ip in response['ips_blocked']:
                        metrics.record_block(
                            alert['type'],
                            alert['severity'],
                            ip
                        )
            
            # Wait before next check
            time.sleep(10)
        except Exception as e:
            print(f"[ERROR] Monitoring error: {e}")
            time.sleep(5)

def start_modules():
    """Initialize all modules"""
    global sniffer, detector, alerter, blocker, response_manager, metrics
    
    print("[INIT] Initializing modules...")
    
    # Start sniffer
    sniffer = NetworkSniffer()
    sniffer.start()
    time.sleep(2)
    
    # Start detector and alerter
    detector = AnomalyDetector()
    alerter = AlertSystem()
    
    # Start Sprint 3 modules
    blocker = IPBlocker()
    response_manager = ResponseManager(blocker)
    metrics = BlockingMetrics()
    
    # Start monitoring thread
    monitor_thread = threading.Thread(target=monitoring_loop, daemon=True)
    monitor_thread.start()
    
    print("[INIT] All modules initialized!")

# ============= MAIN =============

if __name__ == '__main__':
    print("=" * 60)
    print("DDoS Detection System - Sprint 3 Dashboard")
    print("=" * 60)
    print("\n[INFO] This requires Administrator privileges!")
    print("[INFO] On Windows: Right-click CMD → Run as Administrator\n")
    
    # Initialize modules
    start_modules()
    
    # Start web server
    print("[DASHBOARD] Starting web server on http://localhost:5000")
    print("[DASHBOARD] Open in browser: http://localhost:5000\n")
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
    except KeyboardInterrupt:
        print("\n[DASHBOARD] Shutting down...")
        sniffer.stop()
