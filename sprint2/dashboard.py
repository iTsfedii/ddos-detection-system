from flask import Flask, render_template, jsonify
import sys
import os

# Fix the import path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sprint1_folder = os.path.join(project_root, 'sprint1')
sys.path.insert(0, sprint1_folder)

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
    return jsonify({'blocked_ips': blocked_ips})

@app.route('/api/system-status', methods=['GET'])
def get_system_status():
    """Get overall system status"""
    alerts = alerter.get_recent_alerts(limit=10) if alerter else []
    
    status = 'MONITORING'
    if any(a['severity'] == 'CRITICAL' for a in alerts[-5:]):
        status = 'ATTACK'
    elif any(a['severity'] == 'HIGH' for a in alerts[-5:]):
        status = 'WARNING'
    
    return jsonify({
        'status': status,
        'blocked_ips_count': len(blocked_ips),
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
            
            # Send alerts
            for alert in alerts:
                alerter.send_alert(alert)
            
            # Wait before next check
            time.sleep(10)
        except Exception as e:
            print(f"[ERROR] Monitoring error: {e}")
            time.sleep(5)

def start_modules():
    """Initialize all modules"""
    global sniffer, detector, alerter
    
    print("[INIT] Initializing modules...")
    
    # Start sniffer
    sniffer = NetworkSniffer()
    sniffer.start()
    time.sleep(2)
    
    # Start detector and alerter
    detector = AnomalyDetector()
    alerter = AlertSystem()
    
    # Start monitoring thread
    monitor_thread = threading.Thread(target=monitoring_loop, daemon=True)
    monitor_thread.start()
    
    print("[INIT] All modules initialized!")

# ============= MAIN =============

if __name__ == '__main__':
    print("=" * 60)
    print("DDoS Detection System - Sprint 2 Dashboard")
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