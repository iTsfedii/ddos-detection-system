from flask import Flask, jsonify
from sniffer import NetworkSniffer
import threading
import time

app = Flask(__name__)
sniffer = None

@app.route('/api/stats', methods=['GET'])
def get_stats():
    if not sniffer:
        return jsonify({'error': 'Sniffer not initialized'}), 500
    
    stats = sniffer.calculate_stats()
    return jsonify(stats)

@app.route('/api/packets', methods=['GET'])
def get_packets():
    if not sniffer:
        return jsonify({'error': 'Sniffer not initialized'}), 500
    
    packets = sniffer.get_packet_history(limit=100)
    return jsonify({'packets': packets})

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'}), 200

def start_sniffer():
    global sniffer
    sniffer = NetworkSniffer()
    sniffer.start()

if __name__ == '__main__':
    print("=" * 50)
    print("DDoS Detection System - Sprint 1")
    print("=" * 50)
    print("\n[INFO] Starting Network Sniffer...")
    print("[INFO] NOTE: This requires Administrator privileges!")
    print("[INFO] On Windows: Run as Administrator\n")
    
    start_sniffer()
    time.sleep(2)
    
    print("[API] Starting Flask server on http://localhost:5000")
    print("[API] Available endpoints:")
    print("  - http://localhost:5000/api/stats")
    print("  - http://localhost:5000/api/packets")
    print("  - http://localhost:5000/health")
    print("\n[INFO] Press Ctrl+C to stop\n")
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=False)
    except KeyboardInterrupt:
        print("\n[API] Shutting down...")
        sniffer.stop()