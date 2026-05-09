import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP

class NetworkSniffer:
    def __init__(self, interface=None, packet_history_size=10000):
        self.interface = interface or 'Ethernet'
        self.packet_history = deque(maxlen=packet_history_size)
        self.stats = {
            'rps': 0,
            'unique_ips': set(),
            'unique_ports': set(),
            'protocol_count': defaultdict(int),
            'ip_packet_count': defaultdict(int),
            'port_packet_count': defaultdict(int),
        }
        self.baseline_rps = None
        self.learning_phase = True
        self.learning_duration = 60
        self.learning_start_time = time.time()
        self.packet_count = 0
        self.lock = threading.Lock()
        self.running = False

    def packet_callback(self, packet):
        if not IP in packet:
            return

        try:
            with self.lock:
                self.packet_count += 1
                src_ip = packet[IP].src
                protocol = packet[IP].proto
                packet_size = len(packet)
                timestamp = datetime.now().isoformat()
                
                dst_port = None
                if TCP in packet:
                    dst_port = packet[TCP].dport
                    protocol_name = 'TCP'
                elif UDP in packet:
                    dst_port = packet[UDP].dport
                    protocol_name = 'UDP'
                elif ICMP in packet:
                    protocol_name = 'ICMP'
                else:
                    protocol_name = 'OTHER'
                
                packet_data = {
                    'src_ip': src_ip,
                    'dst_port': dst_port,
                    'protocol': protocol_name,
                    'size': packet_size,
                    'timestamp': timestamp,
                }
                self.packet_history.append(packet_data)
                
                self.stats['unique_ips'].add(src_ip)
                if dst_port:
                    self.stats['unique_ports'].add(dst_port)
                self.stats['protocol_count'][protocol_name] += 1
                self.stats['ip_packet_count'][src_ip] += 1
                if dst_port:
                    self.stats['port_packet_count'][dst_port] += 1
                
                if self.learning_phase:
                    elapsed = time.time() - self.learning_start_time
                    if elapsed >= self.learning_duration:
                        self.baseline_rps = self.packet_count / self.learning_duration
                        self.learning_phase = False
                        print(f"[SNIFFER] Learning complete. Baseline RPS: {self.baseline_rps:.2f}")
        except Exception as e:
            print(f"[ERROR] Error processing packet: {e}")

    def calculate_stats(self):
        with self.lock:
            current_time = time.time()
            if not hasattr(self, 'last_stat_time'):
                self.last_stat_time = current_time
                self.last_packet_count = 0
            
            time_diff = current_time - self.last_stat_time
            if time_diff >= 1:
                packets_in_interval = self.packet_count - self.last_packet_count
                self.stats['rps'] = packets_in_interval / time_diff if time_diff > 0 else 0
                
                self.last_stat_time = current_time
                self.last_packet_count = self.packet_count
            
            return {
                'rps': self.stats['rps'],
                'unique_ips': len(self.stats['unique_ips']),
                'unique_ports': len(self.stats['unique_ports']),
                'total_packets': self.packet_count,
                'top_ips': self._get_top_items(self.stats['ip_packet_count'], 10),
                'top_ports': self._get_top_items(self.stats['port_packet_count'], 10),
                'protocols': dict(self.stats['protocol_count']),
                'baseline_rps': self.baseline_rps,
                'learning_phase': self.learning_phase,
            }

    def _get_top_items(self, counter, limit=10):
        return sorted(counter.items(), key=lambda x: x[1], reverse=True)[:limit]

    def get_packet_history(self, limit=100):
        with self.lock:
            return list(self.packet_history)[-limit:]

    def start(self):
        self.running = True
        
        def sniff_packets():
            print(f"[SNIFFER] Starting on interface: {self.interface}")
            try:
                sniff(
                    iface=self.interface,
                    prn=self.packet_callback,
                    store=False,
                    stop_filter=lambda x: not self.running
                )
            except PermissionError:
                print("[ERROR] Admin privileges required to capture packets!")
                print("[INFO] Run as Administrator on Windows")
            except Exception as e:
                print(f"[ERROR] Sniffer error: {e}")

        sniffer_thread = threading.Thread(target=sniff_packets, daemon=True)
        sniffer_thread.start()
        print("[SNIFFER] Sniffer started successfully")

    def stop(self):
        self.running = False
        print("[SNIFFER] Sniffer stopped")