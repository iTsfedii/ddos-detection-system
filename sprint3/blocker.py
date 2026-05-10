import subprocess
import threading
from datetime import datetime
from collections import defaultdict

class IPBlocker:
    def __init__(self):
        self.blocked_ips = set()
        self.block_history = []
        self.lock = threading.Lock()
        self.max_history = 1000

    def block_ip(self, ip, reason="DDoS Attack"):
        """Block an IP using Windows Firewall"""
        if ip in self.blocked_ips:
            return False
        
        try:
            with self.lock:
                # Add firewall rule
                rule_name = f"Block_{ip.replace('.', '_')}"
                
                cmd = [
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name={rule_name}',
                    'dir=in',
                    'action=block',
                    f'remoteip={ip}',
                    'protocol=any'
                ]
                
                subprocess.run(cmd, capture_output=True, timeout=5)
                
                self.blocked_ips.add(ip)
                
                # Log the block
                block_record = {
                    'ip': ip,
                    'reason': reason,
                    'timestamp': datetime.now().isoformat(),
                    'status': 'BLOCKED'
                }
                self.block_history.append(block_record)
                
                if len(self.block_history) > self.max_history:
                    self.block_history.pop(0)
                
                print(f"[BLOCKER] Blocked IP: {ip} - Reason: {reason}")
                return True
        except Exception as e:
            print(f"[ERROR] Failed to block IP {ip}: {e}")
            return False

    def unblock_ip(self, ip):
        """Unblock an IP"""
        if ip not in self.blocked_ips:
            return False
        
        try:
            with self.lock:
                rule_name = f"Block_{ip.replace('.', '_')}"
                
                cmd = [
                    'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                    f'name={rule_name}'
                ]
                
                subprocess.run(cmd, capture_output=True, timeout=5)
                
                self.blocked_ips.remove(ip)
                
                print(f"[BLOCKER] Unblocked IP: {ip}")
                return True
        except Exception as e:
            print(f"[ERROR] Failed to unblock IP {ip}: {e}")
            return False

    def get_blocked_ips(self):
        """Get list of blocked IPs"""
        with self.lock:
            return list(self.blocked_ips)

    def get_block_history(self, limit=100):
        """Get block history"""
        with self.lock:
            return self.block_history[-limit:]

    def is_blocked(self, ip):
        """Check if IP is blocked"""
        return ip in self.blocked_ips