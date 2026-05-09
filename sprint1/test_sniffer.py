import time
from sniffer import NetworkSniffer

def test_sniffer():
    print("[TEST] Starting Sniffer Test...")
    
    sniffer = NetworkSniffer()
    sniffer.start()
    
    print("[TEST] Sniffer running... collecting data for 10 seconds")
    
    for i in range(10):
        time.sleep(1)
        stats = sniffer.calculate_stats()
        print(f"[{i+1}s] RPS: {stats['rps']:.2f} | Unique IPs: {stats['unique_ips']} | Packets: {stats['total_packets']}")
    
    sniffer.stop()
    print("[TEST] Test complete!")

if __name__ == '__main__':
    test_sniffer()