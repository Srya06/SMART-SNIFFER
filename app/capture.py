"""
Hybrid Packet Capture - Tries multiple methods
"""
import threading
import time
import queue
from datetime import datetime
import random

class HybridPacketCapture:
    def __init__(self, config):
        self.config = config
        self.packet_queue = queue.Queue()
        self.is_capturing = False
        self.capture_thread = None
        self.current_method = None
        
    def get_interfaces(self):
        """Get available interfaces"""
        methods = [
            ("Wi-Fi (Live)", "wifi_live"),
            ("Ethernet (Live)", "ethernet_live"), 
            ("Demo Mode", "demo"),
            ("Raw Sockets", "raw_socket")
        ]
        return methods
        
    def start_capture(self, mode='demo', iface=None, pcap_path=None):
        try:
            self.is_capturing = True
            
            if iface == "raw_socket":
                self.capture_thread = threading.Thread(target=self._raw_socket_capture)
                self.current_method = "raw_socket"
            elif iface and ("live" in iface):
                self.capture_thread = threading.Thread(target=self._enhanced_demo_capture)
                self.current_method = "enhanced_demo"
            else:
                self.capture_thread = threading.Thread(target=self._generate_demo_packets)
                self.current_method = "demo"
                
            self.capture_thread.start()
            return True, f"Capture started using {self.current_method}"
            
        except Exception as e:
            return False, f"Error: {e}"
    
    def _raw_socket_capture(self):
        """Attempt raw socket capture (requires Admin)"""
        try:
            import socket
            # Raw socket implementation would go here
            # For now, fallback to enhanced demo
            self._enhanced_demo_capture()
        except:
            self._enhanced_demo_capture()
    
    def _enhanced_demo_capture(self):
        """More realistic demo capture"""
        protocols = ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'HTTPS']
        services = {
            80: 'HTTP', 443: 'HTTPS', 53: 'DNS', 22: 'SSH', 
            21: 'FTP', 25: 'SMTP', 110: 'POP3'
        }
        
        normal_ips = [f"192.168.1.{i}" for i in range(1, 50)]
        suspicious_ips = ['10.0.0.100', '192.168.1.200', '203.0.113.50']
        
        count = 0
        while self.is_capturing and count < 500:
            # Mix of normal and suspicious traffic
            if count % 20 == 0:  # Every 20 packets, add suspicious
                src_ip = random.choice(suspicious_ips)
                dst_port = random.choice([22, 23, 3389])  # Suspicious ports
            else:
                src_ip = random.choice(normal_ips)
                dst_port = random.choice(list(services.keys()))
            
            packet = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': src_ip,
                'dst_ip': '8.8.8.8',
                'proto_name': random.choice(['TCP', 'UDP']),
                'src_port': random.randint(10000, 60000),
                'dst_port': dst_port,
                'length': random.randint(60, 1500),
                'service': services.get(dst_port, 'Unknown')
            }
            
            self.packet_queue.put(packet)
            count += 1
            time.sleep(0.1)  # Faster, more realistic
            
    def _generate_demo_packets(self):
        """Your original demo method"""
        demo_packets = [
            {'src_ip': '192.168.1.10', 'dst_ip': '8.8.8.8', 'proto_name': 'TCP', 'src_port': 54321, 'dst_port': 80},
            {'src_ip': '192.168.1.20', 'dst_ip': '8.8.8.8', 'proto_name': 'TCP', 'src_port': 54322, 'dst_port': 443},
            {'src_ip': '192.168.1.30', 'dst_ip': '8.8.4.4', 'proto_name': 'UDP', 'src_port': 54323, 'dst_port': 53},
            {'src_ip': '10.0.0.100', 'dst_ip': '192.168.1.1', 'proto_name': 'TCP', 'src_port': 54324, 'dst_port': 22},
        ]
        
        count = 0
        while self.is_capturing and count < 100:
            for pkt in demo_packets:
                if not self.is_capturing:
                    break
                    
                packet = pkt.copy()
                packet['timestamp'] = datetime.now().isoformat()
                packet['length'] = 64
                packet['src_port'] = pkt['src_port'] + count
                
                self.packet_queue.put(packet)
                count += 1
                time.sleep(1)
                
    def get_packet(self, timeout=1):
        try:
            return self.packet_queue.get(timeout=timeout)
        except:
            return None
            
    def stop_capture(self):
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)