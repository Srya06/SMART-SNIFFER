"""
Enhanced Intrusion Detection System with Alert Deduplication
"""
from datetime import datetime, timedelta
from collections import defaultdict, deque

class IntrusionDetectionSystem:
    def __init__(self, config):
        self.config = config
        self.alert_count = 0
        
        # Detection data structures
        self.port_scan_data = defaultdict(lambda: deque(maxlen=100))
        self.dos_data = defaultdict(lambda: deque(maxlen=200))
        self.brute_force_data = defaultdict(lambda: defaultdict(int))
        
        # Alert cooldown tracking
        self.alert_cooldown = {}  # {alert_key: last_trigger_time}
        self.cooldown_period = 60
        
        # Load blacklist
        self.blacklist = self._load_blacklist()
    
    def _load_blacklist(self):
        """Load blacklisted IPs"""
        blacklisted_ips = [
            '10.0.0.100',
            '192.168.1.200', 
            '203.0.113.50',
            '198.51.100.25'
        ]
        return set(blacklisted_ips)
    
    def _should_trigger_alert(self, alert_type, src_ip, details=""):
        """Check if we should trigger alert (prevent duplicates)"""
        alert_key = f"{alert_type}_{src_ip}_{details}"
        current_time = datetime.now()
        
        # Check cooldown
        if alert_key in self.alert_cooldown:
            last_trigger = self.alert_cooldown[alert_key]
            if current_time - last_trigger < timedelta(seconds=self.cooldown_period):
                return False  # Still in cooldown
        
        # Update cooldown
        self.alert_cooldown[alert_key] = current_time
        return True
        
    def process_packet(self, packet):
        """Process packet through all detection rules"""
        alerts = []
        
        if 'src_ip' not in packet:
            return alerts
            
        src_ip = packet['src_ip']
        
        # Rule 1: Port Scan Detection
        alert = self._detect_port_scan(packet, src_ip)
        if alert:
            alerts.append(alert)
            
        # Rule 2: DoS Detection  
        alert = self._detect_dos(packet, src_ip)
        if alert:
            alerts.append(alert)
            
        # Rule 3: Brute Force Detection
        alert = self._detect_brute_force(packet, src_ip)
        if alert:
            alerts.append(alert)
            
        # Rule 4: Blacklist Detection
        alert = self._detect_blacklist(packet, src_ip)
        if alert:
            alerts.append(alert)
            
        return alerts
    
    def _detect_port_scan(self, packet, src_ip):
        """Detect port scanning activity with cooldown"""
        if packet.get('proto_name') == 'TCP' and packet.get('flags') == 'S':
            current_time = datetime.now()
            dst_port = packet.get('dst_port')
            
            # Record the scan attempt
            self.port_scan_data[src_ip].append({
                'time': current_time,
                'dst_port': dst_port
            })
            
            # Check last 30 seconds
            time_threshold = current_time - timedelta(seconds=30)
            recent_scans = [
                scan for scan in self.port_scan_data[src_ip]
                if scan['time'] > time_threshold
            ]
            
            # Count unique ports
            unique_ports = len(set(scan['dst_port'] for scan in recent_scans))
            
            if unique_ports >= 10:  # Lowered threshold for demo
                if self._should_trigger_alert('PORT_SCAN', src_ip, f"ports_{unique_ports}"):
                    self.alert_count += 1
                    return {
                        'id': self.alert_count,
                        'type': 'PORT_SCAN',
                        'src_ip': src_ip,
                        'timestamp': current_time.isoformat(),
                        'severity': 'HIGH',
                        'details': f'Port scan detected: {unique_ports} unique ports in 30 seconds'
                    }
        return None
    
    def _detect_dos(self, packet, src_ip):
        """Detect DoS attacks with cooldown"""
        current_time = datetime.now()
        
        # Record packet
        self.dos_data[src_ip].append(current_time)
        
        # Check last 10 seconds
        time_threshold = current_time - timedelta(seconds=10)
        recent_packets = [
            ts for ts in self.dos_data[src_ip]
            if ts > time_threshold
        ]
        
        if len(recent_packets) >= 30:  # Lowered threshold for demo
            if self._should_trigger_alert('DOS_ATTEMPT', src_ip):
                self.alert_count += 1
                return {
                    'id': self.alert_count,
                    'type': 'DOS_ATTEMPT',
                    'src_ip': src_ip,
                    'timestamp': current_time.isoformat(),
                    'severity': 'HIGH',
                    'details': f'Potential DoS: {len(recent_packets)} packets in 10 seconds'
                }
        return None
    
    def _detect_brute_force(self, packet, src_ip):
        """Detect brute force attacks with cooldown"""
        dst_port = packet.get('dst_port')
        
        # Common service ports
        service_ports = [21, 22, 23, 3389]  # FTP, SSH, Telnet, RDP
        
        if dst_port in service_ports and packet.get('proto_name') == 'TCP':
            if packet.get('flags') == 'S':  # Connection attempt
                current_time = datetime.now()
                minute_key = current_time.strftime('%Y-%m-%d %H:%M')
                key = f"{src_ip}_{dst_port}_{minute_key}"
                
                self.brute_force_data[key] += 1
                
                if self.brute_force_data[key] >= 3:  # Lowered threshold for demo
                    if self._should_trigger_alert('BRUTE_FORCE', src_ip, f"port_{dst_port}"):
                        self.alert_count += 1
                        return {
                            'id': self.alert_count,
                            'type': 'BRUTE_FORCE',
                            'src_ip': src_ip,
                            'timestamp': current_time.isoformat(),
                            'severity': 'MEDIUM',
                            'details': f'Brute force attempt on port {dst_port}: {self.brute_force_data[key]} attempts this minute'
                        }
        return None
    
    def _detect_blacklist(self, packet, src_ip):
        """Detect blacklisted IPs with cooldown"""
        if src_ip in self.blacklist:
            if self._should_trigger_alert('BLACKLISTED_IP', src_ip):
                self.alert_count += 1
                return {
                    'id': self.alert_count,
                    'type': 'BLACKLISTED_IP',
                    'src_ip': src_ip,
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'HIGH',
                    'details': f'Traffic from blacklisted IP address'
                }
        return None