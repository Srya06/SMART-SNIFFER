"""
Simple Analytics
"""
class NetworkAnalytics:
    def __init__(self, config):
        self.config = config
        self.reset()
        
    def reset(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.protocols = {}
        
    def process_packet(self, packet):
        self.total_packets += 1
        self.total_bytes += packet.get('length', 0)
        proto = packet.get('proto_name', 'Unknown')
        self.protocols[proto] = self.protocols.get(proto, 0) + 1
        
    def get_snapshot(self):
        return {
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'protocols': self.protocols,
            'packets_per_second': [],
            'top_src_ips': [],
            'top_dst_ports': [],
            'avg_packet_size': self.total_bytes / max(self.total_packets, 1)
        }
