"""
Smart Sniffer - Network Packet Capture & IDS
Streamlit Dashboard for Windows
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import yaml
import sys
import os
from datetime import datetime
import time
import random

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Page configuration
st.set_page_config(
    page_title="Smart Sniffer",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load configuration
def load_config():
    try:
        with open('config/config.yaml', 'r') as f:
            return yaml.safe_load(f)
    except:
        # Create config directory if it doesn't exist
        os.makedirs('config', exist_ok=True)
        # Create default config
        default_config = {
            'capture': {'packet_count': 1000},
            'ids': {
                'port_scan': {'enabled': True, 'threshold': 10, 'window_seconds': 30},
                'dos_flood': {'enabled': True, 'threshold': 50, 'window_seconds': 10},
                'brute_force': {'enabled': True, 'threshold': 5, 'window_seconds': 60, 'ports': [21, 22, 23]},
                'blacklist': {'enabled': True, 'file': 'config/blacklist.txt'}
            },
            'storage': {'max_alerts_display': 100},
            'ui': {'refresh_interval': 1, 'max_packets_display': 100}
        }
        # Save default config
        with open('config/config.yaml', 'w') as f:
            yaml.dump(default_config, f)
        st.success("✅ Created default config file!")
        return default_config

config = load_config()

# Load blacklist function
def load_blacklist():
    """Load blacklisted IP addresses from file"""
    blacklist_file = 'config/blacklist.txt'
    blacklisted_ips = []
    
    try:
        # Create config directory if it doesn't exist
        os.makedirs('config', exist_ok=True)
        
        # Create blacklist file if it doesn't exist
        if not os.path.exists(blacklist_file):
            default_blacklist = """# Smart Sniffer Blacklist
# Add suspicious/malicious IP addresses here (one per line)

10.0.0.100
192.168.1.200
172.16.0.50

# Add any IPs you want to block or monitor
"""
            with open(blacklist_file, 'w') as f:
                f.write(default_blacklist)
            st.success("✅ Created default blacklist file!")
        
        # Read the blacklist
        with open(blacklist_file, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith('#'):
                    blacklisted_ips.append(line)
        
        return blacklisted_ips
        
    except Exception as e:
        st.warning(f"⚠️ Could not load blacklist: {e}")
        # Return default blacklisted IPs
        return ['10.0.0.100', '192.168.1.200', '172.16.0.50']

# Initialize session state
if 'packets' not in st.session_state:
    st.session_state.packets = []
if 'alerts' not in st.session_state:
    st.session_state.alerts = []
if 'is_capturing' not in st.session_state:
    st.session_state.is_capturing = False
if 'selected_interface' not in st.session_state:
    st.session_state.selected_interface = "Demo Mode"
if 'capture_start_time' not in st.session_state:
    st.session_state.capture_start_time = None

# Demo packet generator with more realistic data
def generate_demo_packet():
    """Generate a single demo packet"""
    services = {80: 'HTTP', 443: 'HTTPS', 53: 'DNS', 22: 'SSH', 21: 'FTP', 25: 'SMTP', 110: 'POP3', 143: 'IMAP'}
    normal_ips = [f"192.168.1.{i}" for i in range(1, 50)] + [f"10.0.0.{i}" for i in range(1, 20)]
    
    # Load blacklist for realistic traffic generation
    blacklisted_ips = load_blacklist()
    # Ensure we always have some suspicious IPs
    suspicious_ips = blacklisted_ips if blacklisted_ips else ['10.0.0.100', '192.168.1.200', '172.16.0.50']
    
    # Mix normal and suspicious traffic (15% suspicious)
    if random.random() < 0.15:
        src_ip = random.choice(suspicious_ips)
        # Suspicious ports for scanning/attacks
        dst_port = random.choice([22, 23, 3389, 445, 135, 1433, 3306])
        proto_name = 'TCP'
    else:
        src_ip = random.choice(normal_ips)
        dst_port = random.choice(list(services.keys()))
        proto_name = random.choice(['TCP', 'UDP'])
    
    return {
        'timestamp': datetime.now().isoformat(),
        'src_ip': src_ip,
        'dst_ip': f"192.168.1.{random.randint(1, 254)}",
        'proto_name': proto_name,
        'src_port': random.randint(10000, 60000),
        'dst_port': dst_port,
        'length': random.randint(60, 1500),
        'service': services.get(dst_port, 'Unknown'),
        'protocol': proto_name
    }

# Generate demo alerts
def generate_demo_alerts():
    """Generate realistic demo alerts"""
    alert_types = ['PORT_SCAN', 'DOS_ATTEMPT', 'BRUTE_FORCE', 'SUSPICIOUS_ACTIVITY', 'BLACKLISTED_IP']
    
    # Load blacklist for realistic detection
    blacklisted_ips = load_blacklist()
    # Ensure we always have some IPs to work with
    if not blacklisted_ips:
        blacklisted_ips = ['10.0.0.100', '192.168.1.200', '172.16.0.50']
    
    sources = blacklisted_ips + ['203.0.113.15', '198.51.100.25']  # Add some extra IPs
    
    alerts = []
    
    # Generate port scan alerts (from blacklisted IPs)
    for _ in range(random.randint(2, 6)):
        src_ip = random.choice(blacklisted_ips)  # Use any blacklisted IP
        alerts.append({
            'type': 'PORT_SCAN',
            'src_ip': src_ip,
            'dst_ip': '192.168.1.1',
            'dst_port': random.randint(20, 5000),
            'timestamp': datetime.now().isoformat(),
            'severity': 'HIGH',
            'details': f'Port scanning activity detected on port {random.randint(20, 5000)}',
            'id': f"alert_{random.randint(1000, 9999)}"
        })
    
    # Generate blacklisted IP alerts
    for _ in range(random.randint(0, 2)):  # Occasionally generate blacklist alerts
        src_ip = random.choice(blacklisted_ips)
        alerts.append({
            'type': 'BLACKLISTED_IP',
            'src_ip': src_ip,
            'dst_ip': '192.168.1.1',
            'timestamp': datetime.now().isoformat(),
            'severity': 'HIGH',
            'details': f'Connection attempt from blacklisted IP: {src_ip}',
            'id': f"alert_{random.randint(1000, 9999)}"
        })
    
    # Generate other types of alerts
    for _ in range(random.randint(1, 3)):
        alert_type = random.choice(['DOS_ATTEMPT', 'BRUTE_FORCE', 'SUSPICIOUS_ACTIVITY'])
        # Use non-blacklisted IPs for other alerts, or fallback to any IP
        available_ips = [ip for ip in sources if ip not in blacklisted_ips]
        if not available_ips:
            available_ips = sources  # Fallback to all IPs if no non-blacklisted ones
        src_ip = random.choice(available_ips)
        alerts.append({
            'type': alert_type,
            'src_ip': src_ip,
            'dst_ip': '192.168.1.1',
            'timestamp': datetime.now().isoformat(),
            'severity': random.choice(['MEDIUM', 'HIGH']),
            'details': f'{alert_type.replace("_", " ").title()} detected from {src_ip}',
            'id': f"alert_{random.randint(1000, 9999)}"
        })
    
    return alerts

def process_packets():
    """Process packets when capture is running"""
    if st.session_state.is_capturing:
        # Generate demo packets (simulate capture)
        for _ in range(random.randint(2, 8)):
            packet = generate_demo_packet()
            st.session_state.packets.append(packet)
            
        # Occasionally generate alerts
        if random.random() < 0.3:  # 30% chance to generate alerts
            new_alerts = generate_demo_alerts()
            st.session_state.alerts.extend(new_alerts)

def group_port_scan_alerts(alerts):
    """
    Group multiple PORT_SCAN alerts from same source->destination
    """
    scan_groups = {}
    
    for alert in alerts:
        if alert.get('type') == 'PORT_SCAN':
            key = f"{alert.get('src_ip')}_{alert.get('dst_ip', 'unknown')}"
            
            if key not in scan_groups:
                scan_groups[key] = {
                    'src_ip': alert.get('src_ip'),
                    'dst_ip': alert.get('dst_ip', 'unknown'),
                    'ports': set(),
                    'count': 0,
                    'first_seen': alert.get('timestamp'),
                    'last_seen': alert.get('timestamp')
                }
            
            # Add destination port if available
            if alert.get('dst_port'):
                scan_groups[key]['ports'].add(alert.get('dst_port'))
            scan_groups[key]['count'] += 1
            scan_groups[key]['last_seen'] = alert.get('timestamp')
    
    # Convert to list for display
    grouped_alerts = []
    for group in scan_groups.values():
        grouped_alerts.append({
            'type': 'PORT_SCAN_GROUP',
            'message': f"PORT_SCAN - Source: {group['src_ip']} scanned {len(group['ports'])} ports on {group['dst_ip']}",
            'count': group['count'],
            'src_ip': group['src_ip'],
            'dst_ip': group['dst_ip'],
            'timestamp': group['last_seen'],
            'severity': 'HIGH'
        })
    
    return grouped_alerts

def main():
    st.title("🔍 Smart Sniffer - Network Packet Analyzer")
    st.markdown("Real-time packet capture and intrusion detection system")
    
    # Sidebar
    with st.sidebar:
        st.title("⚙️ Configuration")
        st.markdown("---")
        
        st.subheader("🎯 Capture Mode")
        
        # Interface selection
        st.session_state.selected_interface = st.selectbox(
            "Select Network Interface",
            ["Demo Mode", "Ethernet", "Wi-Fi", "Loopback"],
            index=0
        )
        
        st.markdown("---")
        
        # Capture controls
        st.subheader("🎮 Capture Controls")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🎬 Start Capture", type="primary", use_container_width=True):
                st.session_state.is_capturing = True
                st.session_state.capture_start_time = datetime.now()
                st.success("🚀 Demo capture started! Generating realistic network traffic...")
                        
        with col2:
            if st.button("⏹️ Stop Capture", use_container_width=True):
                st.session_state.is_capturing = False
                st.info("🛑 Capture stopped")
        
        st.markdown("---")
        
        # Blacklist Management
        st.subheader("🚫 Blacklist Management")
        
        # Show current blacklisted IPs
        blacklisted_ips = load_blacklist()
        if blacklisted_ips:
            st.write("**Currently Blacklisted:**")
            for ip in blacklisted_ips[:5]:  # Show first 5
                st.code(ip)
            if len(blacklisted_ips) > 5:
                st.write(f"... and {len(blacklisted_ips) - 5} more")
        else:
            st.info("No IPs in blacklist. Default IPs will be used for demo.")
        
        # Add IP to blacklist
        with st.expander("➕ Add IP to Blacklist"):
            new_ip = st.text_input("Enter IP address to blacklist:", placeholder="e.g., 192.168.1.100")
            if st.button("Add to Blacklist") and new_ip:
                # Simple IP validation
                if '.' in new_ip and len(new_ip.split('.')) == 4:
                    try:
                        with open('config/blacklist.txt', 'a') as f:
                            f.write(f"\n{new_ip}")
                        st.success(f"✅ Added {new_ip} to blacklist!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Error: {e}")
                else:
                    st.error("Please enter a valid IP address (e.g., 192.168.1.100)")
        
        # Clear blacklist button
        if st.button("🗑️ Clear Blacklist", use_container_width=True):
            try:
                with open('config/blacklist.txt', 'w') as f:
                    f.write("# Smart Sniffer Blacklist\n# Add suspicious/malicious IP addresses here\n\n")
                st.success("✅ Blacklist cleared!")
                st.rerun()
            except Exception as e:
                st.error(f"Error clearing blacklist: {e}")
        
        st.markdown("---")
        
        # Statistics
        st.subheader("📊 Live Statistics")
        
        # Count grouped alerts for statistics
        port_scan_alerts = [alert for alert in st.session_state.alerts if alert.get('type') == 'PORT_SCAN']
        other_alerts = [alert for alert in st.session_state.alerts if alert.get('type') != 'PORT_SCAN']
        grouped_port_scans = group_port_scan_alerts(port_scan_alerts)
        total_grouped_alerts = len(grouped_port_scans) + len(other_alerts)
        
        st.metric("📦 Total Packets", len(st.session_state.packets))
        st.metric("🚨 Security Alerts", total_grouped_alerts)
        
        if st.session_state.capture_start_time and st.session_state.is_capturing:
            capture_duration = datetime.now() - st.session_state.capture_start_time
            st.metric("⏱️ Capture Time", f"{int(capture_duration.total_seconds())}s")
        
        st.markdown("---")
        
        if st.button("🗑️ Clear All Data", use_container_width=True):
            st.session_state.packets.clear()
            st.session_state.alerts.clear()
            st.session_state.capture_start_time = None
            st.rerun()
    
    # Process packets if capturing
    if st.session_state.is_capturing:
        process_packets()
        time.sleep(1)  # Simulate real-time
        st.rerun()
    
    # Main content tabs
    tab1, tab2, tab3, tab4 = st.tabs(["📊 Dashboard", "📦 Packets", "🚨 Alerts", "📈 Analytics"])
    
    with tab1:
        st.header("🌐 Network Dashboard")
        
        # Live metrics
        col1, col2, col3, col4 = st.columns(4)
        
        # Count grouped alerts for statistics
        port_scan_alerts = [a for a in st.session_state.alerts if a.get('type') == 'PORT_SCAN']
        other_alerts = [a for a in st.session_state.alerts if a.get('type') != 'PORT_SCAN']
        grouped_port_scans = group_port_scan_alerts(port_scan_alerts)
        
        with col1:
            st.metric("📦 Total Packets", len(st.session_state.packets))
            st.metric("🚨 Total Alerts", len(grouped_port_scans) + len(other_alerts))
        
        with col2:
            tcp_count = sum(1 for p in st.session_state.packets if p.get('proto_name') == 'TCP')
            udp_count = sum(1 for p in st.session_state.packets if p.get('proto_name') == 'UDP')
            st.metric("🔗 TCP Packets", tcp_count)
            st.metric("📨 UDP Packets", udp_count)
        
        with col3:
            port_scans = len(grouped_port_scans)
            dos_attempts = sum(1 for a in st.session_state.alerts if a.get('type') == 'DOS_ATTEMPT')
            blacklisted_alerts = sum(1 for a in st.session_state.alerts if a.get('type') == 'BLACKLISTED_IP')
            st.metric("🔍 Port Scans", port_scans)
            st.metric("💥 DoS Attempts", dos_attempts)
        
        with col4:
            brute_force = sum(1 for a in st.session_state.alerts if a.get('type') == 'BRUTE_FORCE')
            suspicious = sum(1 for a in st.session_state.alerts if a.get('type') == 'SUSPICIOUS_ACTIVITY')
            st.metric("🔑 Brute Force", brute_force)
            st.metric("🚫 Blacklisted", blacklisted_alerts)
        
        # Live packet chart
        if st.session_state.packets:
            st.subheader("📈 Live Traffic Flow")
            
            # Show last 30 packets in a simple chart
            recent_packets = st.session_state.packets[-30:]
            times = [p['timestamp'][11:19] for p in recent_packets]
            
            # Create a more realistic traffic flow chart
            chart_data = pd.DataFrame({
                'Time': times,
                'Packet_Size': [p['length'] for p in recent_packets],
                'Protocol': [p['proto_name'] for p in recent_packets]
            })
            
            fig = px.line(chart_data, x='Time', y='Packet_Size', 
                         title='Real-time Packet Size Distribution',
                         color='Protocol')
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("🎯 Start capture to see live network traffic data...")
    
    with tab2:
        st.header("📦 Captured Packets")
        
        if st.session_state.packets:
            # Create dataframe for display
            display_data = []
            for packet in st.session_state.packets[-50:]:  # Show last 50 packets
                display_data.append({
                    'Timestamp': packet['timestamp'][11:19],
                    'Source IP': packet['src_ip'],
                    'Dest IP': packet['dst_ip'],
                    'Protocol': packet['proto_name'],
                    'Src Port': packet['src_port'],
                    'Dest Port': packet['dst_port'],
                    'Length': packet['length'],
                    'Service': packet.get('service', 'Unknown')
                })
            
            df = pd.DataFrame(display_data)
            
            # Enhanced dataframe with styling
            st.dataframe(
                df,
                use_container_width=True,
                height=400,
                column_config={
                    "Timestamp": st.column_config.TextColumn("🕒 Time"),
                    "Source IP": st.column_config.TextColumn("📡 Source"),
                    "Dest IP": st.column_config.TextColumn("🎯 Destination"),
                    "Protocol": st.column_config.TextColumn("🔗 Protocol"),
                    "Src Port": st.column_config.NumberColumn("🔢 Src Port"),
                    "Dest Port": st.column_config.NumberColumn("🎯 Dest Port"),
                    "Length": st.column_config.NumberColumn("📏 Length"),
                    "Service": st.column_config.TextColumn("🌐 Service")
                }
            )
            
            # Packet details
            st.subheader("🔍 Packet Details")
            if len(st.session_state.packets) > 0:
                selected_idx = st.slider(
                    "Select packet to inspect", 
                    0, 
                    len(st.session_state.packets)-1, 
                    len(st.session_state.packets)-1
                )
                if selected_idx < len(st.session_state.packets):
                    st.json(st.session_state.packets[selected_idx])
        else:
            st.info("📭 No packets captured yet. Click 'Start Capture' to begin monitoring network traffic.")
    
    with tab3:
        st.header("🚨 Security Alerts")
        
        if st.session_state.alerts:
            # Group port scan alerts
            port_scan_alerts = [alert for alert in st.session_state.alerts if alert.get('type') == 'PORT_SCAN']
            other_alerts = [alert for alert in st.session_state.alerts if alert.get('type') != 'PORT_SCAN']
            
            grouped_port_scans = group_port_scan_alerts(port_scan_alerts)
            
            # Combine grouped port scans with other alerts
            all_alerts_to_display = grouped_port_scans + other_alerts
            
            # Sort by timestamp (newest first)
            all_alerts_to_display.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            
            # Show recent alerts (newest first)
            recent_alerts = all_alerts_to_display[:20]
            
            # Alert summary
            st.success(f"🔍 Found {len(recent_alerts)} security alerts")
            
            for alert in recent_alerts:
                if alert.get('type') == 'PORT_SCAN_GROUP':
                    # Display grouped port scan alert
                    with st.expander(f"🔴 PORT_SCAN - {alert.get('src_ip')} → {alert.get('dst_ip')} ({alert.get('count', 0)} ports)", expanded=True):
                        st.error(f"**🚨 High Severity Port Scan Detected**")
                        st.write(f"**🕒 Time:** {alert.get('timestamp')}")
                        st.write(f"**📡 Source IP:** `{alert.get('src_ip')}`")
                        st.write(f"**🎯 Target IP:** `{alert.get('dst_ip')}`")
                        st.write(f"**🔢 Ports Scanned:** {alert.get('count', 0)}")
                        st.write(f"**🛡️ Action Recommended:** Block source IP and investigate")
                elif alert.get('type') == 'BLACKLISTED_IP':
                    # Display blacklisted IP alert
                    with st.expander(f"🚫 BLACKLISTED_IP - {alert.get('src_ip')} blocked", expanded=True):
                        st.error(f"**🚨 Blacklisted IP Detected**")
                        st.write(f"**🕒 Time:** {alert.get('timestamp')}")
                        st.write(f"**📡 Source IP:** `{alert.get('src_ip')}`")
                        st.write(f"**🎯 Target IP:** `{alert.get('dst_ip', 'N/A')}`")
                        st.write(f"**📝 Details:** {alert.get('details')}")
                        st.write(f"**🛡️ Action:** IP automatically blocked")
                        st.write(f"**🆔 Alert ID:** `{alert.get('id')}`")
                else:
                    # Display individual alerts for other types
                    severity = alert.get('severity', 'MEDIUM')
                    severity_emoji = "🔴" if severity == 'HIGH' else "🟡" if severity == 'MEDIUM' else "🟢"
                    
                    with st.expander(f"{severity_emoji} {alert.get('type')} - {alert.get('src_ip')}", expanded=True):
                        if severity == 'HIGH':
                            st.error(f"**{severity_emoji} High Severity Alert**")
                        elif severity == 'MEDIUM':
                            st.warning(f"**{severity_emoji} Medium Severity Alert**")
                        else:
                            st.success(f"**{severity_emoji} Low Severity Alert**")
                            
                        st.write(f"**🕒 Time:** {alert.get('timestamp')}")
                        st.write(f"**📡 Source IP:** `{alert.get('src_ip')}`")
                        st.write(f"**🎯 Target:** `{alert.get('dst_ip', 'N/A')}`")
                        st.write(f"**📝 Details:** {alert.get('details')}")
                        if alert.get('dst_port'):
                            st.write(f"**🔢 Destination Port:** {alert.get('dst_port')}")
                        st.write(f"**🆔 Alert ID:** `{alert.get('id')}`")
        else:
            st.success("✅ No security alerts detected. Network traffic appears normal.")
    
    with tab4:
        st.header("📈 Network Analytics")
        
        if st.session_state.packets:
            # Calculate analytics
            total_packets = len(st.session_state.packets)
            total_bytes = sum(p.get('length', 0) for p in st.session_state.packets)
            avg_packet_size = total_bytes / total_packets if total_packets > 0 else 0
            
            # Protocol distribution
            protocols = {}
            for packet in st.session_state.packets:
                proto = packet.get('proto_name', 'Unknown')
                protocols[proto] = protocols.get(proto, 0) + 1
            
            # Top Source IPs
            src_ips = {}
            for packet in st.session_state.packets:
                ip = packet.get('src_ip')
                if ip:
                    src_ips[ip] = src_ips.get(ip, 0) + 1
            
            # Service distribution
            services = {}
            for packet in st.session_state.packets:
                service = packet.get('service', 'Unknown')
                services[service] = services.get(service, 0) + 1
            
            # Alert type distribution
            alert_types = {}
            for alert in st.session_state.alerts:
                alert_type = alert.get('type')
                if alert_type == 'PORT_SCAN_GROUP':
                    alert_type = 'PORT_SCAN'  # Group port scans
                alert_types[alert_type] = alert_types.get(alert_type, 0) + 1
            
            # Metrics
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("📦 Total Packets", total_packets)
            col2.metric("💾 Total Bytes", f"{total_bytes:,}")
            col3.metric("📏 Avg Size", f"{avg_packet_size:.0f} B")
            
            # Count grouped alerts for statistics
            port_scan_alerts = [a for a in st.session_state.alerts if a.get('type') == 'PORT_SCAN']
            other_alerts = [a for a in st.session_state.alerts if a.get('type') != 'PORT_SCAN']
            grouped_port_scans = group_port_scan_alerts(port_scan_alerts)
            total_grouped_alerts = len(grouped_port_scans) + len(other_alerts)
            
            col4.metric("🚨 Alerts", total_grouped_alerts)
            
            # Charts
            col1, col2 = st.columns(2)
            
            with col1:
                # Protocol distribution
                if protocols:
                    fig_proto = px.pie(
                        values=list(protocols.values()),
                        names=list(protocols.keys()),
                        title='🔗 Protocol Distribution',
                        color_discrete_sequence=px.colors.qualitative.Set3
                    )
                    st.plotly_chart(fig_proto, use_container_width=True)
                
                # Service distribution
                if services:
                    fig_service = px.pie(
                        values=list(services.values()),
                        names=list(services.keys()),
                        title='🌐 Service Distribution',
                        color_discrete_sequence=px.colors.qualitative.Pastel
                    )
                    st.plotly_chart(fig_service, use_container_width=True)
            
            with col2:
                # Top Source IPs
                if src_ips:
                    top_ips = sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:10]
                    ip_df = pd.DataFrame(top_ips, columns=['IP Address', 'Packet Count'])
                    fig_ips = px.bar(ip_df, x='IP Address', y='Packet Count', 
                                   title='📡 Top Source IPs (Packet Count)',
                                   color='Packet Count')
                    st.plotly_chart(fig_ips, use_container_width=True)
                
                # Alert type distribution
                if alert_types:
                    alert_df = pd.DataFrame(list(alert_types.items()), columns=['Alert Type', 'Count'])
                    fig_alerts = px.bar(alert_df, x='Alert Type', y='Count',
                                      title='🚨 Alert Type Distribution',
                                      color='Count')
                    st.plotly_chart(fig_alerts, use_container_width=True)
        else:
            st.info("📊 Start capture to see network analytics and statistics...")

if __name__ == "__main__":
    main()

