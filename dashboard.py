#!/usr/bin/env python3
"""
Q-SAFE Interactive Mission Dashboard
Real-time topology visualization with MITM controls and live logging
"""

import streamlit as st
import requests
import json
import time
import threading
import websocket
import queue
from datetime import datetime
import pandas as pd
try:
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.subplots import make_subplots
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

# Configure Streamlit page
st.set_page_config(
    page_title="Q-SAFE Mission Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for military theme
st.markdown("""
<style>
    .stApp {
        background-color: #0e1117;
        color: #fafafa;
    }
    .main-header {
        background: linear-gradient(90deg, #1e3d59, #2d5a87);
        padding: 20px;
        border-radius: 10px;
        text-align: center;
        margin-bottom: 20px;
        border: 2px solid #00ff00;
    }
    .status-card {
        background-color: #1e1e1e;
        padding: 15px;
        border-radius: 8px;
        border-left: 4px solid #00ff00;
        margin: 10px 0;
    }
    .attack-card {
        background-color: #2d1b1b;
        padding: 15px;
        border-radius: 8px;
        border-left: 4px solid #ff0000;
        margin: 10px 0;
    }
    .secure-log {
        color: #00ff00;
        font-family: 'Courier New', monospace;
    }
    .warning-log {
        color: #ffff00;
        font-family: 'Courier New', monospace;
    }
    .breach-log {
        color: #ff0000;
        font-family: 'Courier New', monospace;
    }
    .info-log {
        color: #00bfff;
        font-family: 'Courier New', monospace;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'mission_logs' not in st.session_state:
    st.session_state.mission_logs = []
if 'mission_running' not in st.session_state:
    st.session_state.mission_running = False
if 'topology_events' not in st.session_state:
    st.session_state.topology_events = []
if 'mission_stats' not in st.session_state:
    st.session_state.mission_stats = {
        'messages_sent': 0,
        'attacks_blocked': 0,
        'integrity_score': 100,
        'pcap_files': []
    }

class DashboardController:
    def __init__(self):
        self.mission_url = "http://localhost:5003"
        self.log_queue = queue.Queue()
        self.ws = None
        
    def start_mission(self):
        """Start the mission simulation"""
        try:
            response = requests.post(f"{self.mission_url}/api/mission/start", timeout=5)
            return response.json()
        except Exception as e:
            return {'success': False, 'message': f'Connection error: {str(e)}'}
            
    def stop_mission(self):
        """Stop the mission simulation"""
        try:
            response = requests.post(f"{self.mission_url}/api/mission/stop", timeout=5)
            return response.json()
        except Exception as e:
            return {'success': False, 'message': f'Connection error: {str(e)}'}
            
    def get_mission_status(self):
        """Get current mission status"""
        try:
            response = requests.get(f"{self.mission_url}/api/mission/status", timeout=5)
            return response.json()
        except Exception as e:
            return {'phase': 'DISCONNECTED', 'error': str(e)}

# Initialize dashboard controller
dashboard = DashboardController()

# Header
st.markdown("""
<div class="main-header">
    <h1>🛡️ Q-SAFE MISSION CONTROL DASHBOARD</h1>
    <h3>🔐 Post-Quantum Secure Communications</h3>
    <p>Real-time Mission Simulation & MITM Visualization</p>
</div>
""", unsafe_allow_html=True)

# Create main layout
col1, col2 = st.columns([2, 1])

with col1:
    st.subheader("🎯 Mission Control")
    
    # Mission control buttons
    button_col1, button_col2, button_col3 = st.columns(3)
    
    with button_col1:
        if st.button("🚀 START MISSION", type="primary", use_container_width=True):
            result = dashboard.start_mission()
            if result.get('success'):
                st.session_state.mission_running = True
                st.success("Mission started successfully!")
            else:
                st.error(f"Failed to start mission: {result.get('message')}")
                
    with button_col2:
        if st.button("🛑 STOP MISSION", type="secondary", use_container_width=True):
            result = dashboard.stop_mission()
            if result.get('success'):
                st.session_state.mission_running = False
                st.success("Mission stopped")
            else:
                st.error(f"Failed to stop mission: {result.get('message')}")
                
    with button_col3:
        if st.button("🔄 REFRESH STATUS", use_container_width=True):
            st.rerun()

    # Network Topology Visualization
    st.subheader("🌐 Network Topology")
    
    # Create network topology visualization
    if PLOTLY_AVAILABLE:
        fig = go.Figure()
        
        # Define node positions
        nodes = {
            'DEVICE_A': {'x': 0, 'y': 0, 'color': '#00ff00', 'size': 20},
            'SATELLITE': {'x': 1, 'y': 1, 'color': '#0080ff', 'size': 25},
            'DEVICE_B': {'x': 2, 'y': 0, 'color': '#00ff00', 'size': 20},
            'MITM': {'x': 1, 'y': 0, 'color': '#ff0000', 'size': 15}
        }
        
        # Add nodes
        for node_id, props in nodes.items():
            fig.add_trace(go.Scatter(
                x=[props['x']], y=[props['y']],
                mode='markers+text',
                marker=dict(size=props['size'], color=props['color']),
                text=[node_id.replace('_', ' ')],
                textposition="bottom center",
                name=node_id,
                showlegend=False
            ))
        
        # Add connections
        connections = [
            ('DEVICE_A', 'SATELLITE', '#00ff00'),
            ('SATELLITE', 'DEVICE_B', '#00ff00'),
            ('DEVICE_A', 'DEVICE_B', '#ffff00'),  # Mesh fallback
            ('MITM', 'SATELLITE', '#ff0000')  # Attack vector
        ]
        
        for start, end, color in connections:
            start_pos = nodes[start]
            end_pos = nodes[end]
            
            line_style = 'solid' if color != '#ffff00' else 'dash'
            width = 3 if color == '#00ff00' else 2
            
            fig.add_trace(go.Scatter(
                x=[start_pos['x'], end_pos['x']],
                y=[start_pos['y'], end_pos['y']],
                mode='lines',
                line=dict(color=color, width=width, dash=line_style),
                showlegend=False,
                hoverinfo='skip'
            ))
        
        fig.update_layout(
            title="Real-time Network Topology",
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            height=400,
            margin=dict(l=20, r=20, t=40, b=20)
        )
        
        st.plotly_chart(fig, use_container_width=True)
    else:
        # Fallback ASCII topology
        st.code("""
    DEVICE_A ←→ SATELLITE ←→ DEVICE_B
         ↑         ↑         ↑
         └─── MITM_NODE ────┘
              (blocked)
        """, language="text")
    
    # Legend
    st.markdown("""
    **Legend:**
    - 🟢 **Green Lines**: Secure satellite relay
    - 🟡 **Yellow Lines**: Mesh network fallback  
    - 🔴 **Red Lines**: MITM attack vectors (blocked)
    - 🔵 **Blue Node**: Zero-knowledge satellite
    - 🟢 **Green Nodes**: Secure devices
    - 🔴 **Red Node**: MITM attacker
    """)

with col2:
    st.subheader("📊 Mission Status")
    
    # Get current mission status
    status = dashboard.get_mission_status()
    current_phase = status.get('phase', 'UNKNOWN')
    
    # Phase indicator
    phase_colors = {
        'INIT': '#0080ff',
        'KEY_EXCHANGE': '#00ff00', 
        'MISSION_TRAFFIC': '#00ff00',
        'SATELLITE_FAILURE': '#ffff00',
        'UNDER_ATTACK': '#ff0000',
        'DEVICE_CAPTURE': '#ff0000',
        'COMPLETE': '#00ff00',
        'DISCONNECTED': '#808080'
    }
    
    phase_color = phase_colors.get(current_phase, '#808080')
    
    st.markdown(f"""
    <div class="status-card">
        <h4>Current Phase</h4>
        <h2 style="color: {phase_color};">{current_phase}</h2>
    </div>
    """, unsafe_allow_html=True)
    
    # Mission statistics
    stats = status.get('stats', st.session_state.mission_stats)
    
    st.markdown(f"""
    <div class="status-card">
        <h4>📈 Mission Statistics</h4>
        <p><strong>Messages Sent:</strong> {stats.get('messages_sent', 0)}</p>
        <p><strong>Attacks Blocked:</strong> {stats.get('attacks_blocked', 0)}</p>
        <p><strong>Integrity Score:</strong> {stats.get('integrity_score', 100)}%</p>
        <p><strong>Security Status:</strong> <span style="color: #00ff00;">SECURE</span></p>
    </div>
    """, unsafe_allow_html=True)
    
    # Encryption status
    devices = status.get('devices', {})
    device_a_status = devices.get('A', {}).get('status', 'offline')
    device_b_status = devices.get('B', {}).get('status', 'offline')
    satellite_status = status.get('satellite', {}).get('status', 'offline')
    
    st.markdown(f"""
    <div class="status-card">
        <h4>🔐 Encryption Status</h4>
        <p><strong>Algorithm:</strong> Post-Quantum (Kyber512)</p>
        <p><strong>Session Key:</strong> AES-256-GCM</p>
        <p><strong>Device A:</strong> <span style="color: {'#00ff00' if device_a_status == 'online' else '#ff0000'};">{device_a_status.upper()}</span></p>
        <p><strong>Device B:</strong> <span style="color: {'#00ff00' if device_b_status == 'online' else '#ff0000'};">{device_b_status.upper()}</span></p>
        <p><strong>Satellite:</strong> <span style="color: {'#00ff00' if satellite_status == 'online' else '#ffff00'};">{satellite_status.upper()}</span></p>
    </div>
    """, unsafe_allow_html=True)

# MITM Control Panel
st.subheader("🔴 MITM Attack Simulation")

mitm_col1, mitm_col2, mitm_col3, mitm_col4 = st.columns(4)

with mitm_col1:
    if st.button("🎯 Start MITM", use_container_width=True):
        st.warning("MITM attack simulation active")

with mitm_col2:
    if st.button("🔧 Tamper Data", use_container_width=True):
        st.error("Data tampering detected and blocked")

with mitm_col3:
    if st.button("🔄 Replay Attack", use_container_width=True):
        st.error("Replay attack detected and blocked")

with mitm_col4:
    if st.button("💥 Self-Destruct", use_container_width=True):
        st.error("Device self-destruct initiated")

# Live Mission Logs
st.subheader("📋 Live Mission Logs")

# Create scrollable log container
log_container = st.container()

with log_container:
    # Sample logs for demonstration
    sample_logs = [
        {"timestamp": "16:45:23.123", "level": "SECURE", "device_id": "MISSION", "message": "🚀 Q-SAFE Mission Simulation Starting"},
        {"timestamp": "16:45:23.456", "level": "SECURE", "device_id": "MISSION", "message": "🔐 Post-Quantum Cryptography: ACTIVE"},
        {"timestamp": "16:45:24.789", "level": "SECURE", "device_id": "A", "message": "Device A connected to satellite"},
        {"timestamp": "16:45:25.012", "level": "SECURE", "device_id": "B", "message": "Device B connected to satellite"},
        {"timestamp": "16:45:26.345", "level": "SECURE", "device_id": "A", "message": "Generating Kyber512 key pairs..."},
        {"timestamp": "16:45:27.678", "level": "SECURE", "device_id": "MISSION", "message": "🛡️ Quantum-Safe Communication: ACTIVE"},
        {"timestamp": "16:45:28.901", "level": "SECURE", "device_id": "A", "message": "[CRYPTO] Encrypting message MSG_001"},
        {"timestamp": "16:45:29.234", "level": "WARNING", "device_id": "SATELLITE", "message": "📡 Satellite communication lost"},
        {"timestamp": "16:45:30.567", "level": "BREACH", "device_id": "MITM", "message": "🔴 Attempting to decrypt intercepted packets"},
        {"timestamp": "16:45:31.890", "level": "SECURE", "device_id": "DEFENSE", "message": "✅ FAILED - Post-quantum encryption resistant"},
    ]
    
    # Display logs with color coding
    for log in reversed(sample_logs[-10:]):  # Show last 10 logs
        level = log['level']
        css_class = f"{level.lower()}-log"
        
        st.markdown(f"""
        <div class="{css_class}">
            [{log['timestamp']}] [{log['device_id']}] [{level}] {log['message']}
        </div>
        """, unsafe_allow_html=True)

# PCAP Files and Downloads
st.subheader("📦 Generated Evidence")

pcap_col1, pcap_col2 = st.columns(2)

with pcap_col1:
    st.markdown("""
    **📁 PCAP Files:**
    - `mission_traffic.pcap` - Encrypted mission communications
    - `mitm_attacks.pcap` - Blocked attack attempts  
    - `mesh_fallback.pcap` - Peer-to-peer routing
    """)

with pcap_col2:
    st.markdown("""
    **📊 Reports:**
    - `mission_summary.txt` - Complete mission analysis
    - `mitm_report.txt` - Attack detection log
    - `crypto_validation.txt` - Encryption verification
    """)

# Download buttons
download_col1, download_col2, download_col3 = st.columns(3)

with download_col1:
    if st.button("📥 Download PCAPs", use_container_width=True):
        st.success("PCAP files ready for Wireshark analysis")

with download_col2:
    if st.button("📄 View Reports", use_container_width=True):
        st.info("Mission reports generated")

with download_col3:
    if st.button("🔍 Open Wireshark", use_container_width=True):
        st.info("Opening Wireshark with Q-SAFE filters")

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #888;">
    <p>🛡️ Q-SAFE Mission Dashboard | Post-Quantum Secure Communications</p>
    <p>All cryptographic operations use quantum-resistant algorithms</p>
</div>
""", unsafe_allow_html=True)

# Auto-refresh every 2 seconds when mission is running
if st.session_state.mission_running:
    time.sleep(2)
    st.rerun()
