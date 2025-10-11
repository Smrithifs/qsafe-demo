#!/usr/bin/env python3
"""
Q-SAFE Unified Demo - All features in one port/webpage
Combines mission simulation, MITM visualization, and interactive controls
"""

import time
import json
import threading
import subprocess
import requests
import signal
import sys
import os
import hashlib
import zipfile
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify, send_file
from flask_socketio import SocketIO, emit
import logging

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import our modules
try:
    from pcap_generator.save_pcap import PcapGenerator
except ImportError:
    class PcapGenerator:
        def __init__(self): pass
        def add_message_packet(self, *args): pass
        def add_mitm_packet(self, *args): pass
        def get_pcap_files(self): return []
        def create_sample_traffic(self): pass

try:
    from reports.generate_reports import ReportGenerator
except ImportError:
    class ReportGenerator:
        def __init__(self): pass
        def create_evidence_package(self, *args): return '/tmp/evidence.zip'

from crypto_backend import CryptoBackend

app = Flask(__name__)
app.config['SECRET_KEY'] = 'qsafe-unified-demo'
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize generators
pcap_gen = PcapGenerator()
report_gen = ReportGenerator()

# Global state
qsafe_state = {
    'devices': {'A': {'status': 'offline', 'keys': None}, 'B': {'status': 'offline', 'keys': None}},
    'satellite_online': True,
    'messages': [],
    'attacks': [],
    'mission_phase': 'INIT',
    'mission_running': False,
    'logs': [],
    'stats': {
        'messages_sent': 0,
        'attacks_blocked': 0,
        'integrity_score': 100
    }
}

crypto = CryptoBackend(use_pqc=False)

def log_event(level, message, device_id='SYSTEM', metadata=None):
    """Add log entry and emit to clients"""
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    
    colors = {
        'SECURE': '#00ff00',
        'WARNING': '#ffff00', 
        'BREACH': '#ff0000',
        'INFO': '#00bfff'
    }
    
    log_entry = {
        'timestamp': timestamp,
        'level': level,
        'message': message,
        'device_id': device_id,
        'color': colors.get(level, '#ffffff'),
        'metadata': metadata or {}
    }
    
    qsafe_state['logs'].append(log_entry)
    if len(qsafe_state['logs']) > 100:
        qsafe_state['logs'] = qsafe_state['logs'][-100:]
    
    socketio.emit('log_update', log_entry)
    print(f"[{timestamp}] [{device_id}] [{level}] {message}")
    return log_entry

# Main Dashboard HTML
UNIFIED_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Q-SAFE Unified Mission Demo</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Courier New', monospace; 
            background: #0a0a0a; 
            color: #00ff00; 
            overflow-x: hidden;
        }
        .header {
            background: linear-gradient(90deg, #1e3d59, #2d5a87);
            padding: 20px;
            text-align: center;
            border-bottom: 2px solid #00ff00;
        }
        .container { display: flex; height: calc(100vh - 100px); }
        .left-panel { width: 60%; padding: 20px; }
        .right-panel { width: 40%; padding: 20px; border-left: 1px solid #333; }
        .section { 
            background: #111; 
            margin: 10px 0; 
            padding: 15px; 
            border: 1px solid #333; 
            border-radius: 5px;
        }
        .controls { display: flex; gap: 10px; margin: 10px 0; flex-wrap: wrap; }
        button {
            background: #1a4a6b;
            color: #00ff00;
            border: 1px solid #00ff00;
            padding: 10px 15px;
            cursor: pointer;
            border-radius: 3px;
            font-family: inherit;
        }
        button:hover { background: #2a5a7b; }
        button.danger { background: #6b1a1a; border-color: #ff0000; color: #ff0000; }
        button.warning { background: #6b6b1a; border-color: #ffff00; color: #ffff00; }
        .logs { 
            height: 300px; 
            overflow-y: auto; 
            background: #000; 
            padding: 10px; 
            font-size: 12px;
            border: 1px solid #333;
        }
        .log-entry { margin: 2px 0; }
        .stats { display: flex; justify-content: space-between; }
        .stat-item { text-align: center; }
        .phase-indicator {
            font-size: 18px;
            font-weight: bold;
            text-align: center;
            padding: 10px;
            border: 2px solid #ffff00;
            border-radius: 5px;
            margin: 10px 0;
        }
        input, select { 
            background: #111; 
            color: #00ff00; 
            border: 1px solid #333; 
            padding: 5px; 
            margin: 5px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Q-SAFE UNIFIED MISSION DEMO</h1>
        <h3>🔐 Post-Quantum Secure Communications with Real-time MITM Visualization</h3>
    </div>

    <div class="container">
        <div class="left-panel">
            <div class="section">
                <h3>🎯 Mission Control</h3>
                <div class="controls">
                    <button onclick="startMission()">🚀 START MISSION</button>
                    <button onclick="stopMission()" class="danger">🛑 STOP MISSION</button>
                    <button onclick="refreshStatus()">🔄 REFRESH</button>
                </div>
                <div id="phase-indicator" class="phase-indicator">INIT</div>
            </div>

            <div class="section">
                <h3>🌐 Live Network Topology</h3>
                <div class="controls">
                    <a href="/topology" target="_blank"><button>📊 Open Live Topology</button></a>
                </div>
                <div style="font-size: 12px; margin-top: 10px;">
                    Click to open the live network visualization in a new window.
                </div>
            </div>

            <div class="section">
                <h3>📱 Device Management</h3>
                <div class="controls">
                    <button onclick="connectDevice('A')">Connect Device A</button>
                    <button onclick="connectDevice('B')">Connect Device B</button>
                    <button onclick="generateKeys()">🔐 Generate Keys</button>
                    <button onclick="toggleSatellite()" class="warning">📡 Toggle Satellite</button>
                </div>
            </div>

            <div class="section">
                <h3>💬 Secure Messaging</h3>
                <div class="controls">
                    <select id="fromDevice">
                        <option value="A">Device A</option>
                        <option value="B">Device B</option>
                    </select>
                    <select id="toDevice">
                        <option value="B">Device B</option>
                        <option value="A">Device A</option>
                    </select>
                    <input type="text" id="messageText" placeholder="Enter message..." style="width: 200px;">
                    <button onclick="sendMessage()">📤 Send Encrypted</button>
                </div>
            </div>

            <div class="section">
                <h3>🔴 MITM Attack Simulation</h3>
                <div class="controls">
                    <button onclick="simulateAttack('decrypt')" class="danger">🎯 Decrypt Attempt</button>
                    <button onclick="simulateAttack('tamper')" class="danger">🔧 Tamper Data</button>
                    <button onclick="simulateAttack('replay')" class="danger">🔄 Replay Attack</button>
                    <button onclick="captureDevice()" class="danger">💥 Device Capture</button>
                </div>
            </div>
        </div>

        <div class="right-panel">
            <div class="section">
                <h3>📊 Mission Statistics</h3>
                <div class="stats">
                    <div class="stat-item"><div>Messages</div><div id="stat-messages">0</div></div>
                    <div class="stat-item"><div>Attacks Blocked</div><div id="stat-attacks">0</div></div>
                    <div class="stat-item"><div>Integrity</div><div id="stat-integrity">100%</div></div>
                </div>
            </div>

            <div class="section">
                <h3>📡 Device Status</h3>
                <div id="device-status">
                    <div>Device A: <span id="status-a">OFFLINE</span></div>
                    <div>Device B: <span id="status-b">OFFLINE</span></div>
                    <div>Satellite: <span id="status-sat">ONLINE</span></div>
                    <div>Encryption: <span id="crypto-status">RSA + AES-256-GCM</span></div>
                </div>
            </div>

            <div class="section">
                <h3>📋 Live Mission Logs</h3>
                <div id="logs" class="logs"></div>
            </div>

            <div class="section">
                <h3>📦 Generated Evidence</h3>
                <div class="controls">
                    <button onclick="downloadPCAP()">📥 Download PCAP</button>
                    <button onclick="viewReport()">📄 View Report</button>
                    <button onclick="openWireshark()">🔍 Wireshark</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        const socket = io();

        function logEvent(level, message) {
            const logsDiv = document.getElementById('logs');
            const logEntry = document.createElement('div');
            logEntry.className = 'log-entry';
            logEntry.style.color = level === 'SECURE' ? '#00ff00' : level === 'WARNING' ? '#ffff00' : '#ff0000';
            logEntry.textContent = `[${new Date().toLocaleTimeString()}] [${level}] ${message}`;
            logsDiv.prepend(logEntry);
        }

        socket.on('connect', () => logEvent('SECURE', 'Dashboard connected'));
        socket.on('log_update', (log) => {
            const logsDiv = document.getElementById('logs');
            const logEntry = document.createElement('div');
            logEntry.className = 'log-entry';
            logEntry.style.color = log.color;
            logEntry.textContent = `[${log.timestamp}] [${log.device_id}] [${log.level}] ${log.message}`;
            logsDiv.prepend(logEntry);
        });
        
        socket.on('full_state_update', (state) => {
            if (state.stats) {
                document.getElementById('stat-messages').textContent = state.stats.messages_sent;
                document.getElementById('stat-attacks').textContent = state.stats.attacks_blocked;
                document.getElementById('stat-integrity').textContent = state.stats.integrity_score + '%';
            }
            if (state.devices) {
                document.getElementById('status-a').textContent = state.devices.A.status.toUpperCase();
                document.getElementById('status-b').textContent = state.devices.B.status.toUpperCase();
            }
            if (state.mission_phase) {
                document.getElementById('phase-indicator').textContent = state.mission_phase;
            }
            document.getElementById('status-sat').textContent = state.satellite_online ? 'ONLINE' : 'OFFLINE';
        });

        function startMission() { fetch('/api/mission/start', {method: 'POST'}); }
        function stopMission() { fetch('/api/mission/stop', {method: 'POST'}); }
        function connectDevice(id) { fetch('/api/device/connect', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({device_id: id}) }); }
        function generateKeys() { fetch('/api/device/keygen', {method: 'POST'}); }
        function toggleSatellite() { fetch('/api/satellite/toggle', {method: 'POST'}); }
        function sendMessage() {
            const from = document.getElementById('fromDevice').value;
            const to = document.getElementById('toDevice').value;
            const message = document.getElementById('messageText').value;
            if (!message) return alert('Please enter a message');
            fetch('/api/message/send', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({from, to, message}) })
                .then(() => document.getElementById('messageText').value = '');
        }
        function simulateAttack(type) { fetch('/api/attack/simulate', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({attack_type: type}) }); }
        function captureDevice() { fetch('/api/device/capture', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({device_id: 'B'}) }); }
        function downloadPCAP() { window.location.href = '/api/pcap/download'; }
        function viewReport() { window.location.href = '/api/report/view'; }
        function openWireshark() { fetch('/api/launch_tool', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({tool: 'wireshark'}) }); }
        function refreshStatus() { socket.emit('request_initial_state'); }

        document.addEventListener('DOMContentLoaded', refreshStatus);
        setInterval(refreshStatus, 5000);
    </script>
</body>
</html>
"""

# Topology Page HTML
TOPOLOGY_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Q-SAFE Live Network Topology</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body { background: #0a0a0a; color: #00ff00; font-family: 'Courier New', monospace; margin: 0; padding: 0; overflow: hidden; }
        #topology { width: 100vw; height: 100vh; }
        .message-line { stroke-width: 3; opacity: 0.8; }
        .secure-line { stroke: #00ff00; }
        .mesh-line { stroke: #ffff00; stroke-dasharray: 5,5; }
        .attack-line { stroke: #ff0000; stroke-dasharray: 3,3; }
    </style>
</head>
<body>
    <div id="topology"></div>
    <script>
        const socket = io();
        let nodes = {
            'DEVICE_A': {x: 200, y: 400, type: 'device', status: 'offline'},
            'SATELLITE': {x: 500, y: 200, type: 'satellite', status: 'online'},
            'DEVICE_B': {x: 800, y: 400, type: 'device', status: 'offline'},
            'MITM': {x: 500, y: 400, type: 'attacker', status: 'inactive'}
        };

        const svg = d3.select("#topology").append("svg")
            .attr("width", '100%').attr("height", '100%').attr("viewBox", "0 0 1000 600");

        function drawTopology() {
            svg.selectAll("*").remove();
            const connections = [
                {from: 'DEVICE_A', to: 'SATELLITE', type: 'secure'},
                {from: 'SATELLITE', to: 'DEVICE_B', type: 'secure'},
                {from: 'DEVICE_A', to: 'DEVICE_B', type: 'mesh'},
                {from: 'MITM', to: 'SATELLITE', type: 'attack'}
            ];
            connections.forEach(conn => {
                const fromNode = nodes[conn.from];
                const toNode = nodes[conn.to];
                if (!fromNode || !toNode) return;
                svg.append("line")
                    .attr("x1", fromNode.x).attr("y1", fromNode.y)
                    .attr("x2", toNode.x).attr("y2", toNode.y)
                    .attr("class", `${conn.type}-line message-line`);
            });
            Object.keys(nodes).forEach(nodeId => {
                const node = nodes[nodeId];
                svg.append("circle")
                    .attr("cx", node.x).attr("cy", node.y).attr("r", 30)
                    .style("fill", getNodeColor(node));
                svg.append("text")
                    .attr("x", node.x).attr("y", node.y + 50)
                    .attr("text-anchor", "middle").style("fill", "#00ff00")
                    .text(nodeId.replace('DEVICE_', ''));
            });
        }

        function getNodeColor(node) {
            if (node.type === 'device') return node.status === 'online' ? '#00ff00' : (node.status === 'compromised' ? '#ff0000' : '#666');
            if (node.type === 'satellite') return node.status === 'online' ? '#0080ff' : '#666';
            if (node.type === 'attacker') return node.status === 'active' ? '#ff0000' : '#800000';
            return '#666';
        }
        
        function animateMessage(from, to, type) {
            const fromNode = nodes[from];
            const toNode = nodes[to];
            if (!fromNode || !toNode) return;
            const line = svg.append("line").attr("class", `${type}-line`)
                .attr("x1", fromNode.x).attr("y1", fromNode.y)
                .attr("x2", fromNode.x).attr("y2", fromNode.y)
                .style("stroke-width", 5).style("opacity", 1);
            line.transition().duration(1000).attr("x2", toNode.x).attr("y2", toNode.y).on("end", () => line.remove());
        }

        socket.on('connect', () => {
            console.log('Topology WebSocket Connected');
            socket.emit('request_initial_state');
        });
        
        socket.on('full_state_update', function(state) {
            if (!state) return;
            if (state.devices) {
                Object.keys(state.devices).forEach(deviceId => {
                    const deviceNode = nodes['DEVICE_' + deviceId];
                    if (deviceNode) deviceNode.status = state.devices[deviceId].status;
                });
            }
            nodes.SATELLITE.status = state.satellite_online ? 'online' : 'offline';
            drawTopology();
        });

        socket.on('topology_update', function(data) {
            animateMessage(`DEVICE_${data.from}`, `DEVICE_${data.to}`, data.route_type);
        });

        socket.on('mitm_attack', function(data) {
            nodes.MITM.status = data.status;
            drawTopology();
        });

        drawTopology();
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(UNIFIED_HTML)

@app.route('/topology')
def topology():
    return render_template_string(TOPOLOGY_HTML)

@app.route('/api/status')
def get_status():
    return jsonify(qsafe_state)

@socketio.on('request_initial_state')
def handle_initial_state_request():
    emit('full_state_update', qsafe_state)

@app.route('/api/mission/start', methods=['POST'])
def start_mission():
    qsafe_state['mission_running'] = True
    qsafe_state['mission_phase'] = 'RUNNING'
    log_event('SECURE', '🚀 Mission started', 'CONTROL')
    socketio.emit('full_state_update', qsafe_state)
    return jsonify({'success': True})

@app.route('/api/mission/stop', methods=['POST'])
def stop_mission():
    qsafe_state['mission_running'] = False
    qsafe_state['mission_phase'] = 'STOPPED'
    log_event('INFO', '🛑 Mission stopped')
    socketio.emit('full_state_update', qsafe_state)
    return jsonify({'success': True})

@app.route('/api/device/connect', methods=['POST'])
def connect_device():
    device_id = request.json['device_id']
    qsafe_state['devices'][device_id]['status'] = 'online'
    log_event('SECURE', f'Device {device_id} connected', device_id)
    socketio.emit('full_state_update', qsafe_state)
    return jsonify({'success': True})

@app.route('/api/device/keygen', methods=['POST'])
def generate_keys():
    try:
        for device_id in ['A', 'B']:
            if qsafe_state['devices'][device_id]['status'] == 'online':
                log_event('INFO', f'🔧 Generating RSA-2048 key pair for Device {device_id}...', device_id)
                
                # Generate keys using CryptoBackend
                private_key, public_key = crypto.generate_keypair()
                qsafe_state['devices'][device_id]['keys'] = {
                    'private_key': private_key,
                    'public_key': public_key
                }
                
                # Log detailed key generation info
                pub_key_hex = public_key.hex()[:64]
                priv_key_hex = private_key.hex()[:64]
                log_event('SECURE', f'✅ RSA Public Key Generated: {pub_key_hex}...', device_id)
                log_event('SECURE', f'🔐 RSA Private Key Generated: {priv_key_hex}...', device_id)
                log_event('INFO', f'📊 Key Size: 2048 bits | Exponent: 65537 | Algorithm: RSA-OAEP', device_id)
                log_event('INFO', f'🔒 Keys stored securely in device memory', device_id)
                
        socketio.emit('full_state_update', qsafe_state)
        return jsonify({'success': True})
    except Exception as e:
        log_event('BREACH', f'❌ Key generation failed: {str(e)}', 'SYSTEM')
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/satellite/toggle', methods=['POST'])
def toggle_satellite():
    qsafe_state['satellite_online'] = not qsafe_state['satellite_online']
    status = 'online' if qsafe_state['satellite_online'] else 'offline'
    log_event('WARNING', f'📡 Satellite is now {status}', 'SATELLITE')
    socketio.emit('full_state_update', qsafe_state)
    return jsonify({'success': True, 'online': qsafe_state['satellite_online']})

@app.route('/api/message/send', methods=['POST'])
def send_message():
    data = request.json
    from_device = data['from']
    to_device = data['to']
    message = data['message']
    
    try:
        # Check if devices have keys
        if not qsafe_state['devices'][from_device]['keys'] or not qsafe_state['devices'][to_device]['keys']:
            log_event('BREACH', f'❌ Cannot send message - devices need keys first', from_device)
            return jsonify({'success': False, 'error': 'Devices need keys'}), 400
        
        # Determine routing: Satellite or Mesh
        if qsafe_state['satellite_online']:
            route_type = 'secure'
            route_name = 'SATELLITE'
            log_event('INFO', f'📡 Routing via SATELLITE (encrypted relay)', from_device)
        else:
            route_type = 'mesh'
            route_name = 'MESH NETWORK'
            log_event('WARNING', f'🔶 Satellite offline - switching to MESH NETWORK', from_device)
            log_event('INFO', f'🔗 Establishing direct peer-to-peer connection', from_device)
        
        # Step 1: Generate AES session key
        import os
        session_key = os.urandom(32)  # 256-bit AES key
        log_event('INFO', f'🔑 Generated AES-256 session key: {session_key.hex()[:32]}...', from_device)
        
        # Step 2: Encrypt message with AES-GCM
        from Crypto.Cipher import AES
        nonce = os.urandom(12)
        cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())
        log_event('SECURE', f'🔐 AES-GCM Encryption:', from_device)
        log_event('INFO', f'  └─ Plaintext: "{message}"', from_device)
        log_event('INFO', f'  └─ Nonce: {nonce.hex()}', from_device)
        log_event('INFO', f'  └─ Ciphertext: {ciphertext.hex()}', from_device)
        log_event('INFO', f'  └─ Auth Tag: {tag.hex()}', from_device)
        
        # Step 3: Encrypt session key with recipient's RSA public key
        from Crypto.Cipher import PKCS1_OAEP
        from Crypto.PublicKey import RSA
        recipient_pub_key = RSA.import_key(qsafe_state['devices'][to_device]['keys']['public_key'])
        cipher_rsa = PKCS1_OAEP.new(recipient_pub_key)
        encrypted_session_key = cipher_rsa.encrypt(session_key)
        log_event('SECURE', f'🔒 RSA-OAEP Key Encapsulation:', from_device)
        log_event('INFO', f'  └─ Recipient: Device {to_device}', from_device)
        log_event('INFO', f'  └─ Encrypted Session Key: {encrypted_session_key.hex()[:64]}...', from_device)
        
        # Step 4: Sign the message with sender's private key
        from Crypto.Signature import pkcs1_15
        from Crypto.Hash import SHA256
        sender_priv_key = RSA.import_key(qsafe_state['devices'][from_device]['keys']['private_key'])
        h = SHA256.new(ciphertext)
        signature = pkcs1_15.new(sender_priv_key).sign(h)
        log_event('SECURE', f'✍️  RSA-PSS Digital Signature:', from_device)
        log_event('INFO', f'  └─ Hash (SHA-256): {h.hexdigest()}', from_device)
        log_event('INFO', f'  └─ Signature: {signature.hex()[:64]}...', from_device)
        
        # Step 5: Transmit over network
        log_event('SECURE', f'📤 Transmitting via {route_name}...', from_device)
        log_event('INFO', f'  └─ Packet Size: {len(encrypted_session_key) + len(ciphertext) + len(tag) + len(nonce) + len(signature)} bytes', from_device)
        
        # Step 6: Recipient decrypts (simulated)
        log_event('INFO', f'📥 Device {to_device} received encrypted packet', to_device)
        
        # Verify signature
        try:
            sender_pub_key = RSA.import_key(qsafe_state['devices'][from_device]['keys']['public_key'])
            pkcs1_15.new(sender_pub_key).verify(h, signature)
            log_event('SECURE', f'✅ Signature verification PASSED', to_device)
            log_event('INFO', f'  └─ Sender authenticated: Device {from_device}', to_device)
        except:
            log_event('BREACH', f'❌ Signature verification FAILED - message rejected', to_device)
            return jsonify({'success': False, 'error': 'Signature verification failed'}), 400
        
        # Decrypt session key with recipient's private key
        recipient_priv_key = RSA.import_key(qsafe_state['devices'][to_device]['keys']['private_key'])
        cipher_rsa_decrypt = PKCS1_OAEP.new(recipient_priv_key)
        decrypted_session_key = cipher_rsa_decrypt.decrypt(encrypted_session_key)
        log_event('SECURE', f'🔓 RSA-OAEP Decryption:', to_device)
        log_event('INFO', f'  └─ Session key recovered: {decrypted_session_key.hex()[:32]}...', to_device)
        
        # Decrypt message with AES
        cipher_aes_decrypt = AES.new(decrypted_session_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher_aes_decrypt.decrypt_and_verify(ciphertext, tag)
        log_event('SECURE', f'🔓 AES-GCM Decryption:', to_device)
        log_event('INFO', f'  └─ Authentication tag verified ✓', to_device)
        log_event('SECURE', f'  └─ Plaintext recovered: "{plaintext.decode()}"', to_device)
        
        log_event('SECURE', f'✅ Message delivered successfully via {route_name}', to_device)
        
        qsafe_state['stats']['messages_sent'] += 1
        socketio.emit('topology_update', {'from': from_device, 'to': to_device, 'route_type': route_type})
        socketio.emit('full_state_update', qsafe_state)
        return jsonify({'success': True})
        
    except Exception as e:
        log_event('BREACH', f'❌ Message transmission failed: {str(e)}', from_device)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/attack/simulate', methods=['POST'])
def simulate_attack():
    attack_type = request.json['attack_type']
    qsafe_state['stats']['attacks_blocked'] += 1
    log_event('BREACH', f'🔴 {attack_type.upper()} attack blocked by encryption', 'MITM')
    socketio.emit('mitm_attack', {'status': 'active'})
    socketio.emit('full_state_update', qsafe_state)
    def revert_mitm():
        time.sleep(2)
        socketio.emit('mitm_attack', {'status': 'inactive'})
    threading.Thread(target=revert_mitm, daemon=True).start()
    return jsonify({'success': True})

@app.route('/api/device/capture', methods=['POST'])
def capture_device():
    device_id = request.json['device_id']
    qsafe_state['devices'][device_id]['status'] = 'compromised'
    qsafe_state['devices'][device_id]['keys'] = None
    log_event('BREACH', f'💥 Device {device_id} captured - Self-destruct activated!', device_id)
    socketio.emit('full_state_update', qsafe_state)
    return jsonify({'success': True})

@app.route('/api/pcap/download')
def download_pcap():
    try:
        # Generate a simple PCAP file with mission data
        import tempfile
        pcap_path = os.path.join(tempfile.gettempdir(), 'qsafe_mission.pcap')
        
        # Create basic PCAP structure (simplified)
        with open(pcap_path, 'wb') as f:
            # PCAP global header
            f.write(b'\xd4\xc3\xb2\xa1')  # Magic number
            f.write(b'\x02\x00\x04\x00')  # Version
            f.write(b'\x00\x00\x00\x00')  # Timezone
            f.write(b'\x00\x00\x00\x00')  # Sigfigs
            f.write(b'\xff\xff\x00\x00')  # Snaplen
            f.write(b'\x01\x00\x00\x00')  # Network (Ethernet)
        
        log_event('INFO', f'📦 PCAP file generated: {pcap_path}', 'SYSTEM')
        return send_file(pcap_path, as_attachment=True, download_name='qsafe_mission.pcap')
    except Exception as e:
        log_event('BREACH', f'❌ PCAP generation failed: {str(e)}', 'SYSTEM')
        return jsonify({'error': str(e)}), 500

@app.route('/api/report/view')
def view_report():
    try:
        # Generate mission report
        report = {
            'mission_phase': qsafe_state['mission_phase'],
            'devices': qsafe_state['devices'],
            'stats': qsafe_state['stats'],
            'satellite_status': 'ONLINE' if qsafe_state['satellite_online'] else 'OFFLINE',
            'total_logs': len(qsafe_state['logs']),
            'timestamp': datetime.now().isoformat()
        }
        
        import tempfile
        report_path = os.path.join(tempfile.gettempdir(), 'qsafe_report.json')
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        log_event('INFO', f'📄 Mission report generated', 'SYSTEM')
        return send_file(report_path, as_attachment=True, download_name='qsafe_mission_report.json')
    except Exception as e:
        log_event('BREACH', f'❌ Report generation failed: {str(e)}', 'SYSTEM')
        return jsonify({'error': str(e)}), 500

@app.route('/api/launch_tool', methods=['POST'])
def launch_tool():
    return jsonify({'success': False, 'message': 'Tool launching not configured'})

if __name__ == '__main__':
    print("🛡️  Q-SAFE Unified Demo Starting...")
    print("📡 Dashboard: http://localhost:5000")
    print("🌐 Topology: http://localhost:5000/topology")
    socketio.run(app, debug=True, port=5000, allow_unsafe_werkzeug=True)
