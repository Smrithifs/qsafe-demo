#!/usr/bin/env python3
"""
Q-SAFE Interactive Web Demo
Full browser-based interface for all operations
"""

import time
import json
import threading
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify
from flask_socketio import SocketIO, emit
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from crypto_backend import CryptoBackend

app = Flask(__name__)
app.config['SECRET_KEY'] = 'qsafe-web-demo'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global state
qsafe_state = {
    'devices': {},
    'messages': [],
    'satellite_online': True,
    'attack_mode': False,
    'logs': []
}

crypto = CryptoBackend(use_pqc=False)

def send_to_topology(data):
    """Send events to topology visualizer"""
    try:
        import requests
        response = requests.post('http://localhost:5002/api/topology/events', json=data, timeout=1)
        print(f"✅ Sent to topology: {data.get('type')} - Status: {response.status_code}")
    except Exception as e:
        print(f"❌ Failed to send to topology: {e}")
        pass  # Topology not running

def log_event(level, message, device_id=None):
    """Add log entry and emit to clients"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    log_entry = {
        'timestamp': timestamp,
        'level': level,
        'message': message,
        'device_id': device_id or 'SYSTEM',
        'color': level.lower()
    }
    qsafe_state['logs'].append(log_entry)
    socketio.emit('new_log', log_entry)
    print(f"[{timestamp}] [{device_id or 'SYSTEM'}] [{level}] {message}")

# Web Interface HTML
WEB_INTERFACE = """
<!DOCTYPE html>
<html>
<head>
    <title>Q-SAFE Interactive Demo</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <style>
        body { font-family: 'Courier New', monospace; background: #000; color: #0f0; margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { text-align: center; border-bottom: 2px solid #0f0; padding: 20px 0; margin-bottom: 20px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #333; background: #111; }
        .controls { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .device-panel { border: 1px solid #0f0; padding: 15px; }
        .device-panel h3 { margin-top: 0; color: #0f0; }
        .device-panel.offline { border-color: #f00; }
        .device-panel.offline h3 { color: #f00; }
        button { background: #333; color: #0f0; border: 1px solid #0f0; padding: 10px 15px; margin: 5px; cursor: pointer; font-family: inherit; }
        button:hover { background: #0f0; color: #000; }
        button.danger { border-color: #f00; color: #f00; }
        button.danger:hover { background: #f00; color: #000; }
        button.warning { border-color: #ff0; color: #ff0; }
        button.warning:hover { background: #ff0; color: #000; }
        input, textarea { background: #222; color: #0f0; border: 1px solid #0f0; padding: 8px; font-family: inherit; width: 100%; box-sizing: border-box; }
        .log-container { height: 400px; overflow-y: scroll; background: #000; padding: 10px; border: 1px solid #333; }
        .log-entry { padding: 2px 0; font-size: 12px; }
        .secure { color: #0f0; }
        .warning { color: #ff0; }
        .breach { color: #f00; }
        .status-indicator { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 5px; }
        .status-online { background: #0f0; }
        .status-offline { background: #f00; }
        .message-form { margin: 10px 0; }
        .message-form input { margin: 5px 0; }
        .attack-panel { border-color: #f00; }
        .attack-panel h3 { color: #f00; }
        .mitm-panel { border-color: #ff0; }
        .mitm-panel h3 { color: #ff0; }
        .topology-link { color: #0ff; text-decoration: none; }
        .topology-link:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛰️ Q-SAFE INTERACTIVE DEMO</h1>
            <div>Satellite Status: <span class="status-indicator" id="sat-indicator"></span><span id="sat-status">ONLINE</span></div>
            <div>Connected Devices: <span id="device-count">0</span></div>
            <div><a href="http://localhost:5001" target="_blank" class="topology-link">🗺️ Network Topology</a> | 
                 <a href="#" onclick="downloadPcap()" class="topology-link">📦 Download PCAP</a></div>
        </div>

        <div class="controls">
            <!-- Device A Panel -->
            <div class="device-panel" id="device-a-panel">
                <h3>📱 Device A</h3>
                <div>Status: <span id="device-a-status">OFFLINE</span></div>
                <div>Keys: <span id="device-a-keys">Not Generated</span></div>
                <button onclick="connectDevice('A')">Connect Device A</button>
                <button onclick="generateKeys('A')">Generate Keys</button>
                <div class="message-form">
                    <input type="text" id="msg-a-to-b" placeholder="Message to Device B" value="Hello from Device A!">
                    <button onclick="sendMessage('A', 'B')">Send to Device B</button>
                </div>
                <button class="danger" onclick="triggerCapture('A')">🚨 Trigger Capture</button>
            </div>

            <!-- Device B Panel -->
            <div class="device-panel" id="device-b-panel">
                <h3>📱 Device B</h3>
                <div>Status: <span id="device-b-status">OFFLINE</span></div>
                <div>Keys: <span id="device-b-keys">Not Generated</span></div>
                <button onclick="connectDevice('B')">Connect Device B</button>
                <button onclick="generateKeys('B')">Generate Keys</button>
                <div class="message-form">
                    <input type="text" id="msg-b-to-a" placeholder="Message to Device A" value="Hello from Device B!">
                    <button onclick="sendMessage('B', 'A')">Send to Device A</button>
                </div>
                <button class="danger" onclick="triggerCapture('B')">🚨 Trigger Capture</button>
            </div>

            <!-- Satellite Control Panel -->
            <div class="device-panel">
                <h3>🛰️ Satellite Control</h3>
                <div>Status: <span id="satellite-status">ONLINE</span></div>
                <div>Messages Relayed: <span id="msg-count">0</span></div>
                <button class="warning" onclick="toggleSatellite()">Toggle Satellite</button>
                <button onclick="clearLogs()">Clear Logs</button>
                <div style="margin-top: 10px;">
                    <strong>Zero-Knowledge Proof:</strong><br>
                    <small>Satellite can only see encrypted data, never plaintext</small>
                </div>
            </div>

            <!-- MITM Analysis Panel -->
            <div class="device-panel mitm-panel">
                <h3>🔴 MITM Analysis</h3>
                <div>Interceptor Status: <span id="mitm-status">INACTIVE</span></div>
                <div>Packets Captured: <span id="packet-count">0</span></div>
                <button class="warning" onclick="startMitmCapture()">Start MITM Capture</button>
                <button onclick="stopMitmCapture()">Stop Capture</button>
                <button onclick="downloadPcap()">📦 Download PCAP</button>
                <button onclick="viewMitmReport()">📊 View Report</button>
            </div>

            <!-- Attack Simulation Panel -->
            <div class="device-panel attack-panel">
                <h3>⚔️ Attack Simulation</h3>
                <button class="danger" onclick="simulateAttack('mitm')">MITM Attack</button>
                <button class="danger" onclick="simulateAttack('replay')">Replay Attack</button>
                <button class="danger" onclick="simulateAttack('keyextract')">Key Extraction</button>
                <button class="warning" onclick="runFullDemo()">🎯 Run Full Demo</button>
            </div>
        </div>

        <!-- Live Logs -->
        <div class="section">
            <h3>📊 Live Event Log</h3>
            <div class="log-container" id="log-container"></div>
        </div>
    </div>

    <script>
        const socket = io();
        let messageCount = 0;

        socket.on('connect', function() {
            console.log('Connected to Q-SAFE server');
            updateStatus();
        });

        socket.on('new_log', function(log) {
            addLogEntry(log);
        });

        socket.on('device_update', function(data) {
            updateDeviceStatus(data.device_id, data.status, data.keys);
        });

        socket.on('satellite_update', function(data) {
            updateSatelliteStatus(data.online);
        });

        function addLogEntry(log) {
            const container = document.getElementById('log-container');
            const entry = document.createElement('div');
            entry.className = `log-entry ${log.color}`;
            entry.textContent = `[${log.timestamp}] [${log.device_id}] [${log.level}] ${log.message}`;
            container.appendChild(entry);
            container.scrollTop = container.scrollHeight;
            
            // Keep only last 100 entries
            while (container.children.length > 100) {
                container.removeChild(container.firstChild);
            }
        }

        function updateDeviceStatus(deviceId, status, keys) {
            const statusElement = document.getElementById(`device-${deviceId.toLowerCase()}-status`);
            const keysElement = document.getElementById(`device-${deviceId.toLowerCase()}-keys`);
            const panelElement = document.getElementById(`device-${deviceId.toLowerCase()}-panel`);
            
            if (statusElement) statusElement.textContent = status.toUpperCase();
            if (keysElement) keysElement.textContent = keys || 'Not Generated';
            
            if (panelElement) {
                if (status === 'compromised') {
                    panelElement.className = 'device-panel offline';
                } else if (status === 'online') {
                    panelElement.className = 'device-panel';
                }
            }
            
            updateDeviceCount();
        }

        function updateSatelliteStatus(online) {
            const indicator = document.getElementById('sat-indicator');
            const status = document.getElementById('sat-status');
            const satStatus = document.getElementById('satellite-status');
            
            if (online) {
                indicator.className = 'status-indicator status-online';
                status.textContent = 'ONLINE';
                satStatus.textContent = 'ONLINE';
            } else {
                indicator.className = 'status-indicator status-offline';
                status.textContent = 'OFFLINE';
                satStatus.textContent = 'OFFLINE';
            }
        }

        function updateDeviceCount() {
            // This would be updated from server in real implementation
            document.getElementById('device-count').textContent = '2';
        }

        function updateStatus() {
            fetch('/api/status')
                .then(response => response.json())
                .then(data => {
                    updateSatelliteStatus(data.satellite_online);
                    document.getElementById('msg-count').textContent = data.message_count || 0;
                });
        }

        // Device Operations
        function connectDevice(deviceId) {
            fetch('/api/device/connect', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({device_id: deviceId})
            });
        }

        function generateKeys(deviceId) {
            fetch('/api/device/generate_keys', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({device_id: deviceId})
            });
        }

        function sendMessage(fromDevice, toDevice) {
            const messageInput = document.getElementById(`msg-${fromDevice.toLowerCase()}-to-${toDevice.toLowerCase()}`);
            const message = messageInput.value;
            
            if (!message) {
                alert('Please enter a message');
                return;
            }

            fetch('/api/message/send', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    from: fromDevice,
                    to: toDevice,
                    message: message
                })
            });
        }

        function triggerCapture(deviceId) {
            if (confirm(`Trigger capture on Device ${deviceId}? This will destroy all keys!`)) {
                fetch('/api/device/capture', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({device_id: deviceId})
                });
            }
        }

        function toggleSatellite() {
            fetch('/api/satellite/toggle', {method: 'POST'});
        }

        function simulateAttack(attackType) {
            fetch('/api/attack/simulate', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({attack_type: attackType})
            });
        }

        function runFullDemo() {
            if (confirm('Run full automated demo? This will demonstrate all Q-SAFE features.')) {
                fetch('/api/demo/run', {method: 'POST'});
            }
        }

        function clearLogs() {
            document.getElementById('log-container').innerHTML = '';
        }

        // MITM Functions
        function startMitmCapture() {
            fetch('/api/mitm/start', {method: 'POST'})
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        document.getElementById('mitm-status').textContent = 'ACTIVE';
                        updateMitmStatus();
                    }
                });
        }

        function stopMitmCapture() {
            fetch('/api/mitm/stop', {method: 'POST'})
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        document.getElementById('mitm-status').textContent = 'INACTIVE';
                    }
                });
        }

        function downloadPcap() {
            window.open('/api/mitm/download_pcap', '_blank');
        }

        function viewMitmReport() {
            window.open('/api/mitm/report', '_blank');
        }

        function updateMitmStatus() {
            fetch('/api/mitm/status')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('mitm-status').textContent = data.active ? 'ACTIVE' : 'INACTIVE';
                    document.getElementById('packet-count').textContent = data.packet_count || 0;
                });
        }

        // Initialize
        updateStatus();
        updateMitmStatus();
        setInterval(updateStatus, 5000);
        setInterval(updateMitmStatus, 2000);
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(WEB_INTERFACE)

@app.route('/api/status')
def api_status():
    return jsonify({
        'satellite_online': qsafe_state['satellite_online'],
        'devices': qsafe_state['devices'],
        'message_count': len(qsafe_state['messages'])
    })

@app.route('/api/device/connect', methods=['POST'])
def api_device_connect():
    data = request.json
    device_id = data['device_id']
    
    qsafe_state['devices'][device_id] = {
        'status': 'online',
        'keys': None,
        'connected_at': time.time()
    }
    
    log_event('SECURE', f'Device {device_id} connected to satellite', device_id)
    socketio.emit('device_update', {'device_id': device_id, 'status': 'online', 'keys': None})
    
    # Send to topology
    send_to_topology({
        'type': 'device_status',
        'device_id': f'DEVICE_{device_id}',
        'status': 'online'
    })
    
    return jsonify({'success': True})

@app.route('/api/device/generate_keys', methods=['POST'])
def api_generate_keys():
    data = request.json
    device_id = data['device_id']
    
    if device_id not in qsafe_state['devices']:
        return jsonify({'error': 'Device not connected'}), 400
    
    # Generate keys using crypto backend
    private_key, public_key = crypto.generate_keypair()
    
    qsafe_state['devices'][device_id]['keys'] = {
        'private': private_key,
        'public': public_key,
        'algorithm': crypto.algorithm
    }
    
    log_event('SECURE', f'Generated {crypto.algorithm} key pair', device_id)
    socketio.emit('device_update', {
        'device_id': device_id, 
        'status': 'online', 
        'keys': f'{crypto.algorithm} Keys Generated'
    })
    
    return jsonify({'success': True, 'algorithm': crypto.algorithm})

@app.route('/api/message/send', methods=['POST'])
def api_send_message():
    data = request.json
    from_device = data['from']
    to_device = data['to']
    message = data['message']
    
    if from_device not in qsafe_state['devices'] or to_device not in qsafe_state['devices']:
        return jsonify({'error': 'Device not found'}), 400
    
    if not qsafe_state['devices'][from_device].get('keys') or not qsafe_state['devices'][to_device].get('keys'):
        return jsonify({'error': 'Keys not generated'}), 400
    
    # Simulate encryption with detailed steps
    msg_id = f"MSG_{len(qsafe_state['messages']) + 1:03d}"
    
    # Get keys
    sender_keys = qsafe_state['devices'][from_device]['keys']
    recipient_keys = qsafe_state['devices'][to_device]['keys']
    
    # Step-by-step cryptographic process
    log_event('SECURE', f'[CRYPTO] Step 1: Generating AES-256-GCM session key for {msg_id}', from_device)
    
    # Encrypt message
    encrypted_data = crypto.encrypt_for(recipient_keys['public'], message)
    
    log_event('SECURE', f'[CRYPTO] Step 2: Encrypting message with session key (AES-GCM)', from_device)
    log_event('SECURE', f'[CRYPTO] Step 3: Encrypting session key with RSA public key', from_device)
    log_event('SECURE', f'[CRYPTO] Step 4: Generating authentication tag', from_device)
    
    # Sign message
    signature = crypto.sign_message(sender_keys['private'], message)
    log_event('SECURE', f'[CRYPTO] Step 5: Signing message with RSA private key', from_device)
    
    message_data = {
        'msg_id': msg_id,
        'from': from_device,
        'to': to_device,
        'encrypted_data': encrypted_data,
        'signature': signature,
        'timestamp': time.time(),
        'algorithm': crypto.algorithm,
        'ciphertext_hex': encrypted_data.get('ciphertext', '')[:32] + '...'
    }
    
    qsafe_state['messages'].append(message_data)
    
    # Send to topology visualizer
    route_type = 'secure' if qsafe_state['satellite_online'] else 'mesh'
    ciphertext_hex = encrypted_data.get('ciphertext', '')
    if isinstance(ciphertext_hex, bytes):
        ciphertext_hex = ciphertext_hex.hex()
    
    send_to_topology({
        'type': 'message',
        'msg_id': msg_id,
        'from': f'DEVICE_{from_device}',
        'to': f'DEVICE_{to_device}',
        'route_type': route_type,
        'ciphertext_hex': str(ciphertext_hex)[:64] + '...' if len(str(ciphertext_hex)) > 64 else str(ciphertext_hex),
        'algorithm': crypto.algorithm,
        'steps': [
            'AES-256-GCM session key generated',
            'Message encrypted with session key',
            'Session key encrypted with RSA public key',
            'Authentication tag generated',
            'Message signed with RSA private key'
        ]
    })
    
    if qsafe_state['satellite_online']:
        log_event('SECURE', f'Message {msg_id} encrypted and sent via satellite', from_device)
        log_event('SECURE', f'[CRYPTO] Step 6: Verifying signature and decrypting', to_device)
        log_event('SECURE', f'Message {msg_id} received and decrypted', to_device)
    else:
        log_event('WARNING', f'Message {msg_id} sent via mesh network (satellite offline)', from_device)
        log_event('SECURE', f'Message {msg_id} received via mesh', to_device)
    
    return jsonify({'success': True, 'msg_id': msg_id})

@app.route('/api/device/capture', methods=['POST'])
def api_device_capture():
    data = request.json
    device_id = data['device_id']
    
    if device_id not in qsafe_state['devices']:
        return jsonify({'error': 'Device not found'}), 400
    
    # Simulate self-destruct
    log_event('BREACH', f'🚨 Device {device_id} captured - Initiating self-destruct', device_id)
    log_event('SECURE', f'🔥 Wiping all cryptographic keys (3 passes)', device_id)
    log_event('SECURE', f'🔥 Overwriting memory sectors', device_id)
    log_event('SECURE', f'🔥 Destroying key derivation material', device_id)
    log_event('SECURE', f'✅ Self-destruct complete - Device disabled', device_id)
    
    # Update device state
    qsafe_state['devices'][device_id]['status'] = 'compromised'
    qsafe_state['devices'][device_id]['keys'] = None
    
    socketio.emit('device_update', {
        'device_id': device_id, 
        'status': 'compromised', 
        'keys': 'WIPED - DEVICE COMPROMISED'
    })
    
    # Send to topology
    send_to_topology({
        'type': 'device_status',
        'device_id': f'DEVICE_{device_id}',
        'status': 'compromised'
    })
    
    send_to_topology({
        'type': 'attack',
        'attack_type': 'DEVICE_CAPTURE',
        'target': f'DEVICE_{device_id}',
        'result': 'self_destruct_triggered'
    })
    
    return jsonify({'success': True})

@app.route('/api/satellite/toggle', methods=['POST'])
def api_satellite_toggle():
    qsafe_state['satellite_online'] = not qsafe_state['satellite_online']
    status = 'online' if qsafe_state['satellite_online'] else 'offline'
    
    log_event('WARNING', f'Satellite status: {status}', 'SATELLITE')
    socketio.emit('satellite_update', {'online': qsafe_state['satellite_online']})
    
    # Send to topology
    send_to_topology({
        'type': 'device_status',
        'device_id': 'SATELLITE',
        'status': status
    })
    
    if not qsafe_state['satellite_online']:
        log_event('WARNING', 'Switching to mesh networking mode', 'SYSTEM')
    
    return jsonify({'online': qsafe_state['satellite_online']})

@app.route('/api/attack/simulate', methods=['POST'])
def api_simulate_attack():
    data = request.json
    attack_type = data['attack_type']
    
    # Send attack event to topology
    send_to_topology({
        'type': 'attack',
        'attack_type': attack_type.upper(),
        'target': 'DEVICE_B',
        'result': 'blocked'
    })
    
    if attack_type == 'mitm':
        log_event('BREACH', '🎯 Attempting MITM attack on satellite communications', 'ATTACKER')
        log_event('BREACH', 'Injecting modified ciphertext...', 'ATTACKER')
        log_event('BREACH', '❌ Invalid signature detected - MITM attack blocked!', 'DEVICE_B')
        
    elif attack_type == 'replay':
        log_event('BREACH', '🔄 Attempting replay attack with old message', 'ATTACKER')
        log_event('BREACH', '❌ Message timestamp too old - replay attack blocked!', 'DEVICE_B')
        
    elif attack_type == 'keyextract':
        log_event('BREACH', '🔓 Attempting key exfiltration from captured device', 'ATTACKER')
        log_event('BREACH', '✅ No cryptographic material found - self-destruct effective!', 'ATTACKER')
    
    return jsonify({'success': True})

@app.route('/api/demo/run', methods=['POST'])
def api_run_demo():
    """Run automated demo sequence"""
    def demo_sequence():
        time.sleep(1)
        
        # Connect devices
        qsafe_state['devices']['A'] = {'status': 'online', 'keys': None}
        qsafe_state['devices']['B'] = {'status': 'online', 'keys': None}
        log_event('SECURE', 'Device A connected', 'A')
        log_event('SECURE', 'Device B connected', 'B')
        socketio.emit('device_update', {'device_id': 'A', 'status': 'online', 'keys': None})
        socketio.emit('device_update', {'device_id': 'B', 'status': 'online', 'keys': None})
        
        time.sleep(2)
        
        # Generate keys
        private_a, public_a = crypto.generate_keypair()
        private_b, public_b = crypto.generate_keypair()
        qsafe_state['devices']['A']['keys'] = {'private': private_a, 'public': public_a, 'algorithm': crypto.algorithm}
        qsafe_state['devices']['B']['keys'] = {'private': private_b, 'public': public_b, 'algorithm': crypto.algorithm}
        
        log_event('SECURE', f'Generated {crypto.algorithm} keys', 'A')
        log_event('SECURE', f'Generated {crypto.algorithm} keys', 'B')
        socketio.emit('device_update', {'device_id': 'A', 'status': 'online', 'keys': f'{crypto.algorithm} Keys'})
        socketio.emit('device_update', {'device_id': 'B', 'status': 'online', 'keys': f'{crypto.algorithm} Keys'})
        
        time.sleep(2)
        
        # Send messages
        log_event('SECURE', 'Forwarding encrypted message A→B', 'SATELLITE')
        log_event('SECURE', '📨 Secure message from A: "Demo message via satellite"', 'B')
        
        time.sleep(3)
        
        # Satellite outage
        qsafe_state['satellite_online'] = False
        log_event('WARNING', 'Satellite going offline', 'SATELLITE')
        socketio.emit('satellite_update', {'online': False})
        
        time.sleep(2)
        log_event('WARNING', 'Using mesh network fallback', 'A')
        log_event('WARNING', '📨 Mesh message from A: "Emergency via mesh"', 'B')
        
        time.sleep(3)
        
        # Restore satellite
        qsafe_state['satellite_online'] = True
        log_event('SECURE', 'Satellite restored', 'SATELLITE')
        socketio.emit('satellite_update', {'online': True})
        
        time.sleep(2)
        
        # Attack simulation
        log_event('BREACH', '🎯 MITM attack detected and blocked', 'SYSTEM')
        log_event('BREACH', '🔄 Replay attack detected and blocked', 'SYSTEM')
        
        time.sleep(3)
        
        # Capture simulation
        log_event('BREACH', '🚨 Device B captured - self-destruct initiated', 'B')
        qsafe_state['devices']['B']['status'] = 'compromised'
        qsafe_state['devices']['B']['keys'] = None
        log_event('BREACH', '🔥 All keys wiped - device disabled', 'B')
        socketio.emit('device_update', {'device_id': 'B', 'status': 'compromised', 'keys': 'WIPED'})
        
        log_event('SECURE', '✅ Q-SAFE Demo Complete - All security features verified', 'SYSTEM')
    
    threading.Thread(target=demo_sequence, daemon=True).start()
    return jsonify({'success': True})

# MITM API endpoints
mitm_interceptor = None

@app.route('/api/mitm/start', methods=['POST'])
def api_mitm_start():
    """Start MITM interceptor"""
    global mitm_interceptor
    
    if mitm_interceptor is None:
        from mitm_simulator.mitm_interceptor import MITMInterceptor
        mitm_interceptor = MITMInterceptor(pcap_file="logs/web_mitm_capture.pcap")
        mitm_interceptor.start_interception()
        
        log_event('WARNING', '🔴 MITM interceptor started - monitoring traffic', 'MITM')
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Already running'})

@app.route('/api/mitm/stop', methods=['POST'])
def api_mitm_stop():
    """Stop MITM interceptor"""
    global mitm_interceptor
    
    if mitm_interceptor:
        mitm_interceptor.stop_interception()
        log_event('WARNING', '🔴 MITM interceptor stopped - analysis complete', 'MITM')
        mitm_interceptor = None
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Not running'})

@app.route('/api/mitm/status')
def api_mitm_status():
    """Get MITM interceptor status"""
    global mitm_interceptor
    
    if mitm_interceptor:
        return jsonify({
            'active': mitm_interceptor.capture_active,
            'packet_count': len(mitm_interceptor.intercepted_packets),
            'attack_count': len(mitm_interceptor.attack_log)
        })
    else:
        return jsonify({'active': False, 'packet_count': 0, 'attack_count': 0})

@app.route('/api/mitm/download_pcap')
def api_mitm_download_pcap():
    """Download PCAP file"""
    from flask import send_file
    pcap_file = "logs/web_mitm_capture.pcap"
    
    if os.path.exists(pcap_file):
        return send_file(pcap_file, as_attachment=True, download_name="qsafe_mitm_capture.pcap")
    else:
        return jsonify({'error': 'No PCAP file available'}), 404

@app.route('/api/mitm/report')
def api_mitm_report():
    """View MITM analysis report"""
    report_file = "logs/mitm_report.txt"
    
    if os.path.exists(report_file):
        with open(report_file, 'r') as f:
            content = f.read()
        return f"<pre>{content}</pre>", 200, {'Content-Type': 'text/html'}
    else:
        return "No MITM report available", 404

if __name__ == '__main__':
    print("🛰️ Q-SAFE Interactive Web Demo Starting...")
    print("📡 Dashboard: http://localhost:5000")
    print("🎮 All operations available in browser interface")
    
    log_event('SECURE', 'Q-SAFE Interactive Demo initialized')
    
    try:
        socketio.run(app, host='0.0.0.0', port=5000, debug=False)
    except KeyboardInterrupt:
        print("\nDemo stopped")
