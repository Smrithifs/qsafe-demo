"""
Q-SAFE Satellite Server
Central relay server that forwards encrypted messages without decryption capability.
"""

import json
import time
import threading
from datetime import datetime
from typing import Dict, List, Optional
from flask import Flask, request, jsonify, render_template_string
from flask_socketio import SocketIO, emit, join_room, leave_room
import colorama
from colorama import Fore, Style
import os
import sys

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

colorama.init()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'qsafe-demo-secret'
socketio = SocketIO(app, cors_allowed_origins="*")

class SatelliteServer:
    def __init__(self):
        self.devices: Dict[str, Dict] = {}  # device_id -> {socket_id, public_key, last_seen}
        self.message_queue: Dict[str, List] = {}  # device_id -> [messages]
        self.event_log: List[Dict] = []
        self.is_online = True
        self.lock = threading.Lock()
        
    def log_event(self, event_type: str, message: str, device_id: str = None):
        """Log events with color coding and timestamps."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Color coding
        if event_type == "SECURE":
            color = Fore.GREEN
        elif event_type == "WARNING":
            color = Fore.YELLOW
        elif event_type == "BREACH":
            color = Fore.RED
        else:
            color = Fore.WHITE
            
        log_entry = {
            'timestamp': timestamp,
            'type': event_type,
            'message': message,
            'device_id': device_id,
            'color': event_type.lower()
        }
        
        with self.lock:
            self.event_log.append(log_entry)
            
        # Print to console
        device_prefix = f"[{device_id}]" if device_id else "[SATELLITE]"
        print(f"{color}[{timestamp}] {device_prefix} [{event_type}] {message}{Style.RESET_ALL}")
        
        # Emit to dashboard
        socketio.emit('log_event', log_entry, room='dashboard')
    
    def register_device(self, device_id: str, public_key: str, socket_id: str):
        """Register a device with the satellite."""
        with self.lock:
            self.devices[device_id] = {
                'socket_id': socket_id,
                'public_key': public_key,
                'last_seen': time.time(),
                'status': 'online'
            }
            
            if device_id not in self.message_queue:
                self.message_queue[device_id] = []
        
        self.log_event("SECURE", f"Device registered successfully", device_id)
        socketio.emit('device_update', self.get_device_status(), room='dashboard')
    
    def unregister_device(self, device_id: str):
        """Unregister a device."""
        with self.lock:
            if device_id in self.devices:
                del self.devices[device_id]
        
        self.log_event("WARNING", f"Device disconnected", device_id)
        socketio.emit('device_update', self.get_device_status(), room='dashboard')
    
    def forward_message(self, from_device: str, to_device: str, encrypted_message: Dict):
        """Forward encrypted message to recipient (satellite cannot decrypt)."""
        if not self.is_online:
            self.log_event("WARNING", "Satellite offline - message dropped", from_device)
            return False
            
        # Demonstrate that satellite only sees ciphertext
        ciphertext_preview = encrypted_message.get('ciphertext', '')[:32] + "..."
        self.log_event("SECURE", f"Forwarding ciphertext to {to_device}: {ciphertext_preview}", from_device)
        
        with self.lock:
            # Add to recipient's queue
            if to_device not in self.message_queue:
                self.message_queue[to_device] = []
            
            message_envelope = {
                'from': from_device,
                'to': to_device,
                'encrypted_data': encrypted_message,
                'timestamp': time.time(),
                'satellite_id': f"sat_{int(time.time())}"
            }
            
            self.message_queue[to_device].append(message_envelope)
            
            # If recipient is online, deliver immediately
            if to_device in self.devices:
                recipient_socket = self.devices[to_device]['socket_id']
                socketio.emit('new_message', message_envelope, room=recipient_socket)
                self.log_event("SECURE", f"Message delivered to {to_device}", from_device)
            else:
                self.log_event("WARNING", f"Recipient {to_device} offline - queued", from_device)
        
        return True
    
    def get_queued_messages(self, device_id: str) -> List[Dict]:
        """Get queued messages for a device."""
        with self.lock:
            messages = self.message_queue.get(device_id, [])
            self.message_queue[device_id] = []  # Clear queue
            return messages
    
    def get_device_status(self) -> Dict:
        """Get current device status for dashboard."""
        with self.lock:
            return {
                'devices': dict(self.devices),
                'satellite_online': self.is_online,
                'total_devices': len(self.devices)
            }
    
    def toggle_satellite(self) -> bool:
        """Toggle satellite online/offline status."""
        self.is_online = not self.is_online
        status = "ONLINE" if self.is_online else "OFFLINE"
        self.log_event("WARNING", f"Satellite status: {status}")
        socketio.emit('satellite_status', {'online': self.is_online}, room='dashboard')
        return self.is_online

# Global satellite instance
satellite = SatelliteServer()

# WebSocket Events
@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    print(f"Client disconnected: {request.sid}")
    # Find and unregister device
    for device_id, device_info in list(satellite.devices.items()):
        if device_info['socket_id'] == request.sid:
            satellite.unregister_device(device_id)
            break

@socketio.on('register_device')
def handle_device_registration(data):
    """Handle device registration."""
    device_id = data.get('device_id')
    public_key = data.get('public_key')
    
    if not device_id or not public_key:
        emit('registration_error', {'error': 'Missing device_id or public_key'})
        return
    
    satellite.register_device(device_id, public_key, request.sid)
    
    # Send queued messages
    queued_messages = satellite.get_queued_messages(device_id)
    if queued_messages:
        emit('queued_messages', {'messages': queued_messages})
    
    emit('registration_success', {'device_id': device_id})

@socketio.on('send_message')
def handle_send_message(data):
    """Handle message forwarding request."""
    from_device = data.get('from')
    to_device = data.get('to')
    encrypted_message = data.get('encrypted_data')
    
    if not all([from_device, to_device, encrypted_message]):
        emit('send_error', {'error': 'Missing required fields'})
        return
    
    success = satellite.forward_message(from_device, to_device, encrypted_message)
    
    if success:
        emit('send_success', {'message_id': f"msg_{int(time.time())}"})
    else:
        emit('send_error', {'error': 'Satellite offline'})

@socketio.on('join_dashboard')
def handle_join_dashboard():
    """Handle dashboard client joining."""
    join_room('dashboard')
    emit('dashboard_init', {
        'devices': satellite.get_device_status(),
        'recent_logs': satellite.event_log[-50:]  # Last 50 events
    })

@socketio.on('toggle_satellite')
def handle_toggle_satellite():
    """Handle satellite toggle from dashboard."""
    new_status = satellite.toggle_satellite()
    emit('satellite_toggled', {'online': new_status}, room='dashboard')

@socketio.on('trigger_capture')
def handle_trigger_capture(data):
    """Handle capture trigger from dashboard."""
    device_id = data.get('device_id')
    if device_id in satellite.devices:
        socket_id = satellite.devices[device_id]['socket_id']
        socketio.emit('capture_triggered', {}, room=socket_id)
        satellite.log_event("BREACH", f"Capture simulation triggered", device_id)

# REST API Endpoints
@app.route('/api/status')
def api_status():
    """Get satellite status."""
    return jsonify({
        'online': satellite.is_online,
        'devices': satellite.get_device_status(),
        'uptime': time.time()
    })

@app.route('/api/toggle', methods=['POST'])
def api_toggle():
    """Toggle satellite status."""
    new_status = satellite.toggle_satellite()
    return jsonify({'online': new_status})

@app.route('/api/devices')
def api_devices():
    """Get device list."""
    return jsonify(satellite.get_device_status())

@app.route('/api/logs')
def api_logs():
    """Get recent logs."""
    return jsonify({'logs': satellite.event_log[-100:]})

# Dashboard HTML
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Q-SAFE Satellite Dashboard</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <style>
        body { font-family: monospace; background: #000; color: #0f0; margin: 0; padding: 20px; }
        .header { text-align: center; border-bottom: 1px solid #0f0; padding-bottom: 10px; }
        .section { margin: 20px 0; padding: 10px; border: 1px solid #333; }
        .device { padding: 5px; margin: 5px 0; background: #111; }
        .online { color: #0f0; }
        .offline { color: #f00; }
        .log-entry { padding: 2px 0; font-size: 12px; }
        .secure { color: #0f0; }
        .warning { color: #ff0; }
        .breach { color: #f00; }
        button { background: #333; color: #0f0; border: 1px solid #0f0; padding: 5px 10px; margin: 5px; cursor: pointer; }
        button:hover { background: #0f0; color: #000; }
        #logs { height: 300px; overflow-y: scroll; background: #111; padding: 10px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛰️ Q-SAFE SATELLITE DASHBOARD</h1>
        <div>Status: <span id="satellite-status" class="online">ONLINE</span></div>
    </div>
    
    <div class="section">
        <h3>Controls</h3>
        <button onclick="toggleSatellite()">Toggle Satellite</button>
        <button onclick="triggerCapture()">Trigger Capture (Device A)</button>
    </div>
    
    <div class="section">
        <h3>Connected Devices (<span id="device-count">0</span>)</h3>
        <div id="devices"></div>
    </div>
    
    <div class="section">
        <h3>Live Event Log</h3>
        <div id="logs"></div>
    </div>

    <script>
        const socket = io();
        
        socket.on('connect', function() {
            socket.emit('join_dashboard');
        });
        
        socket.on('dashboard_init', function(data) {
            updateDevices(data.devices);
            data.recent_logs.forEach(log => addLogEntry(log));
        });
        
        socket.on('device_update', function(data) {
            updateDevices(data);
        });
        
        socket.on('satellite_status', function(data) {
            document.getElementById('satellite-status').textContent = data.online ? 'ONLINE' : 'OFFLINE';
            document.getElementById('satellite-status').className = data.online ? 'online' : 'offline';
        });
        
        socket.on('log_event', function(log) {
            addLogEntry(log);
        });
        
        function updateDevices(deviceData) {
            const devicesDiv = document.getElementById('devices');
            const devices = deviceData.devices || {};
            
            document.getElementById('device-count').textContent = Object.keys(devices).length;
            
            devicesDiv.innerHTML = '';
            for (const [deviceId, info] of Object.entries(devices)) {
                const deviceDiv = document.createElement('div');
                deviceDiv.className = 'device';
                deviceDiv.innerHTML = `
                    <strong>${deviceId}</strong> - 
                    <span class="${info.status === 'online' ? 'online' : 'offline'}">${info.status.toUpperCase()}</span>
                    (Last seen: ${new Date(info.last_seen * 1000).toLocaleTimeString()})
                `;
                devicesDiv.appendChild(deviceDiv);
            }
        }
        
        function addLogEntry(log) {
            const logsDiv = document.getElementById('logs');
            const logDiv = document.createElement('div');
            logDiv.className = `log-entry ${log.color}`;
            
            const devicePrefix = log.device_id ? `[${log.device_id}]` : '[SATELLITE]';
            logDiv.textContent = `[${log.timestamp}] ${devicePrefix} [${log.type}] ${log.message}`;
            
            logsDiv.appendChild(logDiv);
            logsDiv.scrollTop = logsDiv.scrollHeight;
            
            // Keep only last 100 entries
            while (logsDiv.children.length > 100) {
                logsDiv.removeChild(logsDiv.firstChild);
            }
        }
        
        function toggleSatellite() {
            socket.emit('toggle_satellite');
        }
        
        function triggerCapture() {
            socket.emit('trigger_capture', {device_id: 'A'});
        }
    </script>
</body>
</html>
"""

@app.route('/')
def dashboard():
    """Serve the dashboard."""
    return render_template_string(DASHBOARD_HTML)

if __name__ == '__main__':
    print(f"{Fore.CYAN}🛰️  Q-SAFE Satellite Server Starting...{Style.RESET_ALL}")
    print(f"{Fore.CYAN}📡 Dashboard: http://localhost:5000{Style.RESET_ALL}")
    print(f"{Fore.CYAN}🔒 Security: Satellite cannot decrypt messages{Style.RESET_ALL}")
    
    satellite.log_event("SECURE", "Satellite server initialized")
    
    try:
        socketio.run(app, host='0.0.0.0', port=5000, debug=False)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Satellite server shutting down...{Style.RESET_ALL}")
        satellite.log_event("WARNING", "Satellite server shutdown")
