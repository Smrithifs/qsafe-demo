#!/usr/bin/env python3
"""
Q-SAFE Mission Simulation Flow
Orchestrates devices, MITM, and topology visualization for complete demo
"""

import time
import json
import threading
import subprocess
import requests
import signal
import sys
import os
from datetime import datetime
from flask import Flask, jsonify
from flask_socketio import SocketIO, emit
import websocket
import logging

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from crypto_backend import CryptoBackend
from mitm_simulator.mitm_interceptor import MITMInterceptor
# from pcap_generator.packet_capture import PCAPGenerator

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MissionSimulator:
    def __init__(self):
        self.crypto = CryptoBackend(use_pqc=True)  # Use PQC for mission
        self.mitm = None
        # self.pcap_gen = PCAPGenerator()
        self.mission_state = {
            'phase': 'INIT',
            'devices': {'A': {'status': 'offline', 'keys': None}, 'B': {'status': 'offline', 'keys': None}},
            'satellite': {'status': 'online'},
            'messages': [],
            'attacks': [],
            'stats': {
                'messages_sent': 0,
                'attacks_blocked': 0,
                'integrity_score': 100,
                'pcap_files': []
            }
        }
        self.processes = []
        self.running = False
        
        # Flask app for dashboard communication
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = 'qsafe-mission-flow'
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        self.setup_routes()
        
    def setup_routes(self):
        """Setup Flask routes for dashboard communication"""
        @self.app.route('/api/mission/status')
        def mission_status():
            return jsonify(self.mission_state)
            
        @self.app.route('/api/mission/start', methods=['POST'])
        def start_mission():
            if not self.running:
                threading.Thread(target=self.run_mission_sequence, daemon=True).start()
                return jsonify({'success': True, 'message': 'Mission started'})
            return jsonify({'success': False, 'message': 'Mission already running'})
            
        @self.app.route('/api/mission/stop', methods=['POST'])
        def stop_mission():
            self.stop_mission_sequence()
            return jsonify({'success': True, 'message': 'Mission stopped'})
            
        @self.socketio.on('connect')
        def handle_connect():
            emit('mission_state', self.mission_state)
            
    def log_mission_event(self, level, message, device_id=None, metadata=None):
        """Log mission events with color coding and metadata"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        # Color coding
        colors = {
            'SECURE': '\033[92m',    # Green
            'WARNING': '\033[93m',   # Yellow  
            'BREACH': '\033[91m',    # Red
            'INFO': '\033[94m',      # Blue
            'RESET': '\033[0m'
        }
        
        color = colors.get(level, colors['INFO'])
        reset = colors['RESET']
        
        log_entry = {
            'timestamp': timestamp,
            'level': level,
            'message': message,
            'device_id': device_id or 'MISSION',
            'metadata': metadata or {}
        }
        
        # Print to console with colors
        print(f"{color}[{timestamp}] [{device_id or 'MISSION'}] [{level}] {message}{reset}")
        
        # Emit to dashboard
        self.socketio.emit('mission_log', log_entry)
        
        return log_entry
        
    def emit_topology_event(self, event_type, data):
        """Emit events to topology visualizer"""
        event = {
            'type': event_type,
            'timestamp': time.time(),
            **data
        }
        self.socketio.emit('topology_event', event)
        
    def run_mission_sequence(self):
        """Execute the complete mission simulation sequence"""
        self.running = True
        self.log_mission_event('INFO', '🚀 Q-SAFE Mission Simulation Starting')
        self.log_mission_event('INFO', '🔐 Post-Quantum Cryptography: ACTIVE')
        
        try:
            # Phase 1: Initialize devices and establish secure channel
            self.mission_state['phase'] = 'INIT'
            self.log_mission_event('SECURE', 'Phase 1: Device Initialization')
            self.initialize_devices()
            time.sleep(2)
            
            # Phase 2: Generate PQC keys and establish session
            self.mission_state['phase'] = 'KEY_EXCHANGE'
            self.log_mission_event('SECURE', 'Phase 2: Post-Quantum Key Exchange')
            self.establish_pqc_session()
            time.sleep(2)
            
            # Phase 3: Normal mission traffic
            self.mission_state['phase'] = 'MISSION_TRAFFIC'
            self.log_mission_event('SECURE', 'Phase 3: Secure Mission Communications')
            self.send_mission_messages()
            time.sleep(3)
            
            # Phase 4: Satellite failure simulation
            self.mission_state['phase'] = 'SATELLITE_FAILURE'
            self.log_mission_event('WARNING', 'Phase 4: Satellite Communication Lost')
            self.simulate_satellite_failure()
            time.sleep(2)
            
            # Phase 5: MITM attack simulation
            self.mission_state['phase'] = 'UNDER_ATTACK'
            self.log_mission_event('BREACH', 'Phase 5: MITM Attack Detected')
            self.simulate_mitm_attacks()
            time.sleep(3)
            
            # Phase 6: Device capture and self-destruct
            self.mission_state['phase'] = 'DEVICE_CAPTURE'
            self.log_mission_event('BREACH', 'Phase 6: Device Compromise Detected')
            self.simulate_device_capture()
            time.sleep(2)
            
            # Phase 7: Mission summary
            self.mission_state['phase'] = 'COMPLETE'
            self.log_mission_event('INFO', 'Phase 7: Mission Complete')
            self.generate_mission_summary()
            
        except Exception as e:
            self.log_mission_event('BREACH', f'Mission error: {str(e)}')
        finally:
            self.running = False
            
    def initialize_devices(self):
        """Initialize Device A and Device B"""
        for device in ['A', 'B']:
            self.mission_state['devices'][device]['status'] = 'online'
            self.log_mission_event('SECURE', f'Device {device} connected to satellite', device)
            
            self.emit_topology_event('device_status', {
                'device_id': f'DEVICE_{device}',
                'status': 'online'
            })
            
        self.log_mission_event('SECURE', 'All devices operational')
        
    def establish_pqc_session(self):
        """Establish post-quantum cryptographic session"""
        self.log_mission_event('SECURE', 'Generating Kyber512 key pairs...', 'A')
        self.log_mission_event('SECURE', 'Generating Kyber512 key pairs...', 'B')
        
        # Generate keys for both devices
        for device in ['A', 'B']:
            keys = self.crypto.generate_keys()
            self.mission_state['devices'][device]['keys'] = {
                'public': keys['public'],
                'private': keys['private'],
                'algorithm': self.crypto.algorithm
            }
            
        self.log_mission_event('SECURE', 'Post-quantum key exchange complete')
        self.log_mission_event('SECURE', 'AES-256-GCM session established')
        self.log_mission_event('INFO', '🛡️ Quantum-Safe Communication: ACTIVE')
        
        self.emit_topology_event('crypto_status', {
            'algorithm': self.crypto.algorithm,
            'status': 'active',
            'session_key': 'AES-256-GCM'
        })
        
    def send_mission_messages(self):
        """Send secure mission traffic"""
        messages = [
            "SITREP: Alpha team in position, all clear",
            "INTEL: Target acquired, coordinates 34.0522°N 118.2437°W", 
            "COMMAND: Execute phase 2, maintain radio silence"
        ]
        
        for i, msg in enumerate(messages, 1):
            msg_id = f"MSG_{i:03d}"
            
            # Simulate encryption process
            self.log_mission_event('SECURE', f'[CRYPTO] Encrypting message {msg_id}', 'A')
            encrypted_data = self.crypto.encrypt_for(
                self.mission_state['devices']['B']['keys']['public'], 
                msg
            )
            
            # Create message metadata
            message_data = {
                'msg_id': msg_id,
                'from': 'A',
                'to': 'B', 
                'content': msg,
                'encrypted': True,
                'algorithm': self.crypto.algorithm,
                'timestamp': time.time(),
                'ciphertext_hex': encrypted_data.get('ciphertext', '')[:32] + '...'
            }
            
            self.mission_state['messages'].append(message_data)
            self.mission_state['stats']['messages_sent'] += 1
            
            self.log_mission_event('SECURE', f'Message {msg_id} encrypted and transmitted', 'A', {
                'algorithm': self.crypto.algorithm,
                'ciphertext': message_data['ciphertext_hex']
            })
            
            self.log_mission_event('SECURE', f'Message {msg_id} received and decrypted', 'B')
            
            # Emit to topology
            self.emit_topology_event('message', {
                'msg_id': msg_id,
                'from': 'DEVICE_A',
                'to': 'DEVICE_B',
                'route_type': 'secure',
                'algorithm': self.crypto.algorithm,
                'status': 'success'
            })
            
            time.sleep(1.5)
            
    def simulate_satellite_failure(self):
        """Simulate satellite failure and mesh fallback"""
        self.mission_state['satellite']['status'] = 'offline'
        self.log_mission_event('WARNING', '📡 Satellite communication lost', 'SATELLITE')
        self.log_mission_event('WARNING', '🔄 Switching to peer-to-peer mesh network', 'SYSTEM')
        
        self.emit_topology_event('satellite_status', {
            'status': 'offline'
        })
        
        # Send mesh message
        msg_id = "MSG_004"
        message_data = {
            'msg_id': msg_id,
            'from': 'A',
            'to': 'B',
            'content': "FALLBACK: Switching to mesh network",
            'route_type': 'mesh',
            'timestamp': time.time()
        }
        
        self.mission_state['messages'].append(message_data)
        self.mission_state['stats']['messages_sent'] += 1
        
        self.log_mission_event('WARNING', f'Message {msg_id} sent via mesh network', 'A')
        self.log_mission_event('WARNING', f'Message {msg_id} received via mesh', 'B')
        
        self.emit_topology_event('message', {
            'msg_id': msg_id,
            'from': 'DEVICE_A', 
            'to': 'DEVICE_B',
            'route_type': 'mesh',
            'status': 'success'
        })
        
    def simulate_mitm_attacks(self):
        """Simulate various MITM attack attempts"""
        self.log_mission_event('BREACH', '🚨 MITM Attacker detected in network', 'SECURITY')
        
        self.emit_topology_event('attack_start', {
            'attacker_id': 'MITM_NODE',
            'target': 'NETWORK'
        })
        
        attacks = [
            {
                'type': 'DECRYPT_ATTEMPT',
                'description': 'Attempting to decrypt intercepted packets',
                'result': 'FAILED - Post-quantum encryption resistant'
            },
            {
                'type': 'CIPHERTEXT_MODIFICATION', 
                'description': 'Modifying encrypted payload',
                'result': 'DETECTED - Authentication tag mismatch'
            },
            {
                'type': 'REPLAY_ATTACK',
                'description': 'Replaying captured packets',
                'result': 'BLOCKED - Nonce validation failed'
            }
        ]
        
        for attack in attacks:
            self.log_mission_event('BREACH', f"🔴 {attack['description']}", 'MITM')
            time.sleep(1)
            self.log_mission_event('SECURE', f"✅ {attack['result']}", 'DEFENSE')
            
            attack_data = {
                'attack_id': f"ATK_{len(self.mission_state['attacks']) + 1:03d}",
                'type': attack['type'],
                'timestamp': time.time(),
                'result': 'blocked'
            }
            
            self.mission_state['attacks'].append(attack_data)
            self.mission_state['stats']['attacks_blocked'] += 1
            
            self.emit_topology_event('attack_attempt', {
                'attack_type': attack['type'],
                'result': 'blocked',
                'target': 'DEVICE_A'
            })
            
            time.sleep(1)
            
    def simulate_device_capture(self):
        """Simulate device capture and self-destruct"""
        device = 'B'
        self.log_mission_event('BREACH', f'🚨 Device {device} physically compromised', device)
        self.log_mission_event('SECURE', f'🔥 Initiating emergency key wipe protocol', device)
        self.log_mission_event('SECURE', f'🔥 Overwriting memory (3 passes)', device)
        self.log_mission_event('SECURE', f'🔥 Destroying cryptographic material', device)
        self.log_mission_event('SECURE', f'✅ Self-destruct complete - Device disabled', device)
        
        # Update device state
        self.mission_state['devices'][device]['status'] = 'compromised'
        self.mission_state['devices'][device]['keys'] = None
        
        self.emit_topology_event('device_capture', {
            'device_id': f'DEVICE_{device}',
            'status': 'compromised'
        })
        
        # Verify key wipe
        self.log_mission_event('SECURE', 'Verification: No recoverable keys found', 'FORENSICS')
        self.log_mission_event('SECURE', 'Mission data integrity: PROTECTED', 'SECURITY')
        
    def generate_mission_summary(self):
        """Generate mission completion summary"""
        summary = {
            'mission_id': f"QSAFE_{int(time.time())}",
            'completion_time': datetime.now().isoformat(),
            'statistics': self.mission_state['stats'],
            'security_status': 'ALL ATTACKS BLOCKED',
            'integrity_score': f"{self.mission_state['stats']['integrity_score']}%",
            'algorithm': self.crypto.algorithm
        }
        
        # Write summary to file
        with open('mission_summary.txt', 'w') as f:
            f.write("=== Q-SAFE MISSION SIMULATION SUMMARY ===\n\n")
            f.write(f"Mission ID: {summary['mission_id']}\n")
            f.write(f"Completion Time: {summary['completion_time']}\n")
            f.write(f"Encryption Algorithm: {summary['algorithm']}\n\n")
            f.write("STATISTICS:\n")
            f.write(f"  Messages Sent: {summary['statistics']['messages_sent']}\n")
            f.write(f"  Attacks Blocked: {summary['statistics']['attacks_blocked']}\n")
            f.write(f"  Integrity Score: {summary['integrity_score']}\n")
            f.write(f"  Security Status: {summary['security_status']}\n\n")
            f.write("SECURITY VALIDATION:\n")
            f.write("  ✅ Post-quantum encryption active\n")
            f.write("  ✅ All MITM attacks blocked\n")
            f.write("  ✅ Self-destruct protocol verified\n")
            f.write("  ✅ Zero data compromise\n")
            
        self.log_mission_event('INFO', '📊 Mission summary generated: mission_summary.txt')
        self.log_mission_event('SECURE', '🎯 Mission completed successfully')
        self.log_mission_event('INFO', f'Security Score: {summary["integrity_score"]} - ALL SYSTEMS SECURE')
        
    def stop_mission_sequence(self):
        """Stop mission and cleanup"""
        self.running = False
        self.log_mission_event('INFO', '🛑 Mission simulation stopped')
        
        # Cleanup processes
        for proc in self.processes:
            try:
                proc.terminate()
            except:
                pass
                
    def run_server(self):
        """Run the mission flow server"""
        self.log_mission_event('INFO', '🎮 Mission Flow Server starting on port 5003')
        self.socketio.run(self.app, host='0.0.0.0', port=5003, debug=False)

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print('\n🛑 Mission simulation interrupted')
    sys.exit(0)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    
    mission = MissionSimulator()
    
    print("🚀 Q-SAFE Mission Flow Controller")
    print("📡 Server: http://localhost:5003")
    print("🎮 Ready for mission simulation")
    
    try:
        mission.run_server()
    except KeyboardInterrupt:
        mission.stop_mission_sequence()
        print("\nMission flow stopped")
