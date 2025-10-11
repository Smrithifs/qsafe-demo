"""
Q-SAFE Device Client
Secure device with PQC encryption, mesh fallback, and self-destruct capability.
"""

import os
import sys
import json
import time
import argparse
import threading
import socket
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import socketio
import colorama
from colorama import Fore, Style
from Crypto.Random import get_random_bytes

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from crypto_backend import CryptoBackend

colorama.init()

class DeviceClient:
    def __init__(self, device_id: str, satellite_url: str = "http://localhost:5000"):
        self.device_id = device_id
        self.satellite_url = satellite_url
        self.crypto = CryptoBackend()
        
        # Device state
        self.is_compromised = False
        self.private_key: Optional[bytes] = None
        self.public_key: Optional[bytes] = None
        self.device_passphrase: Optional[str] = None
        
        # Networking
        self.sio = socketio.Client()
        self.satellite_connected = False
        self.peer_devices: Dict[str, Dict] = {}  # device_id -> {ip, port, public_key}
        self.mesh_server_port = 6000 + hash(device_id) % 1000  # Unique port per device
        
        # Message tracking
        self.message_history: List[Dict] = []
        self.nonce_cache: set = set()  # For replay protection
        
        # Setup directories
        self.device_dir = f"device/data/{device_id}"
        os.makedirs(self.device_dir, exist_ok=True)
        
        self._setup_socket_handlers()
        self._load_or_generate_keys()
        
    def log(self, level: str, message: str, color: str = None):
        """Log with color coding and device ID."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if color is None:
            if level == "SECURE":
                color = Fore.GREEN
            elif level == "WARNING":
                color = Fore.YELLOW
            elif level == "BREACH":
                color = Fore.RED
            else:
                color = Fore.WHITE
        
        print(f"{color}[{timestamp}] [{self.device_id}] [{level}] {message}{Style.RESET_ALL}")
    
    def _setup_socket_handlers(self):
        """Setup WebSocket event handlers."""
        @self.sio.event
        def connect():
            self.log("SECURE", "Connected to satellite")
            self.satellite_connected = True
            self._register_with_satellite()
        
        @self.sio.event
        def disconnect():
            self.log("WARNING", "Disconnected from satellite")
            self.satellite_connected = False
        
        @self.sio.event
        def registration_success(data):
            self.log("SECURE", f"Registered with satellite: {data['device_id']}")
        
        @self.sio.event
        def registration_error(data):
            self.log("BREACH", f"Registration failed: {data['error']}")
        
        @self.sio.event
        def new_message(data):
            self._handle_incoming_message(data)
        
        @self.sio.event
        def queued_messages(data):
            for message in data['messages']:
                self._handle_incoming_message(message)
        
        @self.sio.event
        def capture_triggered(data):
            self.log("BREACH", "CAPTURE DETECTED - Initiating self-destruct!")
            self._self_destruct()
    
    def _load_or_generate_keys(self):
        """Load existing keys or generate new ones."""
        if self.is_compromised:
            self.log("BREACH", "Device compromised - keys unavailable")
            return
            
        private_key_file = os.path.join(self.device_dir, "private_key.enc")
        public_key_file = os.path.join(self.device_dir, "public_key.pem")
        passphrase_file = os.path.join(self.device_dir, ".passphrase")
        
        try:
            # Load existing keys
            if os.path.exists(private_key_file) and os.path.exists(public_key_file):
                with open(passphrase_file, 'rb') as f:
                    self.device_passphrase = f.read().decode()
                
                with open(private_key_file, 'rb') as f:
                    encrypted_private_key = f.read()
                
                with open(public_key_file, 'rb') as f:
                    self.public_key = f.read()
                
                self.private_key = self.crypto.decrypt_key_file(encrypted_private_key, self.device_passphrase)
                self.log("SECURE", f"Loaded existing {self.crypto.algorithm} keys")
                
            else:
                # Generate new keys
                self.log("SECURE", f"Generating new {self.crypto.algorithm} key pair...")
                self.private_key, self.public_key = self.crypto.generate_keypair()
                
                # Generate device passphrase
                self.device_passphrase = hashlib.sha256(get_random_bytes(32)).hexdigest()
                
                # Save encrypted private key
                encrypted_private_key = self.crypto.encrypt_key_file(self.private_key, self.device_passphrase)
                
                with open(private_key_file, 'wb') as f:
                    f.write(encrypted_private_key)
                
                with open(public_key_file, 'wb') as f:
                    f.write(self.public_key)
                
                with open(passphrase_file, 'wb') as f:
                    f.write(self.device_passphrase.encode())
                
                # Set restrictive permissions
                os.chmod(private_key_file, 0o600)
                os.chmod(passphrase_file, 0o600)
                
                self.log("SECURE", f"Generated and saved new {self.crypto.algorithm} keys")
                
        except Exception as e:
            self.log("BREACH", f"Key loading/generation failed: {e}")
            self.is_compromised = True
    
    def _register_with_satellite(self):
        """Register device with satellite server."""
        if self.is_compromised or not self.public_key:
            return
            
        public_key_hex = self.crypto.serialize_public_key(self.public_key)
        
        self.sio.emit('register_device', {
            'device_id': self.device_id,
            'public_key': public_key_hex
        })
    
    def connect_to_satellite(self):
        """Connect to satellite server."""
        if self.is_compromised:
            self.log("BREACH", "Cannot connect - device compromised")
            return False
            
        try:
            self.sio.connect(self.satellite_url)
            return True
        except Exception as e:
            self.log("WARNING", f"Failed to connect to satellite: {e}")
            return False
    
    def send_message(self, recipient_id: str, plaintext: str) -> bool:
        """Send encrypted message to recipient."""
        if self.is_compromised:
            self.log("BREACH", "Cannot send - device compromised")
            return False
            
        if not self.private_key:
            self.log("BREACH", "No private key available")
            return False
        
        try:
            # Get recipient's public key (in real implementation, this would be from a key directory)
            recipient_public_key = self._get_recipient_public_key(recipient_id)
            if not recipient_public_key:
                self.log("WARNING", f"No public key for recipient {recipient_id}")
                return False
            
            # Create message with timestamp and nonce for replay protection
            message_data = {
                'content': plaintext,
                'timestamp': time.time(),
                'nonce': get_random_bytes(16).hex(),
                'from': self.device_id
            }
            
            message_json = json.dumps(message_data)
            
            # Encrypt message
            encrypted_data = self.crypto.encrypt_for(recipient_public_key, message_json)
            
            # Sign the encrypted data
            signature = self.crypto.sign(self.private_key, json.dumps(encrypted_data))
            
            # Create final message envelope
            message_envelope = {
                'from': self.device_id,
                'to': recipient_id,
                'encrypted_data': encrypted_data,
                'signature': signature,
                'timestamp': time.time(),
                'algorithm': self.crypto.algorithm
            }
            
            # Try satellite first
            if self.satellite_connected:
                success = self._send_via_satellite(message_envelope)
                if success:
                    self.log("SECURE", f"Message sent to {recipient_id} via satellite")
                    return True
            
            # Fallback to mesh
            self.log("WARNING", "Satellite unavailable - attempting mesh fallback")
            success = self._send_via_mesh(recipient_id, message_envelope)
            if success:
                self.log("WARNING", f"Message sent to {recipient_id} via mesh", Fore.YELLOW)
                return True
            
            self.log("BREACH", f"Failed to send message to {recipient_id}")
            return False
            
        except Exception as e:
            self.log("BREACH", f"Message sending failed: {e}")
            return False
    
    def _send_via_satellite(self, message_envelope: Dict) -> bool:
        """Send message via satellite."""
        try:
            self.sio.emit('send_message', message_envelope)
            return True
        except Exception as e:
            self.log("WARNING", f"Satellite send failed: {e}")
            return False
    
    def _send_via_mesh(self, recipient_id: str, message_envelope: Dict) -> bool:
        """Send message via mesh network."""
        if recipient_id not in self.peer_devices:
            self.log("WARNING", f"No mesh route to {recipient_id}")
            return False
        
        try:
            peer_info = self.peer_devices[recipient_id]
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((peer_info['ip'], peer_info['port']))
            
            message_data = json.dumps(message_envelope).encode()
            sock.send(len(message_data).to_bytes(4, 'big'))
            sock.send(message_data)
            sock.close()
            
            return True
        except Exception as e:
            self.log("WARNING", f"Mesh send failed: {e}")
            return False
    
    def _handle_incoming_message(self, message_envelope: Dict):
        """Handle incoming encrypted message."""
        if self.is_compromised:
            self.log("BREACH", "Ignoring message - device compromised")
            return
        
        try:
            from_device = message_envelope['from']
            encrypted_data = message_envelope['encrypted_data']
            signature = message_envelope['signature']
            
            # Get sender's public key
            sender_public_key = self._get_recipient_public_key(from_device)
            if not sender_public_key:
                self.log("BREACH", f"No public key for sender {from_device}")
                return
            
            # Verify signature
            if not self.crypto.verify(sender_public_key, json.dumps(encrypted_data), signature):
                self.log("BREACH", f"Invalid signature from {from_device} - possible MITM attack!")
                return
            
            # Decrypt message
            decrypted_json = self.crypto.decrypt_with(self.private_key, encrypted_data)
            message_data = json.loads(decrypted_json)
            
            # Check for replay attack
            nonce = message_data.get('nonce')
            if nonce in self.nonce_cache:
                self.log("BREACH", f"Replay attack detected from {from_device}!")
                return
            
            self.nonce_cache.add(nonce)
            
            # Check timestamp (reject messages older than 5 minutes)
            message_time = message_data.get('timestamp', 0)
            if time.time() - message_time > 300:
                self.log("BREACH", f"Message from {from_device} too old - possible replay attack!")
                return
            
            # Message is valid
            content = message_data['content']
            self.log("SECURE", f"📨 Message from {from_device}: {content}")
            
            # Store in history
            self.message_history.append({
                'from': from_device,
                'content': content,
                'timestamp': message_time,
                'verified': True
            })
            
        except Exception as e:
            self.log("BREACH", f"Message processing failed: {e}")
    
    def _get_recipient_public_key(self, device_id: str) -> Optional[bytes]:
        """Get public key for a device (simplified for demo)."""
        # In a real implementation, this would query a secure key directory
        # For demo, we'll simulate having keys for devices A and B
        if device_id == 'A' and self.device_id != 'A':
            # Return a mock public key for device A
            return self._load_mock_public_key('A')
        elif device_id == 'B' and self.device_id != 'B':
            # Return a mock public key for device B
            return self._load_mock_public_key('B')
        return None
    
    def _load_mock_public_key(self, device_id: str) -> bytes:
        """Load or create mock public key for demo."""
        mock_key_file = f"device/data/{device_id}/public_key.pem"
        if os.path.exists(mock_key_file):
            with open(mock_key_file, 'rb') as f:
                return f.read()
        else:
            # Generate a mock key pair for the other device
            mock_crypto = CryptoBackend()
            private_key, public_key = mock_crypto.generate_keypair()
            os.makedirs(f"device/data/{device_id}", exist_ok=True)
            with open(mock_key_file, 'wb') as f:
                f.write(public_key)
            return public_key
    
    def start_mesh_server(self):
        """Start mesh networking server."""
        def mesh_server():
            try:
                server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_sock.bind(('localhost', self.mesh_server_port))
                server_sock.listen(5)
                
                self.log("SECURE", f"Mesh server listening on port {self.mesh_server_port}")
                
                while not self.is_compromised:
                    try:
                        client_sock, addr = server_sock.accept()
                        threading.Thread(target=self._handle_mesh_connection, args=(client_sock,)).start()
                    except Exception as e:
                        if not self.is_compromised:
                            self.log("WARNING", f"Mesh server error: {e}")
                        break
                        
            except Exception as e:
                self.log("WARNING", f"Failed to start mesh server: {e}")
        
        threading.Thread(target=mesh_server, daemon=True).start()
        
        # Register with other devices for mesh networking
        self._discover_peers()
    
    def _handle_mesh_connection(self, client_sock):
        """Handle incoming mesh connection."""
        try:
            # Read message length
            length_bytes = client_sock.recv(4)
            if len(length_bytes) != 4:
                return
            
            message_length = int.from_bytes(length_bytes, 'big')
            
            # Read message data
            message_data = b''
            while len(message_data) < message_length:
                chunk = client_sock.recv(message_length - len(message_data))
                if not chunk:
                    break
                message_data += chunk
            
            if len(message_data) == message_length:
                message_envelope = json.loads(message_data.decode())
                self.log("WARNING", f"Received mesh message from {message_envelope['from']}", Fore.YELLOW)
                self._handle_incoming_message(message_envelope)
                
        except Exception as e:
            self.log("WARNING", f"Mesh connection error: {e}")
        finally:
            client_sock.close()
    
    def _discover_peers(self):
        """Discover other devices for mesh networking."""
        # For demo, we'll hardcode peer discovery
        # In real implementation, this would use mDNS or other discovery protocols
        base_port = 6000
        for device_letter in ['A', 'B', 'C']:
            if device_letter != self.device_id:
                peer_port = base_port + hash(device_letter) % 1000
                self.peer_devices[device_letter] = {
                    'ip': 'localhost',
                    'port': peer_port,
                    'public_key': None  # Would be discovered in real implementation
                }
        
        self.log("SECURE", f"Discovered {len(self.peer_devices)} mesh peers")
    
    def _self_destruct(self):
        """Secure self-destruct sequence."""
        if self.is_compromised:
            return  # Already compromised
        
        self.log("BREACH", "🔥 INITIATING SELF-DESTRUCT SEQUENCE")
        
        # Mark as compromised immediately
        self.is_compromised = True
        
        # Disconnect from satellite
        if self.satellite_connected:
            try:
                self.sio.disconnect()
            except:
                pass
        
        # Secure wipe of memory
        if self.private_key:
            self.crypto.secure_wipe(self.private_key)
            self.private_key = None
        
        if self.device_passphrase:
            self.device_passphrase = None
        
        # Overwrite key files
        key_files = [
            os.path.join(self.device_dir, "private_key.enc"),
            os.path.join(self.device_dir, ".passphrase")
        ]
        
        for key_file in key_files:
            if os.path.exists(key_file):
                try:
                    # Overwrite with random data multiple times
                    file_size = os.path.getsize(key_file)
                    with open(key_file, 'wb') as f:
                        for _ in range(3):
                            f.seek(0)
                            f.write(get_random_bytes(file_size))
                            f.flush()
                            os.fsync(f.fileno())
                    
                    # Delete file
                    os.remove(key_file)
                    self.log("BREACH", f"Wiped key file: {key_file}")
                    
                except Exception as e:
                    self.log("BREACH", f"Failed to wipe {key_file}: {e}")
        
        # Clear message history
        self.message_history.clear()
        self.nonce_cache.clear()
        
        self.log("BREACH", "🔥 SELF-DESTRUCT COMPLETE - DEVICE DISABLED")
        self.log("BREACH", "All cryptographic material has been securely wiped")
    
    def interactive_mode(self):
        """Interactive command mode for demo."""
        self.log("SECURE", f"Device {self.device_id} ready - Type 'help' for commands")
        
        while not self.is_compromised:
            try:
                command = input(f"\n{Fore.CYAN}[{self.device_id}]> {Style.RESET_ALL}").strip()
                
                if not command:
                    continue
                
                parts = command.split()
                cmd = parts[0].lower()
                
                if cmd == 'help':
                    print(f"{Fore.YELLOW}Commands:")
                    print("  send <device_id> <message>  - Send encrypted message")
                    print("  status                      - Show device status")
                    print("  history                     - Show message history")
                    print("  peers                       - Show mesh peers")
                    print("  destruct                    - Trigger self-destruct")
                    print(f"  quit                        - Exit{Style.RESET_ALL}")
                
                elif cmd == 'send' and len(parts) >= 3:
                    recipient = parts[1]
                    message = ' '.join(parts[2:])
                    self.send_message(recipient, message)
                
                elif cmd == 'status':
                    status = "COMPROMISED" if self.is_compromised else "OPERATIONAL"
                    sat_status = "CONNECTED" if self.satellite_connected else "DISCONNECTED"
                    print(f"{Fore.CYAN}Device Status: {status}")
                    print(f"Satellite: {sat_status}")
                    print(f"Algorithm: {self.crypto.algorithm}")
                    print(f"Mesh Port: {self.mesh_server_port}{Style.RESET_ALL}")
                
                elif cmd == 'history':
                    print(f"{Fore.CYAN}Message History:")
                    for msg in self.message_history[-10:]:  # Last 10 messages
                        timestamp = datetime.fromtimestamp(msg['timestamp']).strftime("%H:%M:%S")
                        print(f"  [{timestamp}] {msg['from']}: {msg['content']}")
                    print(Style.RESET_ALL)
                
                elif cmd == 'peers':
                    print(f"{Fore.CYAN}Mesh Peers:")
                    for peer_id, peer_info in self.peer_devices.items():
                        print(f"  {peer_id}: {peer_info['ip']}:{peer_info['port']}")
                    print(Style.RESET_ALL)
                
                elif cmd == 'destruct':
                    confirm = input(f"{Fore.RED}Are you sure? This will destroy all keys! (yes/no): {Style.RESET_ALL}")
                    if confirm.lower() == 'yes':
                        self._self_destruct()
                
                elif cmd == 'quit':
                    break
                
                else:
                    print(f"{Fore.RED}Unknown command. Type 'help' for available commands.{Style.RESET_ALL}")
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.log("WARNING", f"Command error: {e}")
        
        # Cleanup
        if self.satellite_connected:
            self.sio.disconnect()

def main():
    parser = argparse.ArgumentParser(description='Q-SAFE Device Client')
    parser.add_argument('--id', required=True, help='Device ID (e.g., A, B, C)')
    parser.add_argument('--satellite', default='http://localhost:5000', help='Satellite server URL')
    parser.add_argument('--auto-send', help='Auto-send test message to specified device')
    parser.add_argument('--message', default='Hello from secure device!', help='Message to send in auto mode')
    
    args = parser.parse_args()
    
    device = DeviceClient(args.id, args.satellite)
    
    # Start mesh server
    device.start_mesh_server()
    
    # Connect to satellite
    if device.connect_to_satellite():
        time.sleep(1)  # Allow connection to establish
    
    # Auto-send mode for demos
    if args.auto_send:
        time.sleep(2)  # Allow setup to complete
        device.send_message(args.auto_send, args.message)
        time.sleep(1)
        return
    
    # Interactive mode
    try:
        device.interactive_mode()
    except KeyboardInterrupt:
        device.log("WARNING", "Device shutting down...")
    finally:
        if device.satellite_connected:
            device.sio.disconnect()

if __name__ == '__main__':
    main()
