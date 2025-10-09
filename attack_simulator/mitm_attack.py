"""
Man-in-the-Middle Attack Simulator
Demonstrates how the Q-SAFE system detects and prevents MITM attacks.
"""

import json
import time
import requests
import colorama
from colorama import Fore, Style
import socketio

colorama.init()

class MITMAttackSimulator:
    def __init__(self, satellite_url: str = "http://localhost:5000"):
        self.satellite_url = satellite_url
        self.intercepted_messages = []
        
    def log(self, message: str, color: str = Fore.RED):
        """Log attack activities."""
        timestamp = time.strftime("%H:%M:%S")
        print(f"{color}[{timestamp}] [ATTACKER] {message}{Style.RESET_ALL}")
    
    def intercept_and_modify_message(self):
        """Simulate intercepting and modifying a message in transit."""
        self.log("🎯 Attempting MITM attack on satellite communications")
        
        # This simulates an attacker who has compromised the satellite relay
        # and attempts to modify messages in transit
        
        # Create a fake modified message
        fake_message = {
            'from': 'A',
            'to': 'B',
            'encrypted_data': {
                'encrypted_session_key': 'deadbeef' * 16,  # Modified ciphertext
                'iv': 'cafebabe' * 4,
                'ciphertext': 'modified_payload' * 10,
                'auth_tag': 'fakehash' * 4,
                'algorithm': 'RSA',
                'timestamp': time.time()
            },
            'signature': 'forged_signature' * 8,  # Forged signature
            'timestamp': time.time(),
            'algorithm': 'RSA'
        }
        
        self.log("📡 Intercepted message from Device A to Device B")
        self.log("🔧 Modifying ciphertext and forging signature...")
        
        # Try to inject the modified message
        try:
            sio = socketio.Client()
            sio.connect(self.satellite_url)
            
            # Register as a fake device to inject messages
            sio.emit('register_device', {
                'device_id': 'ATTACKER',
                'public_key': 'fake_public_key'
            })
            
            time.sleep(1)
            
            # Inject the modified message
            sio.emit('send_message', fake_message)
            
            self.log("💀 Injected modified message into satellite relay")
            self.log("⚠️  Recipient should detect signature verification failure")
            
            time.sleep(2)
            sio.disconnect()
            
        except Exception as e:
            self.log(f"Attack failed: {e}")
    
    def attempt_message_replay(self):
        """Simulate a replay attack using previously captured messages."""
        self.log("🔄 Attempting replay attack with old message")
        
        # Simulate replaying an old legitimate message
        old_message = {
            'from': 'A',
            'to': 'B',
            'encrypted_data': {
                'encrypted_session_key': 'legitimate_but_old_key',
                'iv': 'old_iv_value',
                'ciphertext': 'old_legitimate_ciphertext',
                'auth_tag': 'old_auth_tag',
                'algorithm': 'RSA',
                'timestamp': time.time() - 3600  # 1 hour old
            },
            'signature': 'old_legitimate_signature',
            'timestamp': time.time() - 3600,
            'algorithm': 'RSA'
        }
        
        try:
            sio = socketio.Client()
            sio.connect(self.satellite_url)
            
            sio.emit('register_device', {
                'device_id': 'REPLAY_ATTACKER',
                'public_key': 'fake_key'
            })
            
            time.sleep(1)
            
            # Replay the old message
            sio.emit('send_message', old_message)
            
            self.log("📤 Replayed old message")
            self.log("⚠️  Recipient should reject due to old timestamp")
            
            time.sleep(2)
            sio.disconnect()
            
        except Exception as e:
            self.log(f"Replay attack failed: {e}")
    
    def attempt_satellite_compromise(self):
        """Simulate attempting to extract plaintext from satellite."""
        self.log("🛰️  Attempting to compromise satellite server")
        
        try:
            # Try to access satellite's internal state
            response = requests.get(f"{self.satellite_url}/api/logs")
            if response.status_code == 200:
                logs = response.json()
                self.log("📋 Retrieved satellite logs")
                
                # Look for any plaintext in logs (there should be none)
                plaintext_found = False
                for log_entry in logs.get('logs', []):
                    message = log_entry.get('message', '')
                    if 'plaintext' in message.lower() or 'decrypted' in message.lower():
                        plaintext_found = True
                        self.log(f"🚨 SECURITY BREACH: Found plaintext in logs: {message}")
                
                if not plaintext_found:
                    self.log("✅ GOOD: No plaintext found in satellite logs")
                    self.log("🔒 Satellite properly maintains zero-knowledge of message content")
            
        except Exception as e:
            self.log(f"Satellite access failed: {e}")
    
    def run_full_attack_simulation(self):
        """Run complete attack simulation."""
        print(f"{Fore.RED}{'='*60}")
        print(f"{Fore.RED}🚨 Q-SAFE ATTACK SIMULATION STARTING 🚨")
        print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}")
        
        self.log("Starting comprehensive attack simulation...")
        
        # Attack 1: MITM with message modification
        print(f"\n{Fore.YELLOW}--- Attack 1: Message Modification ---{Style.RESET_ALL}")
        self.intercept_and_modify_message()
        
        time.sleep(3)
        
        # Attack 2: Replay attack
        print(f"\n{Fore.YELLOW}--- Attack 2: Replay Attack ---{Style.RESET_ALL}")
        self.attempt_message_replay()
        
        time.sleep(3)
        
        # Attack 3: Satellite compromise attempt
        print(f"\n{Fore.YELLOW}--- Attack 3: Satellite Data Extraction ---{Style.RESET_ALL}")
        self.attempt_satellite_compromise()
        
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}✅ ATTACK SIMULATION COMPLETE")
        print(f"{Fore.GREEN}All attacks should be detected and prevented by Q-SAFE")
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Q-SAFE Attack Simulator')
    parser.add_argument('--satellite', default='http://localhost:5000', help='Satellite server URL')
    parser.add_argument('--attack', choices=['mitm', 'replay', 'satellite', 'all'], 
                       default='all', help='Type of attack to simulate')
    
    args = parser.parse_args()
    
    attacker = MITMAttackSimulator(args.satellite)
    
    if args.attack == 'mitm':
        attacker.intercept_and_modify_message()
    elif args.attack == 'replay':
        attacker.attempt_message_replay()
    elif args.attack == 'satellite':
        attacker.attempt_satellite_compromise()
    else:
        attacker.run_full_attack_simulation()

if __name__ == '__main__':
    main()
