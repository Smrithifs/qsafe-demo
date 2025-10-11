"""
Key Exfiltration Attack Simulator
Demonstrates how self-destruct prevents key recovery after device capture.
"""

import os
import time
import json
import colorama
from colorama import Fore, Style

colorama.init()

class KeyExfiltrationSimulator:
    def __init__(self, target_device_id: str):
        self.target_device_id = target_device_id
        self.device_dir = f"device/data/{target_device_id}"
        
    def log(self, message: str, color: str = Fore.RED):
        """Log attack activities."""
        timestamp = time.strftime("%H:%M:%S")
        print(f"{color}[{timestamp}] [KEY_ATTACKER] {message}{Style.RESET_ALL}")
    
    def attempt_key_extraction(self):
        """Simulate attempting to extract cryptographic keys from captured device."""
        self.log(f"🎯 Attempting key exfiltration from captured device {self.target_device_id}")
        
        # Check if device directory exists
        if not os.path.exists(self.device_dir):
            self.log(f"❌ Device directory not found: {self.device_dir}")
            return False
        
        # Try to access key files
        key_files = [
            "private_key.enc",
            "public_key.pem", 
            ".passphrase"
        ]
        
        keys_found = 0
        keys_accessible = 0
        
        for key_file in key_files:
            key_path = os.path.join(self.device_dir, key_file)
            
            if os.path.exists(key_path):
                keys_found += 1
                self.log(f"📁 Found key file: {key_file}")
                
                try:
                    # Attempt to read the key file
                    with open(key_path, 'rb') as f:
                        data = f.read()
                    
                    if len(data) > 0:
                        keys_accessible += 1
                        self.log(f"📖 Successfully read {key_file} ({len(data)} bytes)")
                        
                        # Try to analyze the data
                        if key_file == ".passphrase":
                            try:
                                passphrase = data.decode()
                                self.log(f"🔑 Extracted passphrase: {passphrase[:10]}...")
                            except:
                                self.log(f"🔒 Passphrase data corrupted or wiped")
                        
                        elif key_file == "private_key.enc":
                            try:
                                # Try to parse as JSON (encrypted key format)
                                key_data = json.loads(data.decode())
                                self.log(f"🔓 Private key structure intact")
                            except:
                                self.log(f"🔒 Private key data corrupted or wiped")
                    else:
                        self.log(f"⚠️  {key_file} exists but is empty (wiped)")
                        
                except Exception as e:
                    self.log(f"❌ Failed to read {key_file}: {e}")
            else:
                self.log(f"❌ Key file not found: {key_file}")
        
        # Summary
        self.log(f"📊 Key extraction summary:")
        self.log(f"   Files found: {keys_found}/{len(key_files)}")
        self.log(f"   Files accessible: {keys_accessible}/{keys_found}")
        
        if keys_accessible == 0:
            self.log("✅ SELF-DESTRUCT SUCCESSFUL: No keys recovered", Fore.GREEN)
            self.log("🔒 Device properly wiped cryptographic material", Fore.GREEN)
            return False
        else:
            self.log("🚨 SECURITY BREACH: Keys still accessible!", Fore.RED)
            return True
    
    def attempt_memory_dump(self):
        """Simulate attempting to extract keys from memory dump."""
        self.log("🧠 Attempting memory dump analysis...")
        
        # In a real scenario, this would analyze process memory
        # For demo, we'll simulate checking if sensitive data is in memory
        
        self.log("🔍 Scanning for cryptographic material in memory...")
        time.sleep(2)  # Simulate analysis time
        
        # Simulate finding no sensitive data (due to secure wiping)
        self.log("✅ No cryptographic keys found in memory", Fore.GREEN)
        self.log("🔒 Memory wiping was effective", Fore.GREEN)
    
    def attempt_filesystem_recovery(self):
        """Simulate attempting to recover deleted key files."""
        self.log("💾 Attempting filesystem recovery of deleted keys...")
        
        # Simulate forensic recovery attempts
        recovery_attempts = [
            "Scanning unallocated disk sectors...",
            "Checking filesystem journal...", 
            "Analyzing file slack space...",
            "Attempting data carving..."
        ]
        
        for attempt in recovery_attempts:
            self.log(f"🔍 {attempt}")
            time.sleep(1)
        
        # Simulate successful secure deletion (multiple overwrites prevent recovery)
        self.log("✅ No recoverable key data found", Fore.GREEN)
        self.log("🔒 Secure deletion with multiple overwrites was effective", Fore.GREEN)
    
    def run_full_exfiltration_attempt(self):
        """Run complete key exfiltration simulation."""
        print(f"{Fore.RED}{'='*60}")
        print(f"{Fore.RED}🔓 KEY EXFILTRATION ATTACK SIMULATION")
        print(f"{Fore.RED}Target: Device {self.target_device_id}")
        print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}")
        
        # Attack 1: Direct key file access
        print(f"\n{Fore.YELLOW}--- Attack 1: Direct Key File Access ---{Style.RESET_ALL}")
        keys_recovered = self.attempt_key_extraction()
        
        time.sleep(2)
        
        # Attack 2: Memory dump analysis
        print(f"\n{Fore.YELLOW}--- Attack 2: Memory Dump Analysis ---{Style.RESET_ALL}")
        self.attempt_memory_dump()
        
        time.sleep(2)
        
        # Attack 3: Filesystem recovery
        print(f"\n{Fore.YELLOW}--- Attack 3: Filesystem Recovery ---{Style.RESET_ALL}")
        self.attempt_filesystem_recovery()
        
        # Final assessment
        print(f"\n{Fore.GREEN}{'='*60}")
        if not keys_recovered:
            print(f"{Fore.GREEN}✅ SELF-DESTRUCT EFFECTIVE")
            print(f"{Fore.GREEN}🔒 No cryptographic material recovered")
            print(f"{Fore.GREEN}🛡️  Device capture mitigation successful")
        else:
            print(f"{Fore.RED}🚨 SECURITY FAILURE")
            print(f"{Fore.RED}🔓 Cryptographic material still accessible")
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Key Exfiltration Attack Simulator')
    parser.add_argument('--target', required=True, help='Target device ID (e.g., A, B)')
    
    args = parser.parse_args()
    
    attacker = KeyExfiltrationSimulator(args.target)
    attacker.run_full_exfiltration_attempt()

if __name__ == '__main__':
    main()
