"""
Device Capture Trigger
Simulates triggering a device capture event for self-destruct demonstration.
"""

import requests
import socketio
import time
import argparse
import colorama
from colorama import Fore, Style

colorama.init()

def trigger_device_capture(device_id: str, satellite_url: str = "http://localhost:5000"):
    """Trigger capture event on specified device."""
    print(f"{Fore.RED}🚨 SIMULATING DEVICE CAPTURE EVENT 🚨{Style.RESET_ALL}")
    print(f"{Fore.RED}Target Device: {device_id}{Style.RESET_ALL}")
    
    try:
        # Connect to satellite as dashboard client
        sio = socketio.Client()
        sio.connect(satellite_url)
        
        # Join dashboard room
        sio.emit('join_dashboard')
        time.sleep(1)
        
        # Trigger capture on target device
        sio.emit('trigger_capture', {'device_id': device_id})
        
        print(f"{Fore.YELLOW}📡 Capture signal sent to device {device_id}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}⚠️  Device should initiate self-destruct sequence{Style.RESET_ALL}")
        
        time.sleep(2)
        sio.disconnect()
        
        print(f"{Fore.GREEN}✅ Capture simulation complete{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}❌ Capture trigger failed: {e}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='Trigger device capture simulation')
    parser.add_argument('--target', required=True, help='Target device ID (e.g., A, B)')
    parser.add_argument('--satellite', default='http://localhost:5000', help='Satellite server URL')
    
    args = parser.parse_args()
    
    trigger_device_capture(args.target, args.satellite)

if __name__ == '__main__':
    main()
