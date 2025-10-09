#!/usr/bin/env python3
"""
Simple Q-SAFE MITM Demo
Shows live attack simulation and network visualization
"""

import time
import requests
import json
import threading
from datetime import datetime

def send_topology_event(event_type, data):
    """Send event to topology visualizer"""
    try:
        url = "http://localhost:5001/api/topology/events"
        payload = {"type": event_type, **data}
        requests.post(url, json=payload, timeout=1)
        print(f"✅ Sent {event_type} event: {data}")
    except:
        print(f"❌ Failed to send {event_type} event")

def simulate_mitm_demo():
    """Run MITM demonstration sequence"""
    print("🎯 Starting Q-SAFE MITM Demonstration")
    print("=" * 50)
    
    # Device connections
    print("\n📱 Phase 1: Device Connections")
    send_topology_event("device_status", {"device_id": "DEVICE_A", "status": "online"})
    time.sleep(1)
    send_topology_event("device_status", {"device_id": "DEVICE_B", "status": "online"})
    time.sleep(2)
    
    # Normal encrypted messages
    print("\n🔐 Phase 2: Encrypted Messages")
    for i in range(3):
        msg_id = f"MSG_{i+1:03d}"
        send_topology_event("message", {
            "msg_id": msg_id,
            "from": "DEVICE_A",
            "to": "DEVICE_B", 
            "route_type": "secure",
            "ciphertext_hex": f"deadbeef{i:08x}" + "a1b2c3d4" * 20
        })
        print(f"📤 Secure message {msg_id} sent")
        time.sleep(2)
    
    # MITM Attack attempts
    print("\n🔴 Phase 3: MITM Attack Simulation")
    attack_types = ["DECRYPTION_ATTEMPT", "SESSION_KEY_EXTRACTION", "MESSAGE_TAMPERING", "REPLAY_ATTACK"]
    
    for attack in attack_types:
        send_topology_event("attack", {
            "attack_type": attack,
            "target": "DEVICE_B",
            "result": "blocked"
        })
        print(f"⚔️  {attack} - BLOCKED")
        time.sleep(2)
    
    # Satellite outage - mesh fallback
    print("\n🛰️  Phase 4: Satellite Outage - Mesh Fallback")
    send_topology_event("device_status", {"device_id": "SATELLITE", "status": "offline"})
    time.sleep(1)
    
    # Mesh messages
    for i in range(2):
        msg_id = f"MESH_{i+1:03d}"
        send_topology_event("message", {
            "msg_id": msg_id,
            "from": "DEVICE_A",
            "to": "DEVICE_B",
            "route_type": "mesh", 
            "ciphertext_hex": f"cafebabe{i:08x}" + "f1e2d3c4" * 15
        })
        print(f"🔗 Mesh message {msg_id} sent")
        time.sleep(2)
    
    # Device capture and self-destruct
    print("\n🚨 Phase 5: Device Capture & Self-Destruct")
    send_topology_event("attack", {
        "attack_type": "DEVICE_CAPTURE",
        "target": "DEVICE_A",
        "result": "self_destruct_triggered"
    })
    print("🔥 Device A captured - Self-destruct activated")
    time.sleep(1)
    
    send_topology_event("device_status", {"device_id": "DEVICE_A", "status": "compromised"})
    print("💀 Device A keys wiped - Forensic recovery impossible")
    
    # Final attack attempts on captured device
    print("\n🔓 Phase 6: Key Extraction Attempts")
    send_topology_event("attack", {
        "attack_type": "KEY_EXTRACTION",
        "target": "DEVICE_A", 
        "result": "failed_wiped"
    })
    print("❌ Key extraction failed - Files wiped")
    
    print("\n✅ MITM Demonstration Complete")
    print("🛡️  All attacks blocked - Q-SAFE security validated")

def main():
    print("🎬 Q-SAFE MITM Live Demo")
    print("📊 Topology: http://localhost:5001")
    print("🎮 Dashboard: http://localhost:5000")
    print("\nStarting demonstration in 3 seconds...")
    
    time.sleep(3)
    simulate_mitm_demo()

if __name__ == "__main__":
    main()
