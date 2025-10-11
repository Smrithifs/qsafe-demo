#!/usr/bin/env python3
"""
Simple Q-SAFE Demo - Minimal working version
"""

import time
import threading
from flask import Flask, render_template_string
import colorama
from colorama import Fore, Style

colorama.init()

app = Flask(__name__)

# Simple in-memory state
demo_state = {
    'devices': {},
    'messages': [],
    'satellite_online': True
}

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Q-SAFE Demo Dashboard</title>
    <meta http-equiv="refresh" content="2">
    <style>
        body { font-family: monospace; background: #000; color: #0f0; margin: 0; padding: 20px; }
        .header { text-align: center; border-bottom: 1px solid #0f0; padding-bottom: 10px; }
        .section { margin: 20px 0; padding: 10px; border: 1px solid #333; }
        .device { padding: 5px; margin: 5px 0; background: #111; }
        .online { color: #0f0; }
        .offline { color: #f00; }
        .message { padding: 2px 0; font-size: 12px; }
        .secure { color: #0f0; }
        .warning { color: #ff0; }
        .breach { color: #f00; }
        button { background: #333; color: #0f0; border: 1px solid #0f0; padding: 5px 10px; margin: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛰️ Q-SAFE DEMO DASHBOARD</h1>
        <div>Status: <span class="online">{{ 'ONLINE' if satellite_online else 'OFFLINE' }}</span></div>
        <div>Time: {{ current_time }}</div>
    </div>
    
    <div class="section">
        <h3>Connected Devices ({{ device_count }})</h3>
        {% for device_id, info in devices.items() %}
        <div class="device">
            <strong>{{ device_id }}</strong> - 
            <span class="online">ONLINE</span>
            ({{ info.algorithm }} keys)
        </div>
        {% endfor %}
    </div>
    
    <div class="section">
        <h3>Recent Messages</h3>
        {% for msg in messages[-10:] %}
        <div class="message {{ msg.type }}">
            [{{ msg.timestamp }}] {{ msg.text }}
        </div>
        {% endfor %}
    </div>
    
    <div class="section">
        <h3>Demo Status</h3>
        <div class="secure">✅ Crypto Backend: RSA (PQC fallback)</div>
        <div class="secure">✅ Satellite Zero-Knowledge: Cannot decrypt messages</div>
        <div class="secure">✅ End-to-End Encryption: Working</div>
        <div class="secure">✅ Digital Signatures: Verified</div>
        <div class="warning">⚠️  Mesh Networking: Ready for fallback</div>
        <div class="breach">🔥 Self-Destruct: Armed and ready</div>
    </div>
</body>
</html>
"""

@app.route('/')
def dashboard():
    return render_template_string(DASHBOARD_HTML, 
        devices=demo_state['devices'],
        messages=demo_state['messages'],
        satellite_online=demo_state['satellite_online'],
        device_count=len(demo_state['devices']),
        current_time=time.strftime("%H:%M:%S")
    )

def simulate_demo():
    """Simulate Q-SAFE demo activities"""
    time.sleep(2)
    
    # Device A connects
    demo_state['devices']['A'] = {'algorithm': 'RSA', 'status': 'online'}
    demo_state['messages'].append({
        'timestamp': time.strftime("%H:%M:%S"),
        'text': '[A] [SECURE] Device A registered with RSA keys',
        'type': 'secure'
    })
    print(f"{Fore.GREEN}[{time.strftime('%H:%M:%S')}] [A] [SECURE] Device A registered{Style.RESET_ALL}")
    
    time.sleep(2)
    
    # Device B connects
    demo_state['devices']['B'] = {'algorithm': 'RSA', 'status': 'online'}
    demo_state['messages'].append({
        'timestamp': time.strftime("%H:%M:%S"),
        'text': '[B] [SECURE] Device B registered with RSA keys',
        'type': 'secure'
    })
    print(f"{Fore.GREEN}[{time.strftime('%H:%M:%S')}] [B] [SECURE] Device B registered{Style.RESET_ALL}")
    
    time.sleep(3)
    
    # Message exchange
    demo_state['messages'].append({
        'timestamp': time.strftime("%H:%M:%S"),
        'text': '[SATELLITE] [SECURE] Forwarding encrypted message A→B',
        'type': 'secure'
    })
    print(f"{Fore.GREEN}[{time.strftime('%H:%M:%S')}] [SATELLITE] [SECURE] Message forwarded{Style.RESET_ALL}")
    
    time.sleep(2)
    
    demo_state['messages'].append({
        'timestamp': time.strftime("%H:%M:%S"),
        'text': '[B] [SECURE] 📨 Decrypted message from A: "Hello Device B!"',
        'type': 'secure'
    })
    print(f"{Fore.GREEN}[{time.strftime('%H:%M:%S')}] [B] [SECURE] Message received and decrypted{Style.RESET_ALL}")
    
    time.sleep(5)
    
    # Satellite outage simulation
    demo_state['satellite_online'] = False
    demo_state['messages'].append({
        'timestamp': time.strftime("%H:%M:%S"),
        'text': '[SATELLITE] [WARNING] Satellite going offline - mesh fallback active',
        'type': 'warning'
    })
    print(f"{Fore.YELLOW}[{time.strftime('%H:%M:%S')}] [SATELLITE] [WARNING] Satellite offline{Style.RESET_ALL}")
    
    time.sleep(3)
    
    demo_state['messages'].append({
        'timestamp': time.strftime("%H:%M:%S"),
        'text': '[A] [WARNING] Using mesh network to reach B',
        'type': 'warning'
    })
    print(f"{Fore.YELLOW}[{time.strftime('%H:%M:%S')}] [A] [WARNING] Mesh fallback activated{Style.RESET_ALL}")
    
    time.sleep(5)
    
    # Attack simulation
    demo_state['messages'].append({
        'timestamp': time.strftime("%H:%M:%S"),
        'text': '[ATTACKER] [BREACH] Attempting MITM attack on satellite',
        'type': 'breach'
    })
    print(f"{Fore.RED}[{time.strftime('%H:%M:%S')}] [ATTACKER] [BREACH] MITM attack attempted{Style.RESET_ALL}")
    
    time.sleep(2)
    
    demo_state['messages'].append({
        'timestamp': time.strftime("%H:%M:%S"),
        'text': '[B] [BREACH] Invalid signature detected - MITM attack blocked!',
        'type': 'breach'
    })
    print(f"{Fore.RED}[{time.strftime('%H:%M:%S')}] [B] [BREACH] Attack blocked by signature verification{Style.RESET_ALL}")
    
    time.sleep(5)
    
    # Self-destruct simulation
    demo_state['messages'].append({
        'timestamp': time.strftime("%H:%M:%S"),
        'text': '[B] [BREACH] 🚨 DEVICE CAPTURE DETECTED - SELF-DESTRUCT INITIATED',
        'type': 'breach'
    })
    print(f"{Fore.RED}[{time.strftime('%H:%M:%S')}] [B] [BREACH] Self-destruct initiated{Style.RESET_ALL}")
    
    time.sleep(2)
    
    demo_state['devices']['B']['status'] = 'compromised'
    demo_state['messages'].append({
        'timestamp': time.strftime("%H:%M:%S"),
        'text': '[B] [BREACH] 🔥 All cryptographic keys securely wiped',
        'type': 'breach'
    })
    print(f"{Fore.RED}[{time.strftime('%H:%M:%S')}] [B] [BREACH] Keys wiped - device disabled{Style.RESET_ALL}")

if __name__ == '__main__':
    print(f"{Fore.CYAN}🛰️ Q-SAFE Simple Demo Starting...{Style.RESET_ALL}")
    print(f"{Fore.CYAN}📡 Dashboard: http://localhost:5000{Style.RESET_ALL}")
    print(f"{Fore.CYAN}🔒 Demo will auto-run scenarios{Style.RESET_ALL}")
    
    # Start demo simulation in background
    threading.Thread(target=simulate_demo, daemon=True).start()
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=False)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Demo stopped{Style.RESET_ALL}")
