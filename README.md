# Q-SAFE: Quantum-Safe Military Communications Demo

## 🚀 Post-Quantum Cryptography for Secure Military Communications

**Q-SAFE** demonstrates **NIST-standardized post-quantum cryptography** (ML-KEM-512 + ML-DSA-44) protecting military communications against both classical and quantum computer attacks. Features real-time attack simulation, detailed cryptographic operation logging, and interactive visualization.

## 🎯 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Launch unified demo
python3 unified_demo.py
```

**Dashboard**: http://localhost:5001

## ✨ Key Features

### 🔐 NIST-Standardized Post-Quantum Cryptography
- **ML-KEM-512 (Kyber)**: Quantum-resistant key encapsulation mechanism (FIPS 203)
- **ML-DSA-44 (Dilithium)**: Quantum-resistant digital signatures (FIPS 204)
- **AES-256-GCM**: Authenticated symmetric encryption
- **Hybrid Architecture**: PQC for key exchange + AES for performance

### 📊 Real-Time Cryptographic Transparency
- **Step-by-step logging**: See every cryptographic operation in detail
- **8-step encryption process**: From session key generation to message delivery
- **Educational explanations**: Learn how quantum-safe encryption works
- **Byte-level visibility**: View ciphertexts, signatures, and keys in hex

### 🛡️ Attack Simulation & Defense
- **MITM Decryption Attempts**: 0% success rate (quantum-resistant)
- **Packet Tampering**: Detected by GCM authentication tags
- **Replay Attacks**: Blocked by nonce-based freshness
- **Device Capture**: Self-destruct protocol wipes keys
- **Real-time blocking**: Watch attacks fail in live logs

### 🌐 Military-Grade Resilience
- **Zero-knowledge satellite**: Cannot decrypt messages (end-to-end encryption)
- **Mesh network fallback**: Automatic P2P if satellite fails
- **Forward secrecy**: Ephemeral session keys per message
- **Interactive dashboard**: Control panel with live network topology

## 🎮 How to Use the Demo

### 1. Start Mission
Click **"Start Mission"** to initialize the system

### 2. Connect Devices
- Click **"Connect Device A"**
- Click **"Connect Device B"**
- Devices show as **ONLINE** in status panel

### 3. Generate Quantum-Safe Keys
Click **"Generate Keys"** - Watch the logs show:
```
🔧 Generating Post-Quantum (ML-KEM-512 + ML-DSA-44) key pair...
✅ Kyber-512 Public Key Generated
🔐 Kyber-512 Private Key Generated
🛡️  Quantum-resistant encryption active
```

### 4. Send Encrypted Message
- Select **From Device** (A or B)
- Select **To Device** (B or A)
- Type your message
- Click **"Send Message"**

Watch the detailed 8-step encryption process:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚀 STEP 1: Ephemeral Session Key Generation
  └─ Algorithm: AES-256 (256-bit symmetric key)
  └─ Purpose: Fast symmetric encryption of message payload

🔐 STEP 2: Message Encryption (AES-256-GCM)
  └─ Plaintext: "Your message" (X chars)
  └─ Ciphertext: [hex] (X bytes)
  └─ Auth Tag (GMAC): [hex] (16 bytes)

🔒 STEP 3: Session Key Encapsulation (ML-KEM-512)
  └─ Kyber Ciphertext: [hex]... (768 bytes)
  └─ Quantum Resistance: Safe against Shor's algorithm

✍️  STEP 4: Digital Signature (ML-DSA-44)
  └─ Dilithium Signature: [hex]... (~2420 bytes)
  └─ Quantum Resistance: Immune to quantum forgery attacks

📤 STEP 5: Network Transmission via SATELLITE
  └─ Total Packet Size: X bytes
  └─ Security: All data encrypted, satellite cannot read contents

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📥 RECEPTION: Device B received encrypted packet

✅ STEP 6: Signature Verification (ML-DSA-44)
  └─ Sender Identity: Device A (authenticated)
  └─ Result: Message is authentic and unmodified

🔓 STEP 7: Session Key Decapsulation (ML-KEM-512)
  └─ Kyber Decapsulation: Using recipient private key
  └─ Session Key Recovered: [hex]...

🔓 STEP 8: Message Decryption (AES-256-GCM)
  └─ Authentication Tag: VERIFIED ✓ (no tampering detected)
  └─ 📨 Message Recovered: "Your message"

✅ COMPLETE: Secure message delivery via SATELLITE
  └─ End-to-end encryption: ✓
  └─ Authentication: ✓
  └─ Quantum resistance: ✓
```

### 5. Simulate Attacks
Click attack buttons to see defenses in action:
- **"Decrypt Attack"**: MITM tries to decrypt → **BLOCKED** (quantum-resistant)
- **"Tamper Attack"**: Modify ciphertext → **DETECTED** (GCM tag fails)
- **"Replay Attack"**: Resend old packet → **BLOCKED** (nonce cache)
- **"Capture Device"**: Self-destruct wipes keys → **PROTECTED** (forward secrecy)

### 6. Toggle Satellite
Click **"Toggle Satellite"** to simulate failure:
- System automatically switches to **MESH NETWORK** (peer-to-peer)
- Security maintained with same quantum-safe encryption

## 🛡️ Security Properties

### Quantum Resistance
| Attack Type | Traditional (RSA/ECC) | Q-SAFE (PQC) |
|-------------|----------------------|--------------|
| Shor's Algorithm | ❌ Broken | ✅ Secure |
| Grover's Algorithm | ⚠️ Weakened | ✅ Secure |
| MITM Decryption | ❌ Vulnerable (with quantum) | ✅ Protected |
| Signature Forgery | ❌ Vulnerable (with quantum) | ✅ Protected |

### Attack Defense Matrix
| Attack Vector | Detection Method | Success Rate |
|---------------|-----------------|--------------|
| Packet Decryption | Quantum-resistant KEM | 0% |
| Ciphertext Tampering | GCM authentication tag | 0% (detected) |
| Replay Attack | Nonce freshness check | 0% (blocked) |
| Signature Forgery | Dilithium verification | 0% |
| Device Capture | Self-destruct protocol | Low impact (forward secrecy) |
| Satellite Compromise | Zero-knowledge relay | 0% (cannot decrypt) |

### Cryptographic Specifications
- **Key Exchange**: ML-KEM-512 (Kyber) - 768-byte ciphertext
- **Digital Signatures**: ML-DSA-44 (Dilithium) - ~2420-byte signatures
- **Symmetric Encryption**: AES-256-GCM - 256-bit keys, 128-bit auth tags
- **Hash Function**: SHA-256 for message digests
- **Session Keys**: Ephemeral (fresh per message)
- **Forward Secrecy**: Yes (session keys not stored)

## 🏗️ Technical Architecture

### System Components

```
┌─────────────────────────────────────────────────────────┐
│                   unified_demo.py                       │
│              Flask + SocketIO Web Server                │
│                    (Port 5001)                          │
└────────────┬────────────────────────────────────────────┘
             │
    ┌────────┴────────┐
    │                 │
┌───▼────────┐  ┌────▼──────────┐
│ Device A   │  │  Device B     │
│ (Sender)   │  │  (Receiver)   │
└───┬────────┘  └────┬──────────┘
    │                │
    └────────┬───────┘
             │
    ┌────────▼────────┐
    │   Satellite     │
    │  (Zero-Know)    │
    └────────┬────────┘
             │
    ┌────────▼────────┐
    │  MITM Attacker  │
    │   (Blocked)     │
    └─────────────────┘
```

### Core Modules

**crypto_backend.py**
- `CryptoBackend` class: Unified PQC/RSA abstraction
- `generate_keypair()`: ML-KEM-512 + ML-DSA-44 key generation
- `_pqc_encrypt_session_key()`: Kyber encapsulation
- `_pqc_decrypt_session_key()`: Kyber decapsulation
- `_pqc_sign()`: Dilithium signature generation
- `_pqc_verify()`: Dilithium signature verification

**unified_demo.py**
- Flask web server with WebSocket support
- `/api/device/keygen`: Generate quantum-safe keypairs
- `/api/message/send`: Encrypt and transmit messages
- `/api/attack/simulate`: Trigger MITM attacks
- `/api/satellite/toggle`: Switch between satellite/mesh
- Real-time logging with detailed cryptographic steps

**mitm_simulator/**
- Realistic attack vector simulation
- Decryption attempts (fail - quantum-resistant)
- Packet tampering (detected by GCM)
- Replay attacks (blocked by nonce cache)

**pcap_generator/**
- Wireshark-compatible packet capture
- Evidence generation for security audits
- Shows encrypted traffic patterns

## 🌟 What Makes Q-SAFE Unique

### 1. **NIST-Standardized PQC (2024)**
- Most systems still use vulnerable RSA/ECC
- Q-SAFE uses **FIPS 203 (ML-KEM)** and **FIPS 204 (ML-DSA)**
- Future-proof against quantum computers

### 2. **Educational Transparency**
- **8-step detailed logging** of every cryptographic operation
- See ciphertexts, signatures, and keys in real-time
- Learn how post-quantum cryptography works
- Perfect for security education and auditing

### 3. **Live Attack Simulation**
- Built-in MITM simulator demonstrates security
- Watch attacks fail in real-time
- **0% success rate** proves quantum resistance
- Interactive attack triggers for demonstration

### 4. **Military-Grade Resilience**
- Zero-knowledge satellite (end-to-end encryption)
- Automatic mesh fallback on satellite failure
- Self-destruct protocol on device capture
- Forward secrecy with ephemeral session keys

### 5. **Complete Working System**
- Not just theory - fully functional implementation
- Interactive web dashboard
- Real-time visualization
- PCAP evidence generation for Wireshark

### 6. **Hybrid Architecture**
- PQC for key exchange (quantum-safe)
- AES-256 for message encryption (performance)
- Dilithium for authentication (quantum-safe)
- Best of both worlds: security + speed

## 🛠️ Technical Architecture

### Mission Orchestration
- **mission_flow.py**: Central controller for devices + MITM + topology
- **WebSocket sync**: Real-time event streaming between components
- **Automated sequencing**: Complete mission flow without manual intervention
- **Evidence collection**: Automatic PCAP and report generation

### Dashboard Integration
- **Streamlit frontend**: Military-themed interactive interface
- **Plotly visualization**: Real-time network topology rendering
- **Flask backend**: Mission control API endpoints
- **Live logging**: Color-coded security event streaming

### Security Components
- **crypto_backend.py**: Post-quantum cryptographic abstraction
- **mitm_simulator/**: Realistic attack vector simulation
- **pcap_generator/**: Wireshark-compatible evidence creation
- **Self-destruct**: Secure key material destruction

## 📁 New File Structure

```
qsafe-demo/
├── mission_flow.py           # 🆕 Mission orchestration controller
├── dashboard.py              # 🆕 Streamlit interactive dashboard  
├── demo_run.sh              # 🆕 One-click judge launcher
├── web_demo.py              # Enhanced main dashboard (port 5000)
├── demo_working.py          # Enhanced topology visualizer (port 5002)
├── crypto_backend.py        # Post-quantum crypto layer
├── mitm_simulator/          # MITM attack simulation
├── pcap_generator/          # Evidence generation
├── topology/                # Network visualization
├── mission_summary.txt      # 🆕 Auto-generated mission report
├── JUDGE_GUIDE.md          # Comprehensive evaluation guide
└── requirements.txt         # Updated with Streamlit + Plotly
```

## 🚀 Quick Start Commands

### For Judges (Recommended)
```bash
./demo_run.sh
# Opens: http://localhost:8501 (Main Dashboard)
# Click "START MISSION" and watch complete simulation
```

### For Developers
```bash
# Install dependencies
pip install -r requirements.txt

# Launch mission controller
python mission_flow.py &

# Launch dashboard
streamlit run dashboard.py
```

### Manual Component Testing
```bash
# Individual components (for debugging)
python web_demo.py          # Port 5000 - Main controls
python demo_working.py      # Port 5002 - Topology viz
python mission_flow.py      # Port 5003 - Mission orchestrator
```

## 🎬 Demo Scenarios

### Complete Mission Simulation
- **Duration**: ~2 minutes automated sequence
- **Phases**: 7 distinct mission phases with visual transitions
- **Attacks**: Multiple MITM attempts (all blocked)
- **Evidence**: Complete PCAP + report generation
- **Validation**: Real-time cryptographic transparency

### Interactive Controls
- **Mission start/stop**: Full simulation control
- **Attack triggers**: Manual MITM simulation
- **PCAP downloads**: Immediate Wireshark analysis
- **Log filtering**: Real-time security event monitoring

## 🏆 Hackathon Judge Benefits

### Complete Integration
- **Single entry point**: One command launches everything
- **Visual proof**: Real-time topology shows all security properties
- **Interactive demonstration**: Judges can trigger attacks and see blocking
- **Comprehensive evidence**: PCAPs + reports for detailed analysis
- **Military presentation**: Professional UI suitable for defense applications

### Security Transparency  
- **Cryptographic visibility**: Step-by-step encryption process display
- **Attack resistance proof**: Live demonstration of 0% MITM success
- **Post-quantum readiness**: Quantum-resistant algorithm validation
- **Evidence generation**: Complete audit trail for security verification

This integrated system provides the most comprehensive demonstration of quantum-safe communications under attack, with complete transparency into all cryptographic operations and real-time visual proof of security properties.
