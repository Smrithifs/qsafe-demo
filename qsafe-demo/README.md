# Q-SAFE: Quantum-Safe Mission Communications Demo

## 🚀 Integrated Mission Simulation + Dashboard + MITM Visualization

Complete interactive demo combining **Mission Simulation Flow**, **MITM Visualization**, and **Real-time Dashboard** into a single cohesive judge presentation demonstrating post-quantum secure communications under attack.

## 🎯 One-Click Demo Launch

```bash
./demo_run.sh
```

**Judge Dashboard**: http://localhost:8501  
**Mission Control**: http://localhost:5003

## 🎬 Automated Mission Flow

### Complete Simulation Sequence
1. **Device Initialization**: Auto-launch Device A, Device B, Satellite, MITM module
2. **Post-Quantum Key Exchange**: Generate Kyber512 keys + establish AES session
3. **Mission Communications**: Send 3 secure messages (normal military traffic)
4. **Satellite Failure**: Automatic fallback to peer-to-peer mesh (yellow routes)
5. **MITM Attack Simulation**:
   - Decryption attempts (fail - red logs)
   - Ciphertext modification (tamper detected)
   - Packet replay (nonce mismatch blocked)
6. **Device Capture**: Trigger key wipe + disable communication
7. **Mission Summary**: Complete report with integrity score + PCAP references

## 🎮 Interactive Streamlit Dashboard

### Real-Time Network Topology
- **Live visualization** of Device A ↔ Satellite ↔ Device B ↔ MITM
- **Animated message arrows**:
  - 🟢 Secure satellite route
  - 🟡 Mesh network fallback  
  - 🔴 Intercepted/tampered packets (blocked)

### Mission Control Panel
- **Live console logs** (color-coded: green/yellow/red)
- **Encryption status**: Kyber512 + AES-GCM indicators
- **MITM control buttons**: Start MITM, Tamper, Replay, Self-Destruct
- **PCAP downloads**: Direct Wireshark integration
- **Mission statistics**: Messages sent, attacks blocked, integrity score

### Military-Themed UI
- **Dark mode** with glowing packet routes
- **Real-time updates** via WebSocket synchronization
- **Judge presentation mode** with one-click mission execution

## 🔐 Security Validation Features

### Post-Quantum Cryptography
- **Kyber512** key exchange (quantum-resistant)
- **AES-256-GCM** session encryption
- **Zero-knowledge satellite** (cannot decrypt messages)
- **Self-destruct protocol** with secure key wiping

### Attack Resistance Demonstration
- **MITM Interception**: ✅ 0% success rate (all attacks blocked)
- **Packet Tampering**: ✅ Authentication tag verification
- **Replay Attacks**: ✅ Nonce-based freshness protection
- **Device Capture**: ✅ Emergency key destruction

### Evidence Generation
- **mission_traffic.pcap** - Encrypted communications
- **mitm_attacks.pcap** - Blocked attack attempts
- **mission_summary.txt** - Complete analysis report
- **Real-time logs** with cryptographic metadata

## 📊 Live Mission Dashboard Features

### Network Topology Visualization
```
    DEVICE_A ←→ SATELLITE ←→ DEVICE_B
         ↑         ↑         ↑
         └─── MITM_NODE ────┘
              (blocked)
```

### Mission Phase Tracking
- **INIT**: Device connection and setup
- **KEY_EXCHANGE**: Post-quantum key generation
- **MISSION_TRAFFIC**: Secure message transmission
- **SATELLITE_FAILURE**: Mesh network fallback
- **UNDER_ATTACK**: MITM simulation active
- **DEVICE_CAPTURE**: Self-destruct protocol
- **COMPLETE**: Mission summary generation

### Real-Time Statistics
- Messages sent: Real-time counter
- Attacks blocked: 100% success rate
- Integrity score: Maintained at 100%
- Security status: Quantum-safe active

## 🎯 Judge Presentation Mode

### Automated Demo Flow
1. **Single "Run Demo" button** launches complete simulation
2. **Live message visualization** with animated packet flows
3. **Real-time attack blocking** with visual confirmation
4. **Automatic evidence generation** (PCAPs + reports)
5. **"Quantum-Safe Communication Active" banner** after key exchange
6. **Automatic cleanup** after demo completion

### Validation Checklist
- [ ] Post-quantum encryption (Kyber512) active
- [ ] All MITM attacks show 0% success rate
- [ ] Wireshark PCAPs confirm no plaintext leakage
- [ ] Self-destruct completely wipes keys
- [ ] Mesh fallback maintains security
- [ ] Real-time topology reflects all network changes
- [ ] Mission summary shows 100% integrity score

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
