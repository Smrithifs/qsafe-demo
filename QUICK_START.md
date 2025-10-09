# Q-SAFE MITM Demo - Quick Start

## 🚀 One-Command Demo
```bash
./demo_mitm.sh
```

## 🎯 Judge Checklist (2 minutes)

### 1. Launch & Observe
- Run `./demo_mitm.sh`
- Open http://localhost:5000 (main dashboard)
- Open http://localhost:5001 (network topology)

### 2. Key Validation Points
- ✅ **MITM attacks fail**: Check red attack logs
- ✅ **Encryption works**: Green secure message logs  
- ✅ **Self-destruct effective**: Key wipe after capture
- ✅ **PCAP generated**: Download from dashboard

### 3. Generated Evidence
- `logs/mitm_capture.pcap` - Wireshark analysis
- `logs/mitm_report.txt` - Attack failure summary
- Network topology shows live attack attempts

## 🔍 What Judges See

### Attack Logs (Red)
```
[ATTACKER] [BREACH] Intercepted encrypted message MSG_001
[ATTACKER] [BREACH] DECRYPTION_FAILED: Invalid private key
[ATTACKER] [BREACH] SESSION_KEY_EXTRACTION_FAILED: No access
[ATTACKER] [BREACH] KEY_EXTRACTION_FAILED: Key file wiped
```

### Security Logs (Green)
```
[DEVICE_A] [SECURE] Generated RSA keys
[DEVICE_A] [SECURE] Sending encrypted message
[DEVICE_B] [SECURE] Message decrypted and verified
[DEVICE_A] [SECURE] Self-destruct: All keys wiped
```

## 📊 Dashboard Features
- **Live Logs**: Real-time attack attempts
- **MITM Panel**: Start/stop packet capture
- **Topology View**: Animated message routes
- **PCAP Download**: Wireshark-ready files

## ⏱️ Demo Timeline
- **0-2min**: Normal encrypted messaging
- **2-5min**: MITM attacks (all fail)
- **5-7min**: Device capture & key wipe
- **7-10min**: Analysis & reports

## 🛡️ Security Proven
- **Confidentiality**: AES-256-GCM encryption
- **Integrity**: RSA digital signatures
- **Authentication**: Public key cryptography
- **Forward Secrecy**: Ephemeral session keys
- **Anti-Forensics**: Secure key wiping

**Result**: All attacks blocked, Q-SAFE security validated
