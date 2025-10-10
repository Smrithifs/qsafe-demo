# Q-SAFE MITM Demonstration - Judge Guide

## Quick Start (5 Minutes)

### 1. Launch Demo
```bash
cd qsafe-demo
./demo_mitm.sh
```

### 2. Open Dashboards
- **Main Dashboard**: http://localhost:5000
- **Network Topology**: http://localhost:5001

### 3. Key Observations
- ✅ All MITM attacks fail
- ✅ Encrypted messages remain secure
- ✅ Self-destruct prevents key recovery
- ✅ PCAP files show attack attempts

---

## Detailed Demonstration Flow

### Phase 1: Normal Operation (2 minutes)
**What to watch:**
- Devices connect and generate RSA keys
- Encrypted messages sent through satellite
- Zero-knowledge relay (satellite cannot decrypt)

**Expected logs:**
```
[12:34:56] [DEVICE_A] [SECURE] Generated RSA keys
[12:34:57] [DEVICE_A] [SECURE] Sending encrypted message to DEVICE_B
[12:34:58] [SATELLITE] [SECURE] Relaying encrypted data (cannot decrypt)
[12:34:59] [DEVICE_B] [SECURE] Message decrypted and verified
```

### Phase 2: MITM Attack Simulation (3 minutes)
**What happens:**
- MITM interceptor captures all network traffic
- Attempts direct decryption of ciphertext
- Tries session key extraction
- Attempts message tampering
- All attacks fail with detailed logs

**Expected attack logs:**
```
[12:35:10] [ATTACKER] [BREACH] Intercepted encrypted message MSG_001
[12:35:11] [ATTACKER] [BREACH] DECRYPTION_FAILED: Invalid private key
[12:35:12] [ATTACKER] [BREACH] SESSION_KEY_EXTRACTION_FAILED: No private key
[12:35:13] [ATTACKER] [BREACH] Tampered ciphertext: deadbeef... → beefdead...
[12:35:14] [DEVICE_B] [BREACH] Signature verification failed - attack detected
```

### Phase 3: Key Extraction Attempt (2 minutes)
**What happens:**
- Simulates device capture
- Self-destruct wipes all cryptographic material
- Attacker attempts key file recovery
- Recovery fails due to secure wiping

**Expected logs:**
```
[12:35:20] [DEVICE_A] [BREACH] CAPTURE DETECTED - Initiating self-destruct
[12:35:21] [DEVICE_A] [SECURE] Wiping private keys (3 passes)
[12:35:22] [DEVICE_A] [SECURE] Wiping session keys
[12:35:23] [ATTACKER] [BREACH] KEY_EXTRACTION_FAILED: Key file wiped (zero bytes)
```

---

## Generated Artifacts

### 1. PCAP Files (Wireshark Analysis)
- **Location**: `logs/mitm_capture.pcap`
- **Contents**: Real network packets with Q-SAFE messages
- **Analysis**: Use provided Wireshark filters

```bash
# Open in Wireshark
wireshark logs/mitm_capture.pcap

# Command line analysis
tshark -r logs/mitm_capture.pcap -Y 'tcp.port == 5000'
```

### 2. Attack Reports
- **Location**: `logs/mitm_report.txt`
- **Contents**: Comprehensive analysis of all attack attempts
- **Summary**: All attacks failed or were detected

### 3. Network Topology
- **URL**: http://localhost:5001
- **Features**: Live animated message routes
- **Visualization**: Shows secure vs intercepted traffic

---

## Security Validation Checklist

### ✅ Cryptographic Protection
- [ ] RSA encryption with AES-GCM hybrid mode
- [ ] Digital signatures prevent tampering
- [ ] Replay protection via timestamps
- [ ] Perfect forward secrecy with ephemeral keys

### ✅ MITM Attack Resistance
- [ ] Direct decryption attempts fail
- [ ] Session key extraction impossible
- [ ] Message tampering detected
- [ ] Replay attacks blocked

### ✅ Self-Destruct Mechanism
- [ ] Capture detection triggers wipe
- [ ] Multiple-pass secure deletion
- [ ] Key files zeroed out
- [ ] Recovery attempts fail

### ✅ Zero-Knowledge Satellite
- [ ] Satellite cannot decrypt messages
- [ ] Only encrypted data visible
- [ ] No plaintext in satellite logs
- [ ] End-to-end encryption maintained

---

## Technical Deep Dive

### Encryption Flow
1. **Key Generation**: RSA-2048 keypairs per device
2. **Message Encryption**: 
   - Generate random AES-256-GCM session key
   - Encrypt message with session key
   - Encrypt session key with recipient's RSA public key
3. **Digital Signature**: Sign entire message with sender's RSA private key
4. **Transmission**: Send encrypted payload + signature through satellite

### Attack Scenarios Tested
1. **Passive Interception**: Capture and analyze ciphertext
2. **Active MITM**: Modify messages in transit
3. **Replay Attack**: Resend old messages
4. **Key Exfiltration**: Extract keys from captured device

### Why Attacks Fail
- **Strong Cryptography**: RSA-2048 + AES-256-GCM
- **Signature Verification**: Detects any tampering
- **Timestamp Validation**: Prevents replay attacks
- **Secure Key Storage**: Self-destruct prevents recovery

---

## Wireshark Analysis Guide

### Key Filters
```
# All Q-SAFE traffic
tcp.port == 5000

# Encrypted messages only
tcp.port == 5000 and frame contains "encrypted_data"

# Large payloads (likely encrypted)
tcp.port == 5000 and tcp.len > 500

# Mesh networking (satellite bypass)
tcp.port == 8080 or tcp.port == 8081
```

### What to Look For
1. **Message Structure**: JSON with encrypted_data, signature, timestamp
2. **Ciphertext**: Hex-encoded encrypted payload
3. **Signatures**: RSA signatures for integrity
4. **Attack Attempts**: Malformed or suspicious packets

---

## Troubleshooting

### Demo Won't Start
```bash
# Check dependencies
pip install -r requirements.txt

# Kill existing processes
pkill -f "python3.*demo"

# Check ports
lsof -i :5000 -i :5001
```

### No PCAP Files Generated
```bash
# Check scapy installation
python3 -c "import scapy; print('OK')"

# Run PCAP generator manually
python3 pcap_generator/packet_capture.py --sample
```

### MITM Interceptor Issues
```bash
# Check network interface
ifconfig

# Test packet capture permissions
sudo python3 mitm_simulator/mitm_interceptor.py --duration 10
```

---

## Expected Demo Outcomes

### Security Assertions Proven
1. **Confidentiality**: Encrypted data remains unreadable
2. **Integrity**: Message tampering is detected
3. **Authentication**: Digital signatures verify sender
4. **Non-repudiation**: Signatures prevent denial
5. **Forward Secrecy**: Captured keys don't compromise past messages

### Attack Mitigation Demonstrated
- ❌ Passive eavesdropping: Ciphertext unbreakable
- ❌ Active MITM: Signature verification fails
- ❌ Replay attacks: Timestamp validation blocks
- ❌ Key extraction: Self-destruct prevents recovery

### Judge Validation Points
1. Review live logs showing attack failures
2. Examine PCAP files in Wireshark
3. Verify MITM report conclusions
4. Observe network topology visualization
5. Confirm self-destruct effectiveness

---

## Contact & Support

**Demo Duration**: ~10 minutes
**Key Files**: `demo_mitm.sh`, `logs/`, `wireshark_demo/`
**Dashboards**: localhost:5000 (main), localhost:5001 (topology)

For technical questions or issues during demonstration, refer to the detailed logs in the `logs/` directory or the comprehensive test suite in `tests/`.

**Security Note**: This demonstration uses simulated attacks for educational purposes. All cryptographic implementations follow industry best practices.
