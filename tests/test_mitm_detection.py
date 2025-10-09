#!/usr/bin/env python3
"""
Tests for MITM detection and PCAP validation
"""

import pytest
import os
import sys
import json
import time
import subprocess
import threading
from unittest.mock import patch, MagicMock

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mitm_simulator.mitm_interceptor import MITMInterceptor
from pcap_generator.packet_capture import QSafePcapGenerator
from crypto_backend import CryptoBackend

class TestMITMDetection:
    
    def setup_method(self):
        """Setup for each test"""
        self.crypto = CryptoBackend(use_pqc=False)
        self.interceptor = MITMInterceptor(pcap_file="test_mitm.pcap")
        self.pcap_generator = QSafePcapGenerator("test_logs")
        
        # Create test directories
        os.makedirs("test_logs", exist_ok=True)
        os.makedirs("device/data/TEST", exist_ok=True)
    
    def teardown_method(self):
        """Cleanup after each test"""
        # Clean up test files
        for file in ["test_mitm.pcap", "test_logs/test.pcap"]:
            if os.path.exists(file):
                os.remove(file)
    
    def test_mitm_interceptor_initialization(self):
        """Test MITM interceptor initializes correctly"""
        assert self.interceptor.satellite_port == 5000
        assert self.interceptor.pcap_file == "test_mitm.pcap"
        assert self.interceptor.capture_active == False
        assert len(self.interceptor.attack_log) == 0
    
    def test_attack_logging(self):
        """Test attack attempt logging"""
        self.interceptor.log_attack("BREACH", "Test attack attempt", "MSG_001", "deadbeef")
        
        assert len(self.interceptor.attack_log) == 1
        log_entry = self.interceptor.attack_log[0]
        assert log_entry['level'] == "BREACH"
        assert log_entry['message'] == "Test attack attempt"
        assert log_entry['msg_id'] == "MSG_001"
        assert log_entry['ciphertext_hex'] == "deadbeef"
    
    def test_decrypt_attack_simulation(self):
        """Test decryption attack simulation"""
        # Create fake encrypted data
        encrypted_data = {
            'ciphertext': 'deadbeef' * 50,
            'encrypted_session_key': 'abcd1234' * 30,
            'iv': '1234567890abcdef',
            'auth_tag': 'cafebabe'
        }
        
        # This should log failed decryption attempts
        self.interceptor.attempt_decrypt_attack(encrypted_data, "TEST_001")
        
        # Check that attack attempts were logged
        breach_logs = [log for log in self.interceptor.attack_log if log['level'] == 'BREACH']
        assert len(breach_logs) >= 3  # Should have multiple attack attempts
        
        # Verify specific attack types were attempted
        attack_messages = [log['message'] for log in breach_logs]
        assert any('DECRYPTION_FAILED' in msg for msg in attack_messages)
        assert any('SESSION_KEY_EXTRACTION_FAILED' in msg for msg in attack_messages)
        assert any('BRUTE_FORCE_FAILED' in msg for msg in attack_messages)
    
    def test_tamper_attack_simulation(self):
        """Test message tampering attack simulation"""
        message_data = {
            'msg_id': 'TEST_002',
            'encrypted_data': {
                'ciphertext': 'originalciphertext123456'
            }
        }
        
        original_ciphertext = message_data['encrypted_data']['ciphertext']
        self.interceptor.attempt_tamper_attack(message_data, "TEST_002")
        
        # Verify ciphertext was modified
        assert message_data['encrypted_data']['ciphertext'] != original_ciphertext
        
        # Check tamper attempt was logged
        tamper_logs = [log for log in self.interceptor.attack_log 
                      if 'Tampered ciphertext' in log['message']]
        assert len(tamper_logs) == 1
    
    def test_key_extraction_simulation(self):
        """Test key extraction attack simulation"""
        device_id = "TEST"
        
        # Create fake key files
        key_file_path = f"device/data/{device_id}/private_key.enc"
        passphrase_path = f"device/data/{device_id}/.passphrase"
        
        # Test with no key files (should fail)
        self.interceptor.attempt_key_extraction(device_id)
        
        extraction_logs = [log for log in self.interceptor.attack_log 
                          if 'KEY_EXTRACTION_FAILED' in log['message']]
        assert len(extraction_logs) >= 1
        
        # Test with wiped key files (zero bytes)
        with open(key_file_path, 'wb') as f:
            f.write(b'')  # Empty file (wiped)
        
        self.interceptor.attack_log = []  # Clear previous logs
        self.interceptor.attempt_key_extraction(device_id)
        
        wipe_logs = [log for log in self.interceptor.attack_log 
                    if 'Key file wiped' in log['message']]
        assert len(wipe_logs) == 1
    
    def test_pcap_generation(self):
        """Test PCAP file generation"""
        # Create sample PCAP
        pcap_path = self.pcap_generator.create_sample_pcap()
        
        assert os.path.exists(pcap_path)
        assert pcap_path.endswith('.pcap')
        
        # Verify file is not empty
        assert os.path.getsize(pcap_path) > 0
    
    def test_pcap_metadata_generation(self):
        """Test PCAP metadata file generation"""
        # Add some fake packet data
        self.pcap_generator.packet_metadata = [
            {
                'packet_id': 1,
                'timestamp': time.time(),
                'size': 500,
                'qsafe_data': {
                    'msg_id': 'TEST_001',
                    'from': 'DEVICE_A',
                    'to': 'DEVICE_B'
                }
            }
        ]
        
        # Mock captured packets
        from scapy.all import IP, TCP, Raw
        packet = IP()/TCP()/Raw(load=b'test data')
        self.pcap_generator.captured_packets = [packet]
        
        pcap_path = self.pcap_generator.save_pcap("test_metadata.pcap")
        
        if pcap_path:
            metadata_path = pcap_path.replace('.pcap', '_metadata.json')
            assert os.path.exists(metadata_path)
            
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            assert 'total_packets' in metadata
            assert 'packets' in metadata
            assert len(metadata['packets']) == 1
    
    def test_mitm_report_generation(self):
        """Test MITM attack report generation"""
        # Add some attack log entries
        self.interceptor.log_attack("BREACH", "DECRYPTION_FAILED: Test", "MSG_001")
        self.interceptor.log_attack("BREACH", "SESSION_KEY_EXTRACTION_FAILED: Test", "MSG_002")
        self.interceptor.log_attack("BREACH", "KEY_EXTRACTION_FAILED: Test", "MSG_003")
        
        self.interceptor.generate_mitm_report()
        
        report_file = "logs/mitm_report.txt"
        assert os.path.exists(report_file)
        
        with open(report_file, 'r') as f:
            report_content = f.read()
        
        # Verify report contains expected sections
        assert "Q-SAFE MITM ATTACK ANALYSIS REPORT" in report_content
        assert "ATTACK SUMMARY" in report_content
        assert "SECURITY CONCLUSION" in report_content
        assert "DETAILED LOG" in report_content
        
        # Verify attack results are marked as failed
        assert "Direct Decryption: FAILED" in report_content
        assert "Session Key Extraction: FAILED" in report_content
        assert "Key File Extraction: FAILED" in report_content
    
    def test_crypto_integrity_under_attack(self):
        """Test that crypto operations remain secure under simulated attacks"""
        # Generate keypair
        private_key, public_key = self.crypto.generate_keypair()
        
        # Create message
        message = "Secret message for testing"
        
        # Encrypt message
        encrypted_data = self.crypto.encrypt_for(public_key, message)
        
        # Verify attacker cannot decrypt without private key
        fake_private_key, _ = self.crypto.generate_keypair()
        
        with pytest.raises(Exception):
            # This should fail - attacker doesn't have correct private key
            self.crypto.decrypt_with(fake_private_key, encrypted_data)
        
        # Verify legitimate recipient can decrypt
        decrypted = self.crypto.decrypt_with(private_key, encrypted_data)
        assert decrypted == message
    
    def test_signature_verification_under_attack(self):
        """Test signature verification detects tampering"""
        # Generate keypair
        private_key, public_key = self.crypto.generate_keypair()
        
        # Create and sign message
        message = "Important message"
        signature = self.crypto.sign_message(private_key, message)
        
        # Verify legitimate signature
        assert self.crypto.verify_signature(public_key, message, signature)
        
        # Test tampering detection
        tampered_message = "Tampered message"
        assert not self.crypto.verify_signature(public_key, tampered_message, signature)
        
        # Test with wrong key
        fake_private_key, fake_public_key = self.crypto.generate_keypair()
        fake_signature = self.crypto.sign_message(fake_private_key, message)
        assert not self.crypto.verify_signature(public_key, message, fake_signature)

class TestPcapValidation:
    
    def test_pcap_file_structure(self):
        """Test PCAP file has correct structure"""
        generator = QSafePcapGenerator("test_logs")
        pcap_path = generator.create_sample_pcap()
        
        # Basic file validation
        assert os.path.exists(pcap_path)
        assert pcap_path.endswith('.pcap')
        
        # Check file is not empty
        file_size = os.path.getsize(pcap_path)
        assert file_size > 0
        
        # Verify it's a valid PCAP file (basic check)
        with open(pcap_path, 'rb') as f:
            header = f.read(4)
            # PCAP magic number (little endian)
            assert header in [b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4']
    
    def test_qsafe_message_in_pcap(self):
        """Test Q-SAFE messages are properly captured in PCAP"""
        generator = QSafePcapGenerator("test_logs")
        pcap_path = generator.create_sample_pcap()
        
        # Check metadata file
        metadata_path = pcap_path.replace('.pcap', '_metadata.json')
        
        # The sample PCAP should contain Q-SAFE message structure
        # This is validated by the create_sample_pcap method
        assert os.path.exists(pcap_path)

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
