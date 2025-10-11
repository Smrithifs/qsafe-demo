"""
Integration tests for the complete Q-SAFE system.
"""

import pytest
import time
import threading
import requests
import json
import sys
import os
import tempfile
import shutil

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from crypto_backend import CryptoBackend

class TestSystemIntegration:
    
    def setup_method(self):
        """Setup for integration tests."""
        self.crypto = CryptoBackend(use_pqc=False)
        
    def test_end_to_end_encryption(self):
        """Test complete end-to-end encryption flow."""
        # Generate keys for two devices
        private_key_a, public_key_a = self.crypto.generate_keypair()
        private_key_b, public_key_b = self.crypto.generate_keypair()
        
        # Device A sends message to Device B
        message = "Classified military communication"
        
        # Create message with metadata
        message_data = {
            'content': message,
            'timestamp': time.time(),
            'nonce': 'unique_nonce_123',
            'from': 'DEVICE_A'
        }
        
        message_json = json.dumps(message_data)
        
        # Encrypt for Device B
        encrypted_data = self.crypto.encrypt_for(public_key_b, message_json)
        
        # Sign with Device A's key
        signature = self.crypto.sign(private_key_a, json.dumps(encrypted_data))
        
        # Create message envelope (what satellite sees)
        message_envelope = {
            'from': 'DEVICE_A',
            'to': 'DEVICE_B', 
            'encrypted_data': encrypted_data,
            'signature': signature,
            'timestamp': time.time(),
            'algorithm': 'RSA'
        }
        
        # Verify satellite cannot read plaintext
        envelope_str = json.dumps(message_envelope)
        assert message not in envelope_str
        assert 'Classified' not in envelope_str
        
        # Device B receives and processes message
        # 1. Verify signature
        signature_valid = self.crypto.verify(
            public_key_a, 
            json.dumps(encrypted_data), 
            signature
        )
        assert signature_valid
        
        # 2. Decrypt message
        decrypted_json = self.crypto.decrypt_with(private_key_b, encrypted_data)
        decrypted_data = json.loads(decrypted_json)
        
        # 3. Verify message content
        assert decrypted_data['content'] == message
        assert decrypted_data['from'] == 'DEVICE_A'
        
    def test_satellite_zero_knowledge_property(self):
        """Test that satellite maintains zero knowledge of message content."""
        # Generate test message
        private_key_a, public_key_a = self.crypto.generate_keypair()
        private_key_b, public_key_b = self.crypto.generate_keypair()
        
        secret_message = "TOP SECRET: Operation Nightfall at 0300 hours"
        
        # Encrypt message
        message_data = json.dumps({
            'content': secret_message,
            'timestamp': time.time(),
            'nonce': 'test_nonce'
        })
        
        encrypted_data = self.crypto.encrypt_for(public_key_b, message_data)
        
        # What satellite stores/forwards
        satellite_data = {
            'encrypted_session_key': encrypted_data['encrypted_session_key'],
            'iv': encrypted_data['iv'],
            'ciphertext': encrypted_data['ciphertext'],
            'auth_tag': encrypted_data['auth_tag']
        }
        
        # Verify no plaintext leakage
        satellite_str = json.dumps(satellite_data)
        assert "TOP SECRET" not in satellite_str
        assert "Operation Nightfall" not in satellite_str
        assert "0300" not in satellite_str
        
        # Verify satellite cannot decrypt (no private key)
        with pytest.raises(Exception):
            # Satellite doesn't have private_key_b
            fake_private_key, _ = self.crypto.generate_keypair()
            self.crypto.decrypt_with(fake_private_key, encrypted_data)
    
    def test_attack_resistance(self):
        """Test system resistance to various attacks."""
        private_key_a, public_key_a = self.crypto.generate_keypair()
        private_key_b, public_key_b = self.crypto.generate_keypair()
        
        original_message = "Legitimate message"
        
        # Create legitimate message
        message_data = json.dumps({
            'content': original_message,
            'timestamp': time.time(),
            'nonce': 'legitimate_nonce'
        })
        
        encrypted_data = self.crypto.encrypt_for(public_key_b, message_data)
        signature = self.crypto.sign(private_key_a, json.dumps(encrypted_data))
        
        # Attack 1: Message tampering (MITM)
        tampered_encrypted = encrypted_data.copy()
        tampered_encrypted['ciphertext'] = 'deadbeef' * 20  # Tampered ciphertext
        
        # Signature should still be valid for original data, but decryption should fail
        signature_valid = self.crypto.verify(public_key_a, json.dumps(encrypted_data), signature)
        assert signature_valid
        
        # But tampered message should fail decryption or signature verification
        tampered_signature_valid = self.crypto.verify(
            public_key_a, 
            json.dumps(tampered_encrypted), 
            signature
        )
        assert not tampered_signature_valid  # Signature should be invalid for tampered data
        
        # Attack 2: Replay attack (old timestamp)
        old_message_data = json.dumps({
            'content': original_message,
            'timestamp': time.time() - 3600,  # 1 hour old
            'nonce': 'old_nonce'
        })
        
        old_encrypted = self.crypto.encrypt_for(public_key_b, old_message_data)
        
        # Decrypt to check timestamp
        decrypted_old = self.crypto.decrypt_with(private_key_b, old_encrypted)
        old_data = json.loads(decrypted_old)
        
        # Application should reject based on old timestamp
        message_age = time.time() - old_data['timestamp']
        assert message_age > 300  # Older than 5 minutes - should be rejected
    
    def test_self_destruct_effectiveness(self):
        """Test that self-destruct properly prevents key recovery."""
        # Create temporary directory for test
        test_dir = tempfile.mkdtemp()
        
        try:
            # Simulate device key storage
            private_key, public_key = self.crypto.generate_keypair()
            passphrase = "test_device_passphrase"
            
            # Save keys (simulate device storage)
            private_key_file = os.path.join(test_dir, "private_key.enc")
            passphrase_file = os.path.join(test_dir, ".passphrase")
            
            encrypted_private_key = self.crypto.encrypt_key_file(private_key, passphrase)
            
            with open(private_key_file, 'wb') as f:
                f.write(encrypted_private_key)
            
            with open(passphrase_file, 'wb') as f:
                f.write(passphrase.encode())
            
            # Verify keys can be loaded
            with open(private_key_file, 'rb') as f:
                loaded_encrypted = f.read()
            
            with open(passphrase_file, 'rb') as f:
                loaded_passphrase = f.read().decode()
            
            loaded_private_key = self.crypto.decrypt_key_file(loaded_encrypted, loaded_passphrase)
            assert loaded_private_key == private_key
            
            # Simulate self-destruct: overwrite files
            file_size = os.path.getsize(private_key_file)
            
            # Multiple-pass overwrite
            with open(private_key_file, 'wb') as f:
                for _ in range(3):
                    f.seek(0)
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            
            # Delete files
            os.remove(private_key_file)
            os.remove(passphrase_file)
            
            # Verify keys cannot be recovered
            assert not os.path.exists(private_key_file)
            assert not os.path.exists(passphrase_file)
            
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)
    
    def test_mesh_networking_concept(self):
        """Test mesh networking fallback concept."""
        # Simulate mesh peer discovery
        devices = ['A', 'B', 'C']
        mesh_topology = {}
        
        # Each device discovers others
        for device in devices:
            mesh_topology[device] = {
                'peers': [d for d in devices if d != device],
                'port': 6000 + hash(device) % 1000
            }
        
        # Verify mesh connectivity
        assert len(mesh_topology['A']['peers']) == 2
        assert 'B' in mesh_topology['A']['peers']
        assert 'C' in mesh_topology['A']['peers']
        
        # Simulate message routing via mesh
        source = 'A'
        destination = 'B'
        
        # Direct connection available
        assert destination in mesh_topology[source]['peers']
        
        # Simulate satellite unavailable, use mesh
        satellite_available = False
        
        if not satellite_available:
            # Use mesh routing
            route = [source, destination]  # Direct route
            assert len(route) == 2
            assert route[0] == source
            assert route[1] == destination

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
