"""
Tests for crypto backend functionality.
"""

import pytest
import json
import time
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from crypto_backend import CryptoBackend

class TestCryptoBackend:
    
    def setup_method(self):
        """Setup for each test."""
        self.crypto = CryptoBackend(use_pqc=False)  # Use RSA for reliable testing
        
    def test_keypair_generation(self):
        """Test key pair generation."""
        private_key, public_key = self.crypto.generate_keypair()
        
        assert private_key is not None
        assert public_key is not None
        assert len(private_key) > 0
        assert len(public_key) > 0
        assert private_key != public_key
    
    def test_key_serialization(self):
        """Test public key serialization."""
        _, public_key = self.crypto.generate_keypair()
        
        serialized = self.crypto.serialize_public_key(public_key)
        loaded = self.crypto.load_public_key(serialized)
        
        assert loaded == public_key
    
    def test_hybrid_encryption_decryption(self):
        """Test hybrid encryption and decryption."""
        private_key, public_key = self.crypto.generate_keypair()
        plaintext = "This is a secret message for testing!"
        
        # Encrypt
        encrypted_data = self.crypto.encrypt_for(public_key, plaintext)
        
        # Verify structure
        assert 'encrypted_session_key' in encrypted_data
        assert 'iv' in encrypted_data
        assert 'ciphertext' in encrypted_data
        assert 'auth_tag' in encrypted_data
        assert 'algorithm' in encrypted_data
        
        # Decrypt
        decrypted = self.crypto.decrypt_with(private_key, encrypted_data)
        
        assert decrypted == plaintext
    
    def test_digital_signatures(self):
        """Test digital signature creation and verification."""
        private_key, public_key = self.crypto.generate_keypair()
        message = "Message to be signed"
        
        # Sign message
        signature = self.crypto.sign(private_key, message)
        
        assert signature is not None
        assert len(signature) > 0
        
        # Verify signature
        is_valid = self.crypto.verify(public_key, message, signature)
        assert is_valid is True
        
        # Test invalid signature
        is_invalid = self.crypto.verify(public_key, "Different message", signature)
        assert is_invalid is False
    
    def test_key_file_encryption(self):
        """Test key file encryption and decryption."""
        test_data = b"sensitive key material"
        passphrase = "test_passphrase_123"
        
        # Encrypt
        encrypted = self.crypto.encrypt_key_file(test_data, passphrase)
        
        assert encrypted != test_data
        assert len(encrypted) > len(test_data)
        
        # Decrypt
        decrypted = self.crypto.decrypt_key_file(encrypted, passphrase)
        
        assert decrypted == test_data
    
    def test_wrong_passphrase_fails(self):
        """Test that wrong passphrase fails decryption."""
        test_data = b"sensitive key material"
        correct_passphrase = "correct_password"
        wrong_passphrase = "wrong_password"
        
        encrypted = self.crypto.encrypt_key_file(test_data, correct_passphrase)
        
        with pytest.raises(Exception):
            self.crypto.decrypt_key_file(encrypted, wrong_passphrase)
    
    def test_signature_tampering_detection(self):
        """Test that signature tampering is detected."""
        private_key, public_key = self.crypto.generate_keypair()
        message = "Original message"
        
        signature = self.crypto.sign(private_key, message)
        
        # Tamper with signature
        tampered_signature = signature[:-4] + "dead"
        
        is_valid = self.crypto.verify(public_key, message, tampered_signature)
        assert is_valid is False
    
    def test_encryption_produces_different_ciphertexts(self):
        """Test that encrypting the same message produces different ciphertexts."""
        _, public_key = self.crypto.generate_keypair()
        message = "Same message"
        
        encrypted1 = self.crypto.encrypt_for(public_key, message)
        encrypted2 = self.crypto.encrypt_for(public_key, message)
        
        # Should be different due to random IV and session key
        assert encrypted1['ciphertext'] != encrypted2['ciphertext']
        assert encrypted1['iv'] != encrypted2['iv']
    
    def test_cross_device_encryption(self):
        """Test encryption between different key pairs."""
        # Device A keys
        private_key_a, public_key_a = self.crypto.generate_keypair()
        
        # Device B keys  
        private_key_b, public_key_b = self.crypto.generate_keypair()
        
        message = "Message from A to B"
        
        # A encrypts for B
        encrypted = self.crypto.encrypt_for(public_key_b, message)
        
        # B decrypts
        decrypted = self.crypto.decrypt_with(private_key_b, encrypted)
        
        assert decrypted == message
        
        # A should not be able to decrypt (wrong private key)
        with pytest.raises(Exception):
            self.crypto.decrypt_with(private_key_a, encrypted)

class TestSecurityProperties:
    
    def setup_method(self):
        """Setup for each test."""
        self.crypto = CryptoBackend(use_pqc=False)
    
    def test_satellite_cannot_decrypt(self):
        """Test that satellite cannot decrypt messages (zero-knowledge property)."""
        # Generate keys for two devices
        private_key_a, public_key_a = self.crypto.generate_keypair()
        private_key_b, public_key_b = self.crypto.generate_keypair()
        
        message = "Secret military communication"
        
        # Device A encrypts for Device B
        encrypted_data = self.crypto.encrypt_for(public_key_b, message)
        
        # Satellite only sees the encrypted data structure
        satellite_view = {
            'encrypted_session_key': encrypted_data['encrypted_session_key'],
            'ciphertext': encrypted_data['ciphertext'],
            'iv': encrypted_data['iv'],
            'auth_tag': encrypted_data['auth_tag']
        }
        
        # Satellite should not be able to extract plaintext
        # (it doesn't have any private keys)
        ciphertext = bytes.fromhex(satellite_view['ciphertext'])
        
        # Verify ciphertext doesn't contain plaintext
        assert message.encode() not in ciphertext
        assert message not in str(satellite_view)
        
        # Only Device B can decrypt
        decrypted = self.crypto.decrypt_with(private_key_b, encrypted_data)
        assert decrypted == message
    
    def test_replay_protection_timestamps(self):
        """Test that old messages can be detected by timestamp."""
        private_key, public_key = self.crypto.generate_keypair()
        
        # Create message with old timestamp
        old_message_data = {
            'content': 'Old message',
            'timestamp': time.time() - 3600,  # 1 hour old
            'nonce': 'test_nonce_123'
        }
        
        message_json = json.dumps(old_message_data)
        encrypted_data = self.crypto.encrypt_for(public_key, message_json)
        
        # Decrypt and check timestamp
        decrypted_json = self.crypto.decrypt_with(private_key, encrypted_data)
        decrypted_data = json.loads(decrypted_json)
        
        # Application should reject based on timestamp
        message_age = time.time() - decrypted_data['timestamp']
        assert message_age > 300  # Older than 5 minutes
    
    def test_forward_secrecy(self):
        """Test that each message uses a unique session key."""
        _, public_key = self.crypto.generate_keypair()
        
        message1 = "First message"
        message2 = "Second message"
        
        encrypted1 = self.crypto.encrypt_for(public_key, message1)
        encrypted2 = self.crypto.encrypt_for(public_key, message2)
        
        # Each message should use different session key
        assert encrypted1['encrypted_session_key'] != encrypted2['encrypted_session_key']
        assert encrypted1['iv'] != encrypted2['iv']

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
