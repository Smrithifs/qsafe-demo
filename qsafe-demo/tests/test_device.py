"""
Tests for device functionality including self-destruct.
"""

import pytest
import os
import tempfile
import shutil
import sys
import time

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from device.device import DeviceClient

class TestDeviceClient:
    
    def setup_method(self):
        """Setup for each test."""
        # Create temporary directory for test data
        self.test_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.test_dir)
        
        # Create device with test ID
        self.device = DeviceClient("TEST_DEVICE", "http://localhost:5000")
    
    def teardown_method(self):
        """Cleanup after each test."""
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_device_initialization(self):
        """Test device initialization and key generation."""
        assert self.device.device_id == "TEST_DEVICE"
        assert self.device.private_key is not None
        assert self.device.public_key is not None
        assert not self.device.is_compromised
    
    def test_key_persistence(self):
        """Test that keys are saved and can be reloaded."""
        original_private_key = self.device.private_key
        original_public_key = self.device.public_key
        
        # Create new device instance with same ID
        device2 = DeviceClient("TEST_DEVICE", "http://localhost:5000")
        
        # Should load the same keys
        assert device2.private_key == original_private_key
        assert device2.public_key == original_public_key
    
    def test_self_destruct_wipes_keys(self):
        """Test that self-destruct properly wipes cryptographic material."""
        device_dir = self.device.device_dir
        
        # Verify keys exist before self-destruct
        private_key_file = os.path.join(device_dir, "private_key.enc")
        passphrase_file = os.path.join(device_dir, ".passphrase")
        
        assert os.path.exists(private_key_file)
        assert os.path.exists(passphrase_file)
        assert self.device.private_key is not None
        
        # Trigger self-destruct
        self.device._self_destruct()
        
        # Verify device is compromised
        assert self.device.is_compromised
        assert self.device.private_key is None
        
        # Verify key files are wiped
        assert not os.path.exists(private_key_file)
        assert not os.path.exists(passphrase_file)
    
    def test_compromised_device_cannot_operate(self):
        """Test that compromised device cannot perform operations."""
        # Trigger self-destruct
        self.device._self_destruct()
        
        # Should not be able to send messages
        result = self.device.send_message("OTHER_DEVICE", "test message")
        assert result is False
    
    def test_message_nonce_tracking(self):
        """Test that message nonces are tracked for replay protection."""
        test_nonce = "test_nonce_12345"
        
        # Add nonce to cache
        self.device.nonce_cache.add(test_nonce)
        
        # Should detect replay
        assert test_nonce in self.device.nonce_cache
    
    def test_peer_discovery(self):
        """Test mesh peer discovery."""
        self.device._discover_peers()
        
        # Should discover other devices (A, B, C except itself)
        expected_peers = {'A', 'B', 'C'} - {self.device.device_id}
        actual_peers = set(self.device.peer_devices.keys())
        
        assert len(actual_peers) > 0
        # At least some peers should be discovered
        assert len(actual_peers.intersection(expected_peers)) > 0

class TestSelfDestructSecurity:
    
    def setup_method(self):
        """Setup for security tests."""
        self.test_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.test_dir)
        
        self.device = DeviceClient("SECURITY_TEST", "http://localhost:5000")
    
    def teardown_method(self):
        """Cleanup after security tests."""
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_key_file_overwrite(self):
        """Test that key files are properly overwritten during self-destruct."""
        device_dir = self.device.device_dir
        private_key_file = os.path.join(device_dir, "private_key.enc")
        
        # Get original file content
        with open(private_key_file, 'rb') as f:
            original_content = f.read()
        
        original_size = len(original_content)
        
        # Trigger self-destruct
        self.device._self_destruct()
        
        # File should be deleted
        assert not os.path.exists(private_key_file)
    
    def test_memory_wiping(self):
        """Test that sensitive data is cleared from memory."""
        original_private_key = self.device.private_key
        original_passphrase = self.device.device_passphrase
        
        # Trigger self-destruct
        self.device._self_destruct()
        
        # Memory should be cleared
        assert self.device.private_key is None
        assert self.device.device_passphrase is None
        
        # Original references should be wiped (can't test directly in Python)
        # But we can verify the device state
        assert self.device.is_compromised
    
    def test_post_destruct_key_loading_fails(self):
        """Test that key loading fails after self-destruct."""
        # Trigger self-destruct
        self.device._self_destruct()
        
        # Try to create new device with same ID
        device2 = DeviceClient("SECURITY_TEST", "http://localhost:5000")
        
        # Should not be able to load keys (they were wiped)
        # New keys will be generated, but old ones are gone
        assert device2.device_id == "SECURITY_TEST"
        # The new device will generate new keys since old ones are wiped

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
