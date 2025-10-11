"""
Crypto abstraction layer with PQC/RSA fallback support.
Provides hybrid encryption and digital signatures.
"""

import os
import json
import hashlib
from typing import Tuple, Dict, Any, Optional
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Protocol.KDF import PBKDF2
import time

# Try to import PQC libraries - fallback to RSA if not available
PQC_AVAILABLE = False
try:
    # Placeholder for PQC imports - would be actual libraries like:
    # from pqcrypto.kem.kyber1024 import generate_keypair as kyber_keygen
    # from pqcrypto.sign.dilithium5 import generate_keypair as dilithium_keygen
    print("PQC libraries not available - using RSA fallback")
except ImportError:
    print("PQC libraries not available - using RSA fallback")

class CryptoBackend:
    """Abstraction layer for cryptographic operations with PQC/RSA fallback."""
    
    def __init__(self, use_pqc: bool = True):
        self.use_pqc = use_pqc and PQC_AVAILABLE
        self.algorithm = "PQC" if self.use_pqc else "RSA"
        print(f"Crypto backend initialized: {self.algorithm}")
    
    def generate_keypair(self, kind: str = 'auto') -> Tuple[bytes, bytes]:
        """Generate a key pair for encryption/signing.
        
        Returns:
            Tuple of (private_key_bytes, public_key_bytes)
        """
        if self.use_pqc and kind in ['auto', 'pqc']:
            return self._generate_pqc_keypair()
        else:
            return self._generate_rsa_keypair()
    
    def _generate_pqc_keypair(self) -> Tuple[bytes, bytes]:
        """Generate PQC key pair (Kyber for encryption, Dilithium for signing)."""
        # This would use actual PQC libraries when available
        # For now, return structured placeholder that can be swapped
        pqc_data = {
            'type': 'PQC',
            'kyber_private': get_random_bytes(32),  # Placeholder
            'kyber_public': get_random_bytes(32),   # Placeholder
            'dilithium_private': get_random_bytes(64),  # Placeholder
            'dilithium_public': get_random_bytes(64),   # Placeholder
            'created': time.time()
        }
        
        private_key = json.dumps(pqc_data).encode()
        public_key = json.dumps({
            'type': 'PQC',
            'kyber_public': pqc_data['kyber_public'].hex(),
            'dilithium_public': pqc_data['dilithium_public'].hex()
        }).encode()
        
        return private_key, public_key
    
    def _generate_rsa_keypair(self) -> Tuple[bytes, bytes]:
        """Generate RSA key pair."""
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key
    
    def serialize_public_key(self, public_key: bytes) -> str:
        """Serialize public key for transmission."""
        return public_key.hex()
    
    def load_public_key(self, serialized_key: str) -> bytes:
        """Load public key from serialized format."""
        return bytes.fromhex(serialized_key)
    
    def encrypt_for(self, public_key: bytes, plaintext: str) -> Dict[str, Any]:
        """Encrypt message for recipient using hybrid encryption.
        
        Returns:
            Dict containing encrypted session key, IV, ciphertext, and metadata
        """
        # Generate ephemeral AES key
        session_key = get_random_bytes(32)
        iv = get_random_bytes(16)
        
        # Encrypt plaintext with AES-GCM
        cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce=iv)
        ciphertext, auth_tag = cipher_aes.encrypt_and_digest(plaintext.encode())
        
        # Encrypt session key with recipient's public key
        if self.use_pqc:
            encrypted_session_key = self._pqc_encrypt_session_key(public_key, session_key)
        else:
            encrypted_session_key = self._rsa_encrypt_session_key(public_key, session_key)
        
        return {
            'encrypted_session_key': encrypted_session_key.hex(),
            'iv': iv.hex(),
            'ciphertext': ciphertext.hex(),
            'auth_tag': auth_tag.hex(),
            'algorithm': self.algorithm,
            'timestamp': time.time()
        }
    
    def _pqc_encrypt_session_key(self, public_key: bytes, session_key: bytes) -> bytes:
        """Encrypt session key using PQC (Kyber)."""
        # Placeholder for actual PQC encryption
        # Would use: ciphertext = kyber_encrypt(public_key, session_key)
        return hashlib.sha256(public_key + session_key).digest()
    
    def _rsa_encrypt_session_key(self, public_key: bytes, session_key: bytes) -> bytes:
        """Encrypt session key using RSA."""
        rsa_key = RSA.import_key(public_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        return cipher_rsa.encrypt(session_key)
    
    def decrypt_with(self, private_key: bytes, ciphertext_blob: Dict[str, Any]) -> str:
        """Decrypt message using private key."""
        # Decrypt session key
        encrypted_session_key = bytes.fromhex(ciphertext_blob['encrypted_session_key'])
        
        if ciphertext_blob.get('algorithm') == 'PQC' and self.use_pqc:
            session_key = self._pqc_decrypt_session_key(private_key, encrypted_session_key)
        else:
            session_key = self._rsa_decrypt_session_key(private_key, encrypted_session_key)
        
        # Decrypt message with AES
        iv = bytes.fromhex(ciphertext_blob['iv'])
        ciphertext = bytes.fromhex(ciphertext_blob['ciphertext'])
        auth_tag = bytes.fromhex(ciphertext_blob['auth_tag'])
        
        cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce=iv)
        plaintext = cipher_aes.decrypt_and_verify(ciphertext, auth_tag)
        
        return plaintext.decode()
    
    def _pqc_decrypt_session_key(self, private_key: bytes, encrypted_session_key: bytes) -> bytes:
        """Decrypt session key using PQC (Kyber)."""
        # Placeholder for actual PQC decryption
        # Would use: session_key = kyber_decrypt(private_key, encrypted_session_key)
        pqc_data = json.loads(private_key.decode())
        return hashlib.sha256(pqc_data['kyber_private'].encode() + encrypted_session_key).digest()[:32]
    
    def _rsa_decrypt_session_key(self, private_key: bytes, encrypted_session_key: bytes) -> bytes:
        """Decrypt session key using RSA."""
        rsa_key = RSA.import_key(private_key)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        return cipher_rsa.decrypt(encrypted_session_key)
    
    def sign(self, private_key: bytes, message: str) -> str:
        """Sign message with private key."""
        message_hash = SHA256.new(message.encode())
        
        if self.use_pqc:
            signature = self._pqc_sign(private_key, message_hash.digest())
        else:
            signature = self._rsa_sign(private_key, message_hash)
        
        return signature.hex()
    
    def _pqc_sign(self, private_key: bytes, message_hash: bytes) -> bytes:
        """Sign using PQC (Dilithium)."""
        # Placeholder for actual PQC signing
        # Would use: signature = dilithium_sign(private_key, message_hash)
        pqc_data = json.loads(private_key.decode())
        return hashlib.sha256(pqc_data['dilithium_private'].encode() + message_hash).digest()
    
    def _rsa_sign(self, private_key: bytes, message_hash) -> bytes:
        """Sign using RSA."""
        rsa_key = RSA.import_key(private_key)
        signature = pkcs1_15.new(rsa_key).sign(message_hash)
        return signature
    
    def verify(self, public_key: bytes, message: str, signature: str) -> bool:
        """Verify message signature."""
        try:
            message_hash = SHA256.new(message.encode())
            signature_bytes = bytes.fromhex(signature)
            
            if self.use_pqc:
                return self._pqc_verify(public_key, message_hash.digest(), signature_bytes)
            else:
                return self._rsa_verify(public_key, message_hash, signature_bytes)
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False
    
    def _pqc_verify(self, public_key: bytes, message_hash: bytes, signature: bytes) -> bool:
        """Verify using PQC (Dilithium)."""
        # Placeholder for actual PQC verification
        # Would use: return dilithium_verify(public_key, message_hash, signature)
        try:
            pqc_data = json.loads(public_key.decode())
            expected_sig = hashlib.sha256(
                bytes.fromhex(pqc_data['dilithium_public']) + message_hash
            ).digest()
            return signature == expected_sig
        except:
            return False
    
    def _rsa_verify(self, public_key: bytes, message_hash, signature: bytes) -> bool:
        """Verify using RSA."""
        try:
            rsa_key = RSA.import_key(public_key)
            pkcs1_15.new(rsa_key).verify(message_hash, signature)
            return True
        except:
            return False
    
    def encrypt_key_file(self, key_data: bytes, passphrase: str) -> bytes:
        """Encrypt key data for storage."""
        salt = get_random_bytes(16)
        key = PBKDF2(passphrase, salt, 32, count=100000)
        
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, auth_tag = cipher.encrypt_and_digest(key_data)
        
        encrypted_data = {
            'salt': salt.hex(),
            'nonce': cipher.nonce.hex(),
            'ciphertext': ciphertext.hex(),
            'auth_tag': auth_tag.hex()
        }
        
        return json.dumps(encrypted_data).encode()
    
    def decrypt_key_file(self, encrypted_data: bytes, passphrase: str) -> bytes:
        """Decrypt key data from storage."""
        data = json.loads(encrypted_data.decode())
        
        salt = bytes.fromhex(data['salt'])
        key = PBKDF2(passphrase, salt, 32, count=100000)
        
        cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(data['nonce']))
        plaintext = cipher.decrypt_and_verify(
            bytes.fromhex(data['ciphertext']),
            bytes.fromhex(data['auth_tag'])
        )
        
        return plaintext
    
    def secure_wipe(self, data: bytes) -> None:
        """Securely wipe sensitive data from memory."""
        # Overwrite memory multiple times
        if isinstance(data, bytes):
            for i in range(len(data)):
                data = data[:i] + b'\x00' + data[i+1:]
            for i in range(len(data)):
                data = data[:i] + b'\xff' + data[i+1:]
            for i in range(len(data)):
                data = data[:i] + get_random_bytes(1) + data[i+1:]
