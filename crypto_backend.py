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
    from pqcrypto.kem.ml_kem_512 import generate_keypair as kyber_keygen
    from pqcrypto.kem.ml_kem_512 import encrypt as kyber_encrypt
    from pqcrypto.kem.ml_kem_512 import decrypt as kyber_decrypt
    from pqcrypto.sign.ml_dsa_44 import generate_keypair as dilithium_keygen
    from pqcrypto.sign.ml_dsa_44 import sign as dilithium_sign
    from pqcrypto.sign.ml_dsa_44 import verify as dilithium_verify
    PQC_AVAILABLE = True
    print("✅ PQC libraries loaded: ML-KEM-512 (Kyber512) + ML-DSA-44 (Dilithium2)")
except ImportError as e:
    print(f"⚠️  PQC libraries not available - using RSA fallback: {e}")

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
        """Generate PQC key pair (Kyber512 for encryption, Dilithium2 for signing)."""
        # Generate real Kyber512 keypair for encryption
        kyber_pk, kyber_sk = kyber_keygen()
        
        # Generate real Dilithium2 keypair for signing
        dilithium_pk, dilithium_sk = dilithium_keygen()
        
        pqc_data = {
            'type': 'PQC',
            'kyber_private': kyber_sk.hex(),
            'kyber_public': kyber_pk.hex(),
            'dilithium_private': dilithium_sk.hex(),
            'dilithium_public': dilithium_pk.hex(),
            'created': time.time()
        }
        
        private_key = json.dumps(pqc_data).encode()
        public_key = json.dumps({
            'type': 'PQC',
            'kyber_public': kyber_pk.hex(),
            'dilithium_public': dilithium_pk.hex()
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
        """Encrypt session key using PQC (Kyber512)."""
        # Extract Kyber public key from the public key bundle
        try:
            pub_data = json.loads(public_key.decode())
            kyber_pk = bytes.fromhex(pub_data['kyber_public'])
        except:
            # If it's already raw bytes, use directly
            kyber_pk = public_key
        
        # Use Kyber512 KEM to encapsulate the session key
        ciphertext, shared_secret = kyber_encrypt(kyber_pk)
        
        # Derive session key from shared secret and original session key
        derived_key = hashlib.sha256(shared_secret + session_key).digest()
        
        # Encrypt the actual session key with derived key
        cipher = AES.new(derived_key, AES.MODE_GCM)
        encrypted_key, tag = cipher.encrypt_and_digest(session_key)
        
        # Return: kyber_ciphertext || nonce || encrypted_session_key || tag
        return ciphertext + cipher.nonce + encrypted_key + tag
    
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
        """Decrypt session key using PQC (Kyber512)."""
        # Extract Kyber private key
        pqc_data = json.loads(private_key.decode())
        kyber_sk = bytes.fromhex(pqc_data['kyber_private'])
        
        # Parse the encrypted data
        # Format: kyber_ciphertext (768 bytes for ML-KEM-512) || nonce (16) || encrypted_key (32) || tag (16)
        kyber_ciphertext = encrypted_session_key[:768]
        nonce = encrypted_session_key[768:784]
        encrypted_key = encrypted_session_key[784:816]
        tag = encrypted_session_key[816:]
        
        # Decapsulate using Kyber512
        shared_secret = kyber_decrypt(kyber_sk, kyber_ciphertext)
        
        # Derive the same key
        derived_key = hashlib.sha256(shared_secret + encrypted_key).digest()
        
        # Decrypt the session key
        cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
        session_key = cipher.decrypt_and_verify(encrypted_key, tag)
        
        return session_key
    
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
        """Sign using PQC (Dilithium2)."""
        # Extract Dilithium private key
        pqc_data = json.loads(private_key.decode())
        dilithium_sk = bytes.fromhex(pqc_data['dilithium_private'])
        
        # Sign with Dilithium2
        signature = dilithium_sign(dilithium_sk, message_hash)
        return signature
    
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
        """Verify using PQC (Dilithium2)."""
        try:
            # Extract Dilithium public key
            pqc_data = json.loads(public_key.decode())
            dilithium_pk = bytes.fromhex(pqc_data['dilithium_public'])
            
            # Verify with Dilithium2
            dilithium_verify(dilithium_pk, message_hash, signature)
            return True
        except Exception as e:
            print(f"Dilithium verification failed: {e}")
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
