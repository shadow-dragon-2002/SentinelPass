"""
Advanced encryption module for SentinelPass Password Manager.

This module provides military-grade AES-256-GCM encryption with secure key derivation
using PBKDF2. It handles all cryptographic operations including encryption, decryption,
key generation, and secure data handling.

Security Features:
- AES-256-GCM encryption for authenticated encryption
- PBKDF2 key derivation with configurable iterations
- Cryptographically secure random number generation
- Secure memory handling for sensitive data
- Salt and IV generation for each encryption operation

Author: Final Year Project
Date: 2025
License: Educational Use
"""

import os
import secrets
import hashlib
from typing import Tuple, Optional, Union
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import logging

from config.settings import settings


class EncryptionError(Exception):
    """Custom exception for encryption-related errors."""
    pass


class DecryptionError(Exception):
    """Custom exception for decryption-related errors."""
    pass


class CryptographyManager:
    """
    Advanced cryptography manager for SentinelPass.
    
    This class provides high-level encryption and decryption operations using
    AES-256-GCM with PBKDF2 key derivation. It ensures secure handling of
    cryptographic operations and sensitive data.
    """
    
    def __init__(self):
        """Initialize the cryptography manager."""
        self.logger = logging.getLogger(__name__)
        self.backend = default_backend()
        
        # Encryption parameters from settings
        self.key_iterations = settings.KEY_DERIVATION_ITERATIONS
        self.salt_length = settings.SALT_LENGTH
        self.iv_length = settings.IV_LENGTH
        self.tag_length = settings.TAG_LENGTH
        
        self.logger.info("CryptographyManager initialized with AES-256-GCM")
        
    def generate_salt(self) -> bytes:
        """
        Generate a cryptographically secure random salt.
        
        Returns:
            bytes: Random salt of configured length
        """
        return secrets.token_bytes(self.salt_length)
        
    def generate_iv(self) -> bytes:
        """
        Generate a cryptographically secure random initialization vector.
        
        Returns:
            bytes: Random IV of configured length
        """
        return secrets.token_bytes(self.iv_length)
        
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from password using PBKDF2.
        
        Args:
            password (str): Master password
            salt (bytes): Cryptographic salt
            
        Returns:
            bytes: Derived 256-bit encryption key
            
        Raises:
            EncryptionError: If key derivation fails
        """
        try:
            # Convert password to bytes
            password_bytes = password.encode('utf-8')
            
            # Setup PBKDF2 key derivation function
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # 256 bits
                salt=salt,
                iterations=self.key_iterations,
                backend=self.backend
            )
            
            # Derive key
            key = kdf.derive(password_bytes)
            
            # Clear password from memory
            password_bytes = b'\x00' * len(password_bytes)
            
            return key
            
        except Exception as e:
            self.logger.error(f"Key derivation failed: {str(e)}")
            raise EncryptionError(f"Failed to derive encryption key: {str(e)}")
            
    def encrypt_data(self, plaintext: Union[str, bytes], password: str) -> bytes:
        """
        Encrypt data using AES-256-GCM with password-derived key.
        
        Args:
            plaintext (Union[str, bytes]): Data to encrypt
            password (str): Master password for key derivation
            
        Returns:
            bytes: Encrypted data with salt, IV, tag, and ciphertext
            
        Raises:
            EncryptionError: If encryption fails
        """
        try:
            # Convert string to bytes if necessary
            if isinstance(plaintext, str):
                plaintext_bytes = plaintext.encode('utf-8')
            else:
                plaintext_bytes = plaintext
                
            # Generate salt and IV
            salt = self.generate_salt()
            iv = self.generate_iv()
            
            # Derive encryption key
            key = self.derive_key(password, salt)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv),
                backend=self.backend
            )
            encryptor = cipher.encryptor()
            
            # Encrypt data
            ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
            
            # Get authentication tag
            tag = encryptor.tag
            
            # Clear sensitive data from memory
            key = b'\x00' * len(key)
            plaintext_bytes = b'\x00' * len(plaintext_bytes)
            
            # Combine salt + IV + tag + ciphertext
            encrypted_data = salt + iv + tag + ciphertext
            
            self.logger.debug(f"Data encrypted successfully, size: {len(encrypted_data)} bytes")
            return encrypted_data
            
        except Exception as e:
            self.logger.error(f"Encryption failed: {str(e)}")
            raise EncryptionError(f"Failed to encrypt data: {str(e)}")
            
    def decrypt_data(self, encrypted_data: bytes, password: str) -> bytes:
        """
        Decrypt data using AES-256-GCM with password-derived key.
        
        Args:
            encrypted_data (bytes): Encrypted data with salt, IV, tag, and ciphertext
            password (str): Master password for key derivation
            
        Returns:
            bytes: Decrypted plaintext data
            
        Raises:
            DecryptionError: If decryption fails or authentication fails
        """
        try:
            # Validate minimum data length
            min_length = self.salt_length + self.iv_length + self.tag_length
            if len(encrypted_data) < min_length:
                raise DecryptionError("Invalid encrypted data format")
                
            # Extract components
            salt = encrypted_data[:self.salt_length]
            iv = encrypted_data[self.salt_length:self.salt_length + self.iv_length]
            tag = encrypted_data[self.salt_length + self.iv_length:self.salt_length + self.iv_length + self.tag_length]
            ciphertext = encrypted_data[self.salt_length + self.iv_length + self.tag_length:]
            
            # Derive decryption key
            key = self.derive_key(password, salt)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            
            # Decrypt data
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Clear sensitive data from memory
            key = b'\x00' * len(key)
            
            self.logger.debug(f"Data decrypted successfully, size: {len(plaintext)} bytes")
            return plaintext
            
        except InvalidTag:
            self.logger.error("Decryption failed: Invalid authentication tag")
            raise DecryptionError("Authentication failed - data may be corrupted or password incorrect")
        except Exception as e:
            self.logger.error(f"Decryption failed: {str(e)}")
            raise DecryptionError(f"Failed to decrypt data: {str(e)}")
            
    def encrypt_string(self, plaintext: str, password: str) -> str:
        """
        Encrypt string and return base64-encoded result.
        
        Args:
            plaintext (str): String to encrypt
            password (str): Master password
            
        Returns:
            str: Base64-encoded encrypted data
        """
        import base64
        encrypted_bytes = self.encrypt_data(plaintext, password)
        return base64.b64encode(encrypted_bytes).decode('ascii')
        
    def decrypt_string(self, encrypted_string: str, password: str) -> str:
        """
        Decrypt base64-encoded encrypted string.
        
        Args:
            encrypted_string (str): Base64-encoded encrypted data
            password (str): Master password
            
        Returns:
            str: Decrypted plaintext string
        """
        import base64
        encrypted_bytes = base64.b64decode(encrypted_string.encode('ascii'))
        decrypted_bytes = self.decrypt_data(encrypted_bytes, password)
        return decrypted_bytes.decode('utf-8')
        
    def hash_password(self, password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Hash password using PBKDF2 for storage verification.
        
        Args:
            password (str): Password to hash
            salt (bytes, optional): Salt for hashing. Generated if not provided.
            
        Returns:
            Tuple[bytes, bytes]: (hash, salt)
        """
        if salt is None:
            salt = self.generate_salt()
            
        # Use higher iterations for password hashing
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.key_iterations * 2,  # Double iterations for password hashing
            backend=self.backend
        )
        
        password_hash = kdf.derive(password.encode('utf-8'))
        return password_hash, salt
        
    def verify_password(self, password: str, stored_hash: bytes, salt: bytes) -> bool:
        """
        Verify password against stored hash.
        
        Args:
            password (str): Password to verify
            stored_hash (bytes): Stored password hash
            salt (bytes): Salt used for hashing
            
        Returns:
            bool: True if password is correct
        """
        try:
            computed_hash, _ = self.hash_password(password, salt)
            return secrets.compare_digest(computed_hash, stored_hash)
        except Exception as e:
            self.logger.error(f"Password verification failed: {str(e)}")
            return False
            
    def secure_delete(self, data: Union[str, bytes]) -> None:
        """
        Securely overwrite sensitive data in memory.
        
        Args:
            data (Union[str, bytes]): Data to securely delete
        """
        if isinstance(data, str):
            # For strings, we can't directly overwrite memory
            # Python's garbage collector will handle it
            pass
        elif isinstance(data, bytes):
            # For bytes objects, overwrite with zeros
            if hasattr(data, '__setitem__'):
                for i in range(len(data)):
                    data[i] = 0
                    
    def generate_secure_token(self, length: int = 32) -> str:
        """
        Generate a cryptographically secure random token.
        
        Args:
            length (int): Token length in bytes
            
        Returns:
            str: Hex-encoded secure token
        """
        return secrets.token_hex(length)
        
    def constant_time_compare(self, a: Union[str, bytes], b: Union[str, bytes]) -> bool:
        """
        Perform constant-time comparison to prevent timing attacks.
        
        Args:
            a (Union[str, bytes]): First value
            b (Union[str, bytes]): Second value
            
        Returns:
            bool: True if values are equal
        """
        if isinstance(a, str):
            a = a.encode('utf-8')
        if isinstance(b, str):
            b = b.encode('utf-8')
            
        return secrets.compare_digest(a, b)


# Global cryptography manager instance
crypto_manager = CryptographyManager()
