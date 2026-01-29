"""
CryptexVault - Key Manager
Password-based key derivation using PBKDF2 and Argon2
"""

import os
import json
import base64
from enum import Enum
from typing import Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

try:
    from argon2.low_level import hash_secret_raw, Type
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False


class KDFType(Enum):
    """Key Derivation Function types."""
    PBKDF2 = "pbkdf2"
    ARGON2 = "argon2"


class KeyManager:
    """Manages key derivation and secure key storage."""
    
    # PBKDF2 settings (NIST recommended)
    PBKDF2_ITERATIONS = 600000  # High iteration count for security
    
    # Argon2 settings (OWASP recommended)
    ARGON2_TIME_COST = 3
    ARGON2_MEMORY_COST = 65536  # 64MB
    ARGON2_PARALLELISM = 4
    
    # Key settings
    KEY_LENGTH = 32  # 256 bits for AES-256
    SALT_LENGTH = 32  # 256-bit salt
    
    def __init__(self, kdf_type: KDFType = KDFType.ARGON2):
        """
        Initialize the key manager.
        
        Args:
            kdf_type: Key derivation function to use (PBKDF2 or Argon2)
        """
        if kdf_type == KDFType.ARGON2 and not ARGON2_AVAILABLE:
            print("Warning: Argon2 not available, falling back to PBKDF2")
            kdf_type = KDFType.PBKDF2
        
        self.kdf_type = kdf_type
    
    def generate_salt(self) -> bytes:
        """Generate a cryptographically secure random salt."""
        return os.urandom(self.SALT_LENGTH)
    
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive a 256-bit key from a password using the configured KDF.
        
        Args:
            password: User's password
            salt: Random salt for key derivation
            
        Returns:
            32-byte derived key
        """
        password_bytes = password.encode('utf-8')
        
        if self.kdf_type == KDFType.ARGON2:
            return self._derive_key_argon2(password_bytes, salt)
        else:
            return self._derive_key_pbkdf2(password_bytes, salt)
    
    def _derive_key_pbkdf2(self, password: bytes, salt: bytes) -> bytes:
        """Derive key using PBKDF2-HMAC-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password)
    
    def _derive_key_argon2(self, password: bytes, salt: bytes) -> bytes:
        """Derive key using Argon2id."""
        return hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=self.ARGON2_TIME_COST,
            memory_cost=self.ARGON2_MEMORY_COST,
            parallelism=self.ARGON2_PARALLELISM,
            hash_len=self.KEY_LENGTH,
            type=Type.ID  # Argon2id - recommended for password hashing
        )
    
    def create_key_file(self, password: str, key_file_path: str) -> bytes:
        """
        Create a key file that stores the salt and KDF parameters.
        The actual key is derived at runtime and never stored.
        
        Args:
            password: User's password
            key_file_path: Path to store the key metadata
            
        Returns:
            The derived encryption key
        """
        salt = self.generate_salt()
        key = self.derive_key(password, salt)
        
        # Store salt and parameters (never the key itself)
        key_metadata = {
            'version': 1,
            'kdf_type': self.kdf_type.value,
            'salt': base64.b64encode(salt).decode('ascii'),
            'parameters': self._get_kdf_parameters()
        }
        
        with open(key_file_path, 'w') as f:
            json.dump(key_metadata, f, indent=2)
        
        # Set restrictive permissions on the key file
        os.chmod(key_file_path, 0o600)
        
        return key
    
    def load_key(self, password: str, key_file_path: str) -> bytes:
        """
        Load and derive the key from a key file.
        
        Args:
            password: User's password
            key_file_path: Path to the key metadata file
            
        Returns:
            The derived encryption key
        """
        with open(key_file_path, 'r') as f:
            key_metadata = json.load(f)
        
        salt = base64.b64decode(key_metadata['salt'])
        
        # Use the KDF type from the file
        saved_kdf_type = KDFType(key_metadata['kdf_type'])
        original_kdf_type = self.kdf_type
        self.kdf_type = saved_kdf_type
        
        try:
            key = self.derive_key(password, salt)
        finally:
            self.kdf_type = original_kdf_type
        
        return key
    
    def _get_kdf_parameters(self) -> dict:
        """Get the current KDF parameters for storage."""
        if self.kdf_type == KDFType.ARGON2:
            return {
                'time_cost': self.ARGON2_TIME_COST,
                'memory_cost': self.ARGON2_MEMORY_COST,
                'parallelism': self.ARGON2_PARALLELISM
            }
        else:
            return {
                'iterations': self.PBKDF2_ITERATIONS,
                'algorithm': 'SHA256'
            }
    
    def derive_key_direct(self, password: str, salt: Optional[bytes] = None) -> tuple[bytes, bytes]:
        """
        Derive a key directly without creating a key file.
        
        Args:
            password: User's password
            salt: Optional salt (generated if not provided)
            
        Returns:
            Tuple of (key, salt)
        """
        if salt is None:
            salt = self.generate_salt()
        
        key = self.derive_key(password, salt)
        return key, salt
    
    @staticmethod
    def is_argon2_available() -> bool:
        """Check if Argon2 is available."""
        return ARGON2_AVAILABLE
