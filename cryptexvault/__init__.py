"""
CryptexVault - Secure File Encryption System
"""

from .crypto_engine import CryptoEngine
from .key_manager import KeyManager, KDFType
from .integrity import IntegrityChecker
from .secure_delete import SecureDelete
from .backup import BackupManager

__version__ = "1.0.0"
__all__ = [
    'CryptoEngine',
    'KeyManager',
    'KDFType',
    'IntegrityChecker',
    'SecureDelete',
    'BackupManager'
]
