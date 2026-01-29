"""
CryptexVault - Crypto Engine
Core AES-256 encryption and decryption functionality
"""

import os
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Constants
BLOCK_SIZE = 16  # AES block size in bytes
CHUNK_SIZE = 64 * 1024  # 64KB chunks for file processing


class CryptoEngine:
    """AES-256 encryption engine for secure file encryption/decryption."""
    
    def __init__(self, key: bytes):
        """
        Initialize the crypto engine with a 256-bit key.
        
        Args:
            key: 32-byte (256-bit) encryption key
        """
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes (256 bits) for AES-256")
        self.key = key
    
    def encrypt_file(self, input_path: str, output_path: str) -> bytes:
        """
        Encrypt a file using AES-256-CBC.
        
        Args:
            input_path: Path to the file to encrypt
            output_path: Path to save the encrypted file
            
        Returns:
            The IV used for encryption (for storage/verification)
        """
        # Generate a random 16-byte IV
        iv = os.urandom(BLOCK_SIZE)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Get original file size for padding removal during decryption
        file_size = os.path.getsize(input_path)
        
        with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            # Write IV at the beginning of the encrypted file
            outfile.write(iv)
            
            # Write original file size (8 bytes, big-endian)
            outfile.write(struct.pack('>Q', file_size))
            
            # Encrypt file in chunks
            while True:
                chunk = infile.read(CHUNK_SIZE)
                if len(chunk) == 0:
                    break
                
                # Pad the last chunk if necessary
                if len(chunk) % BLOCK_SIZE != 0:
                    padding_length = BLOCK_SIZE - (len(chunk) % BLOCK_SIZE)
                    chunk += bytes([padding_length]) * padding_length
                elif len(chunk) == 0:
                    # Handle empty final chunk - add full block of padding
                    chunk = bytes([BLOCK_SIZE]) * BLOCK_SIZE
                
                encrypted_chunk = encryptor.update(chunk)
                outfile.write(encrypted_chunk)
            
            # Finalize encryption
            final_block = encryptor.finalize()
            if final_block:
                outfile.write(final_block)
        
        return iv
    
    def decrypt_file(self, input_path: str, output_path: str) -> bool:
        """
        Decrypt a file encrypted with AES-256-CBC.
        
        Args:
            input_path: Path to the encrypted file
            output_path: Path to save the decrypted file
            
        Returns:
            True if decryption was successful
        """
        with open(input_path, 'rb') as infile:
            # Read IV from the beginning of the file
            iv = infile.read(BLOCK_SIZE)
            if len(iv) != BLOCK_SIZE:
                raise ValueError("Invalid encrypted file format - missing IV")
            
            # Read original file size
            size_data = infile.read(8)
            if len(size_data) != 8:
                raise ValueError("Invalid encrypted file format - missing size")
            original_size = struct.unpack('>Q', size_data)[0]
            
            # Create cipher for decryption
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            with open(output_path, 'wb') as outfile:
                bytes_written = 0
                
                while True:
                    chunk = infile.read(CHUNK_SIZE)
                    if len(chunk) == 0:
                        break
                    
                    decrypted_chunk = decryptor.update(chunk)
                    
                    # Calculate how much to write (avoid writing padding)
                    remaining = original_size - bytes_written
                    if remaining < len(decrypted_chunk):
                        outfile.write(decrypted_chunk[:remaining])
                        bytes_written += remaining
                    else:
                        outfile.write(decrypted_chunk)
                        bytes_written += len(decrypted_chunk)
                
                # Finalize decryption
                final_block = decryptor.finalize()
                if final_block:
                    remaining = original_size - bytes_written
                    if remaining > 0:
                        outfile.write(final_block[:remaining])
        
        return True
    
    def encrypt_data(self, data: bytes) -> tuple[bytes, bytes]:
        """
        Encrypt raw bytes data.
        
        Args:
            data: Bytes to encrypt
            
        Returns:
            Tuple of (iv, encrypted_data)
        """
        iv = os.urandom(BLOCK_SIZE)
        
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Pad data to block size
        padding_length = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
        padded_data = data + bytes([padding_length]) * padding_length
        
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        return iv, encrypted_data
    
    def decrypt_data(self, iv: bytes, encrypted_data: bytes) -> bytes:
        """
        Decrypt raw bytes data.
        
        Args:
            iv: Initialization vector used for encryption
            encrypted_data: Encrypted bytes
            
        Returns:
            Decrypted bytes
        """
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Remove PKCS7 padding
        padding_length = decrypted_padded[-1]
        return decrypted_padded[:-padding_length]
