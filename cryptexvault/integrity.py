"""
CryptexVault - Integrity Checker
Hash-based file integrity verification
"""

import hashlib
import json
import os
import base64
from typing import Optional
from datetime import datetime


class IntegrityChecker:
    """Provides hash-based integrity verification for files."""
    
    # Supported hash algorithms
    ALGORITHMS = ['sha256', 'sha384', 'sha512', 'blake2b']
    DEFAULT_ALGORITHM = 'sha256'
    CHUNK_SIZE = 64 * 1024  # 64KB chunks
    
    def __init__(self, algorithm: str = DEFAULT_ALGORITHM):
        """
        Initialize the integrity checker.
        
        Args:
            algorithm: Hash algorithm to use (sha256, sha384, sha512, blake2b)
        """
        if algorithm not in self.ALGORITHMS:
            raise ValueError(f"Unsupported algorithm. Choose from: {self.ALGORITHMS}")
        self.algorithm = algorithm
    
    def compute_file_hash(self, file_path: str) -> str:
        """
        Compute the hash of a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Hexadecimal hash string
        """
        if self.algorithm == 'blake2b':
            hasher = hashlib.blake2b()
        else:
            hasher = hashlib.new(self.algorithm)
        
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(self.CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
        
        return hasher.hexdigest()
    
    def compute_data_hash(self, data: bytes) -> str:
        """
        Compute the hash of raw bytes data.
        
        Args:
            data: Bytes to hash
            
        Returns:
            Hexadecimal hash string
        """
        if self.algorithm == 'blake2b':
            hasher = hashlib.blake2b()
        else:
            hasher = hashlib.new(self.algorithm)
        
        hasher.update(data)
        return hasher.hexdigest()
    
    def verify_file(self, file_path: str, expected_hash: str) -> bool:
        """
        Verify a file's integrity against an expected hash.
        
        Args:
            file_path: Path to the file to verify
            expected_hash: Expected hash value
            
        Returns:
            True if the file matches the expected hash
        """
        actual_hash = self.compute_file_hash(file_path)
        return actual_hash.lower() == expected_hash.lower()
    
    def create_integrity_file(self, file_path: str, integrity_file_path: str) -> dict:
        """
        Create an integrity record file for a given file.
        
        Args:
            file_path: Path to the file to create integrity record for
            integrity_file_path: Path to save the integrity record
            
        Returns:
            The integrity record dictionary
        """
        file_hash = self.compute_file_hash(file_path)
        file_stat = os.stat(file_path)
        
        integrity_record = {
            'version': 1,
            'file_name': os.path.basename(file_path),
            'algorithm': self.algorithm,
            'hash': file_hash,
            'file_size': file_stat.st_size,
            'created_at': datetime.utcnow().isoformat(),
            'original_modified_time': file_stat.st_mtime
        }
        
        with open(integrity_file_path, 'w') as f:
            json.dump(integrity_record, f, indent=2)
        
        return integrity_record
    
    def verify_with_integrity_file(self, file_path: str, integrity_file_path: str) -> tuple[bool, Optional[str]]:
        """
        Verify a file using its integrity record file.
        
        Args:
            file_path: Path to the file to verify
            integrity_file_path: Path to the integrity record file
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            with open(integrity_file_path, 'r') as f:
                integrity_record = json.load(f)
            
            # Use the algorithm from the record
            original_algorithm = self.algorithm
            self.algorithm = integrity_record.get('algorithm', self.DEFAULT_ALGORITHM)
            
            try:
                actual_hash = self.compute_file_hash(file_path)
            finally:
                self.algorithm = original_algorithm
            
            expected_hash = integrity_record['hash']
            
            if actual_hash.lower() != expected_hash.lower():
                return False, "Hash mismatch - file has been modified"
            
            # Optionally check file size
            actual_size = os.path.getsize(file_path)
            expected_size = integrity_record.get('file_size')
            
            if expected_size and actual_size != expected_size:
                return False, f"Size mismatch - expected {expected_size}, got {actual_size}"
            
            return True, None
            
        except FileNotFoundError:
            return False, "Integrity file not found"
        except json.JSONDecodeError:
            return False, "Invalid integrity file format"
        except KeyError as e:
            return False, f"Missing required field in integrity file: {e}"
    
    def create_manifest(self, directory_path: str, manifest_path: str, recursive: bool = True) -> dict:
        """
        Create a manifest file containing hashes for all files in a directory.
        
        Args:
            directory_path: Path to the directory
            manifest_path: Path to save the manifest file
            recursive: Whether to include subdirectories
            
        Returns:
            The manifest dictionary
        """
        files_info = {}
        
        if recursive:
            for root, dirs, files in os.walk(directory_path):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    rel_path = os.path.relpath(file_path, directory_path)
                    
                    files_info[rel_path] = {
                        'hash': self.compute_file_hash(file_path),
                        'size': os.path.getsize(file_path)
                    }
        else:
            for file_name in os.listdir(directory_path):
                file_path = os.path.join(directory_path, file_name)
                if os.path.isfile(file_path):
                    files_info[file_name] = {
                        'hash': self.compute_file_hash(file_path),
                        'size': os.path.getsize(file_path)
                    }
        
        manifest = {
            'version': 1,
            'algorithm': self.algorithm,
            'created_at': datetime.utcnow().isoformat(),
            'base_directory': os.path.basename(directory_path),
            'files': files_info
        }
        
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)
        
        return manifest
    
    def verify_manifest(self, directory_path: str, manifest_path: str) -> tuple[bool, list[str]]:
        """
        Verify all files in a directory against a manifest.
        
        Args:
            directory_path: Path to the directory
            manifest_path: Path to the manifest file
            
        Returns:
            Tuple of (all_valid, list_of_errors)
        """
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
        
        original_algorithm = self.algorithm
        self.algorithm = manifest.get('algorithm', self.DEFAULT_ALGORITHM)
        
        errors = []
        
        try:
            for rel_path, file_info in manifest['files'].items():
                file_path = os.path.join(directory_path, rel_path)
                
                if not os.path.exists(file_path):
                    errors.append(f"Missing file: {rel_path}")
                    continue
                
                actual_hash = self.compute_file_hash(file_path)
                if actual_hash.lower() != file_info['hash'].lower():
                    errors.append(f"Hash mismatch: {rel_path}")
                
                actual_size = os.path.getsize(file_path)
                if actual_size != file_info['size']:
                    errors.append(f"Size mismatch: {rel_path}")
        
        finally:
            self.algorithm = original_algorithm
        
        return len(errors) == 0, errors
