"""
CryptexVault - Backup Manager
Encrypted backup creation and restoration
"""

import os
import json
import tarfile
import tempfile
import shutil
from datetime import datetime
from typing import Optional, List
from .crypto_engine import CryptoEngine
from .key_manager import KeyManager, KDFType
from .integrity import IntegrityChecker


class BackupManager:
    """Create and restore encrypted backups of files and directories."""
    
    BACKUP_EXTENSION = '.cvbackup'
    METADATA_FILE = 'backup_metadata.json'
    
    def __init__(self, key_manager: Optional[KeyManager] = None):
        """
        Initialize the backup manager.
        
        Args:
            key_manager: Optional KeyManager instance (creates default if not provided)
        """
        self.key_manager = key_manager or KeyManager()
        self.integrity_checker = IntegrityChecker()
    
    def create_backup(
        self,
        source_paths: List[str],
        backup_path: str,
        password: str,
        compression: str = 'gz',
        include_hidden: bool = False
    ) -> dict:
        """
        Create an encrypted backup of files/directories.
        
        Args:
            source_paths: List of file/directory paths to backup
            backup_path: Path for the output backup file
            password: Password for encryption
            compression: Compression type ('gz', 'bz2', 'xz', or '' for none)
            include_hidden: Whether to include hidden files
            
        Returns:
            Backup metadata dictionary
        """
        if not backup_path.endswith(self.BACKUP_EXTENSION):
            backup_path += self.BACKUP_EXTENSION
        
        # Validate source paths
        for path in source_paths:
            if not os.path.exists(path):
                raise FileNotFoundError(f"Source path not found: {path}")
        
        # Create temporary directory for staging
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create archive
            archive_path = os.path.join(temp_dir, 'backup.tar')
            if compression:
                archive_path += f'.{compression}'
            
            mode = 'w'
            if compression:
                mode += f':{compression}'
            
            # Collect file info for metadata
            files_info = []
            
            with tarfile.open(archive_path, mode) as tar:
                for source_path in source_paths:
                    if os.path.isfile(source_path):
                        # Single file
                        arcname = os.path.basename(source_path)
                        tar.add(source_path, arcname=arcname)
                        files_info.append({
                            'path': arcname,
                            'type': 'file',
                            'size': os.path.getsize(source_path),
                            'hash': self.integrity_checker.compute_file_hash(source_path)
                        })
                    else:
                        # Directory
                        base_name = os.path.basename(source_path.rstrip('/'))
                        for root, dirs, files in os.walk(source_path):
                            # Filter hidden files if needed
                            if not include_hidden:
                                dirs[:] = [d for d in dirs if not d.startswith('.')]
                                files = [f for f in files if not f.startswith('.')]
                            
                            for file_name in files:
                                file_path = os.path.join(root, file_name)
                                rel_path = os.path.relpath(file_path, os.path.dirname(source_path))
                                tar.add(file_path, arcname=rel_path)
                                files_info.append({
                                    'path': rel_path,
                                    'type': 'file',
                                    'size': os.path.getsize(file_path),
                                    'hash': self.integrity_checker.compute_file_hash(file_path)
                                })
            
            # Create metadata
            metadata = {
                'version': 1,
                'created_at': datetime.utcnow().isoformat(),
                'compression': compression,
                'kdf_type': self.key_manager.kdf_type.value,
                'files_count': len(files_info),
                'files': files_info
            }
            
            # Save metadata
            metadata_path = os.path.join(temp_dir, self.METADATA_FILE)
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            # Create combined archive with metadata
            combined_path = os.path.join(temp_dir, 'combined.tar')
            with tarfile.open(combined_path, 'w') as tar:
                tar.add(metadata_path, arcname=self.METADATA_FILE)
                tar.add(archive_path, arcname='data.tar' + (f'.{compression}' if compression else ''))
            
            # Derive key and encrypt
            key, salt = self.key_manager.derive_key_direct(password)
            crypto_engine = CryptoEngine(key)
            
            # Add salt to the beginning of backup file
            with open(backup_path, 'wb') as f:
                f.write(salt)
            
            # Encrypt and append to backup file
            encrypted_path = os.path.join(temp_dir, 'encrypted.bin')
            crypto_engine.encrypt_file(combined_path, encrypted_path)
            
            # Append encrypted data
            with open(backup_path, 'ab') as f_out:
                with open(encrypted_path, 'rb') as f_in:
                    shutil.copyfileobj(f_in, f_out)
            
            # Compute final backup hash
            metadata['backup_hash'] = self.integrity_checker.compute_file_hash(backup_path)
        
        return metadata
    
    def restore_backup(
        self,
        backup_path: str,
        restore_path: str,
        password: str,
        overwrite: bool = False
    ) -> dict:
        """
        Restore files from an encrypted backup.
        
        Args:
            backup_path: Path to the backup file
            restore_path: Directory to restore files to
            password: Password for decryption
            overwrite: Whether to overwrite existing files
            
        Returns:
            Restoration metadata
        """
        if not os.path.exists(backup_path):
            raise FileNotFoundError(f"Backup not found: {backup_path}")
        
        # Create restore directory if needed
        os.makedirs(restore_path, exist_ok=True)
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Read salt from backup file
            with open(backup_path, 'rb') as f:
                salt = f.read(self.key_manager.SALT_LENGTH)
                encrypted_data_start = f.tell()
            
            # Derive key
            key = self.key_manager.derive_key(password, salt)
            crypto_engine = CryptoEngine(key)
            
            # Extract encrypted portion to temp file
            encrypted_path = os.path.join(temp_dir, 'encrypted.bin')
            with open(backup_path, 'rb') as f_in:
                f_in.seek(encrypted_data_start)
                with open(encrypted_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            # Decrypt
            decrypted_path = os.path.join(temp_dir, 'decrypted.tar')
            try:
                crypto_engine.decrypt_file(encrypted_path, decrypted_path)
            except Exception as e:
                raise ValueError(f"Decryption failed - incorrect password or corrupted backup: {e}")
            
            # Extract combined archive
            combined_extract = os.path.join(temp_dir, 'combined')
            os.makedirs(combined_extract, exist_ok=True)
            
            with tarfile.open(decrypted_path, 'r') as tar:
                tar.extractall(combined_extract)
            
            # Read metadata
            metadata_path = os.path.join(combined_extract, self.METADATA_FILE)
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            # Find and extract data archive
            compression = metadata.get('compression', '')
            data_archive_name = 'data.tar' + (f'.{compression}' if compression else '')
            data_archive_path = os.path.join(combined_extract, data_archive_name)
            
            mode = 'r'
            if compression:
                mode += f':{compression}'
            
            restored_files = []
            failed_files = []
            
            with tarfile.open(data_archive_path, mode) as tar:
                for member in tar.getmembers():
                    dest_path = os.path.join(restore_path, member.name)
                    
                    # Check if file exists
                    if os.path.exists(dest_path) and not overwrite:
                        failed_files.append({
                            'path': member.name,
                            'reason': 'File exists and overwrite=False'
                        })
                        continue
                    
                    # Create parent directories
                    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                    
                    try:
                        tar.extract(member, restore_path)
                        restored_files.append(member.name)
                    except Exception as e:
                        failed_files.append({
                            'path': member.name,
                            'reason': str(e)
                        })
            
            # Verify integrity of restored files
            integrity_errors = []
            files_info = {f['path']: f for f in metadata.get('files', [])}
            
            for file_name in restored_files:
                if file_name in files_info:
                    file_path = os.path.join(restore_path, file_name)
                    expected_hash = files_info[file_name]['hash']
                    actual_hash = self.integrity_checker.compute_file_hash(file_path)
                    
                    if actual_hash.lower() != expected_hash.lower():
                        integrity_errors.append(file_name)
        
        return {
            'restored_files': restored_files,
            'failed_files': failed_files,
            'integrity_errors': integrity_errors,
            'backup_created_at': metadata.get('created_at'),
            'total_files': metadata.get('files_count', 0)
        }
    
    def list_backup_contents(self, backup_path: str, password: str) -> dict:
        """
        List contents of an encrypted backup without extracting.
        
        Args:
            backup_path: Path to the backup file
            password: Password for decryption
            
        Returns:
            Backup metadata including file list
        """
        if not os.path.exists(backup_path):
            raise FileNotFoundError(f"Backup not found: {backup_path}")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Read salt
            with open(backup_path, 'rb') as f:
                salt = f.read(self.key_manager.SALT_LENGTH)
            
            # Derive key
            key = self.key_manager.derive_key(password, salt)
            crypto_engine = CryptoEngine(key)
            
            # Extract and decrypt
            encrypted_path = os.path.join(temp_dir, 'encrypted.bin')
            with open(backup_path, 'rb') as f_in:
                f_in.seek(self.key_manager.SALT_LENGTH)
                with open(encrypted_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            decrypted_path = os.path.join(temp_dir, 'decrypted.tar')
            crypto_engine.decrypt_file(encrypted_path, decrypted_path)
            
            # Extract just the metadata
            with tarfile.open(decrypted_path, 'r') as tar:
                metadata_member = tar.getmember(self.METADATA_FILE)
                tar.extract(metadata_member, temp_dir)
            
            metadata_path = os.path.join(temp_dir, self.METADATA_FILE)
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
        
        return metadata
    
    def verify_backup(self, backup_path: str, password: str) -> tuple[bool, Optional[str]]:
        """
        Verify backup integrity without restoring.
        
        Args:
            backup_path: Path to the backup file
            password: Password for decryption
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            metadata = self.list_backup_contents(backup_path, password)
            return True, None
        except ValueError as e:
            return False, f"Decryption error: {e}"
        except Exception as e:
            return False, f"Verification error: {e}"
