"""
CryptexVault - Secure Delete
Secure file deletion with multiple overwrite passes
"""

import os
import random
from typing import Callable, Optional


class SecureDelete:
    """Securely delete files by overwriting data before removal."""
    
    # DoD 5220.22-M standard patterns
    DOD_PASSES = [
        b'\x00',  # Pass 1: zeros
        b'\xff',  # Pass 2: ones
        None,     # Pass 3: random data
    ]
    
    # Gutmann method - 35 passes (simplified version)
    GUTMANN_PASSES = 35
    
    CHUNK_SIZE = 64 * 1024  # 64KB chunks
    
    def __init__(self, method: str = 'dod'):
        """
        Initialize the secure delete handler.
        
        Args:
            method: Deletion method ('simple', 'dod', 'gutmann')
        """
        self.method = method.lower()
        if self.method not in ['simple', 'dod', 'gutmann']:
            raise ValueError("Method must be 'simple', 'dod', or 'gutmann'")
    
    def secure_delete_file(
        self, 
        file_path: str, 
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> bool:
        """
        Securely delete a file by overwriting it before removal.
        
        Args:
            file_path: Path to the file to delete
            progress_callback: Optional callback function(current_pass, total_passes)
            
        Returns:
            True if deletion was successful
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        if not os.path.isfile(file_path):
            raise ValueError(f"Not a file: {file_path}")
        
        file_size = os.path.getsize(file_path)
        
        if self.method == 'simple':
            self._simple_overwrite(file_path, file_size, progress_callback)
        elif self.method == 'dod':
            self._dod_overwrite(file_path, file_size, progress_callback)
        elif self.method == 'gutmann':
            self._gutmann_overwrite(file_path, file_size, progress_callback)
        
        # Rename file to random name before deletion (obscure original name)
        dir_path = os.path.dirname(file_path)
        random_name = os.path.join(dir_path, self._generate_random_name())
        os.rename(file_path, random_name)
        
        # Finally remove the file
        os.remove(random_name)
        
        return True
    
    def secure_delete_directory(
        self, 
        dir_path: str, 
        progress_callback: Optional[Callable[[str, int, int], None]] = None
    ) -> tuple[int, int]:
        """
        Securely delete all files in a directory.
        
        Args:
            dir_path: Path to the directory
            progress_callback: Optional callback(file_path, current_file, total_files)
            
        Returns:
            Tuple of (successful_deletions, failed_deletions)
        """
        if not os.path.isdir(dir_path):
            raise ValueError(f"Not a directory: {dir_path}")
        
        # Collect all files
        files_to_delete = []
        for root, dirs, files in os.walk(dir_path, topdown=False):
            for file_name in files:
                files_to_delete.append(os.path.join(root, file_name))
        
        successful = 0
        failed = 0
        total = len(files_to_delete)
        
        for i, file_path in enumerate(files_to_delete):
            if progress_callback:
                progress_callback(file_path, i + 1, total)
            
            try:
                self.secure_delete_file(file_path)
                successful += 1
            except Exception:
                failed += 1
        
        # Remove empty directories
        for root, dirs, files in os.walk(dir_path, topdown=False):
            for dir_name in dirs:
                try:
                    os.rmdir(os.path.join(root, dir_name))
                except OSError:
                    pass  # Directory not empty or permission denied
        
        # Try to remove the root directory
        try:
            os.rmdir(dir_path)
        except OSError:
            pass
        
        return successful, failed
    
    def _simple_overwrite(
        self, 
        file_path: str, 
        file_size: int,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ):
        """Single pass random overwrite."""
        if progress_callback:
            progress_callback(1, 1)
        
        self._overwrite_with_pattern(file_path, file_size, None)
    
    def _dod_overwrite(
        self, 
        file_path: str, 
        file_size: int,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ):
        """DoD 5220.22-M 3-pass overwrite."""
        total_passes = len(self.DOD_PASSES)
        
        for i, pattern in enumerate(self.DOD_PASSES):
            if progress_callback:
                progress_callback(i + 1, total_passes)
            
            self._overwrite_with_pattern(file_path, file_size, pattern)
    
    def _gutmann_overwrite(
        self, 
        file_path: str, 
        file_size: int,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ):
        """Gutmann 35-pass overwrite (simplified)."""
        for i in range(self.GUTMANN_PASSES):
            if progress_callback:
                progress_callback(i + 1, self.GUTMANN_PASSES)
            
            # Alternate between specific patterns and random data
            if i < 4 or i >= 31:
                # Random passes at beginning and end
                pattern = None
            else:
                # Various patterns for middle passes
                patterns = [
                    b'\x55', b'\xaa', b'\x92\x49\x24', b'\x49\x24\x92',
                    b'\x24\x92\x49', b'\x00', b'\x11', b'\x22', b'\x33',
                    b'\x44', b'\x55', b'\x66', b'\x77', b'\x88', b'\x99',
                    b'\xaa', b'\xbb', b'\xcc', b'\xdd', b'\xee', b'\xff',
                    b'\x92\x49\x24', b'\x49\x24\x92', b'\x24\x92\x49',
                    b'\x6d\xb6\xdb', b'\xb6\xdb\x6d', b'\xdb\x6d\xb6'
                ]
                pattern = patterns[(i - 4) % len(patterns)]
            
            self._overwrite_with_pattern(file_path, file_size, pattern)
    
    def _overwrite_with_pattern(
        self, 
        file_path: str, 
        file_size: int, 
        pattern: Optional[bytes]
    ):
        """
        Overwrite file with a specific pattern or random data.
        
        Args:
            file_path: Path to the file
            file_size: Size of the file in bytes
            pattern: Byte pattern to use, or None for random data
        """
        with open(file_path, 'r+b') as f:
            bytes_written = 0
            
            while bytes_written < file_size:
                chunk_size = min(self.CHUNK_SIZE, file_size - bytes_written)
                
                if pattern is None:
                    # Random data
                    chunk = os.urandom(chunk_size)
                else:
                    # Repeat pattern to fill chunk
                    repeats = (chunk_size // len(pattern)) + 1
                    chunk = (pattern * repeats)[:chunk_size]
                
                f.write(chunk)
                bytes_written += chunk_size
            
            # Ensure data is written to disk
            f.flush()
            os.fsync(f.fileno())
    
    def _generate_random_name(self, length: int = 16) -> str:
        """Generate a random filename."""
        chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
        return ''.join(random.choice(chars) for _ in range(length))
    
    @staticmethod
    def quick_delete(file_path: str, passes: int = 3) -> bool:
        """
        Quick secure delete with specified number of random passes.
        
        Args:
            file_path: Path to the file
            passes: Number of overwrite passes
            
        Returns:
            True if successful
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        file_size = os.path.getsize(file_path)
        
        for _ in range(passes):
            with open(file_path, 'r+b') as f:
                bytes_written = 0
                while bytes_written < file_size:
                    chunk_size = min(64 * 1024, file_size - bytes_written)
                    f.write(os.urandom(chunk_size))
                    bytes_written += chunk_size
                f.flush()
                os.fsync(f.fileno())
        
        os.remove(file_path)
        return True
