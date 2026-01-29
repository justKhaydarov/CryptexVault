#!/usr/bin/env python3
"""
CryptexVault - Secure File Encryption System
Main CLI entry point
"""

import argparse
import getpass
import os
import sys
from pathlib import Path

from cryptexvault import (
    CryptoEngine,
    KeyManager,
    KDFType,
    IntegrityChecker,
    SecureDelete,
    BackupManager
)


def get_password(confirm: bool = False) -> str:
    """Get password from user with optional confirmation."""
    password = getpass.getpass("Enter password: ")
    
    if confirm:
        password_confirm = getpass.getpass("Confirm password: ")
        if password != password_confirm:
            print("Error: Passwords do not match")
            sys.exit(1)
    
    if len(password) < 8:
        print("Warning: Password should be at least 8 characters for security")
    
    return password


def encrypt_command(args):
    """Handle file encryption."""
    input_path = args.file
    output_path = args.output or f"{input_path}.encrypted"
    
    if not os.path.exists(input_path):
        print(f"Error: File not found: {input_path}")
        sys.exit(1)
    
    password = get_password(confirm=True)
    
    # Select KDF type
    kdf_type = KDFType.ARGON2 if args.kdf == 'argon2' else KDFType.PBKDF2
    if kdf_type == KDFType.ARGON2 and not KeyManager.is_argon2_available():
        print("Warning: Argon2 not available, using PBKDF2")
        kdf_type = KDFType.PBKDF2
    
    print(f"Encrypting {input_path}...")
    print(f"Using {kdf_type.value.upper()} for key derivation")
    
    # Derive key
    key_manager = KeyManager(kdf_type)
    key, salt = key_manager.derive_key_direct(password)
    
    # Compute original file hash for integrity
    integrity_checker = IntegrityChecker()
    original_hash = integrity_checker.compute_file_hash(input_path)
    
    # Encrypt file
    crypto_engine = CryptoEngine(key)
    
    # Create a temporary encrypted file with salt prepended
    temp_output = output_path + '.tmp'
    crypto_engine.encrypt_file(input_path, temp_output)
    
    # Prepend salt and KDF info to final output
    with open(output_path, 'wb') as f_out:
        # Write header: version (1 byte) + kdf_type (1 byte) + salt (32 bytes)
        f_out.write(bytes([1]))  # Version
        f_out.write(bytes([0 if kdf_type == KDFType.PBKDF2 else 1]))  # KDF type
        f_out.write(salt)
        # Write original hash (32 bytes for SHA256)
        f_out.write(bytes.fromhex(original_hash))
        
        # Append encrypted data
        with open(temp_output, 'rb') as f_in:
            while True:
                chunk = f_in.read(64 * 1024)
                if not chunk:
                    break
                f_out.write(chunk)
    
    # Remove temp file
    os.remove(temp_output)
    
    print(f"File encrypted successfully: {output_path}")
    print(f"Original file hash (SHA256): {original_hash}")
    
    # Optionally delete original
    if args.delete_original:
        if args.secure_delete:
            print("Securely deleting original file...")
            secure_delete = SecureDelete(method=args.secure_delete_method)
            secure_delete.secure_delete_file(input_path)
        else:
            os.remove(input_path)
        print("Original file deleted")


def decrypt_command(args):
    """Handle file decryption."""
    input_path = args.file
    
    if not os.path.exists(input_path):
        print(f"Error: File not found: {input_path}")
        sys.exit(1)
    
    # Determine output path
    if args.output:
        output_path = args.output
    elif input_path.endswith('.encrypted'):
        output_path = input_path[:-10]
    else:
        output_path = input_path + '.decrypted'
    
    password = get_password()
    
    print(f"Decrypting {input_path}...")
    
    # Read header
    with open(input_path, 'rb') as f:
        version = f.read(1)[0]
        kdf_byte = f.read(1)[0]
        salt = f.read(32)
        stored_hash = f.read(32).hex()
        encrypted_start = f.tell()
    
    kdf_type = KDFType.PBKDF2 if kdf_byte == 0 else KDFType.ARGON2
    
    if kdf_type == KDFType.ARGON2 and not KeyManager.is_argon2_available():
        print("Error: This file was encrypted with Argon2 but Argon2 is not available")
        sys.exit(1)
    
    print(f"Using {kdf_type.value.upper()} for key derivation")
    
    # Derive key
    key_manager = KeyManager(kdf_type)
    key = key_manager.derive_key(password, salt)
    
    # Extract encrypted data to temp file
    temp_input = input_path + '.tmp'
    with open(input_path, 'rb') as f_in:
        f_in.seek(encrypted_start)
        with open(temp_input, 'wb') as f_out:
            while True:
                chunk = f_in.read(64 * 1024)
                if not chunk:
                    break
                f_out.write(chunk)
    
    # Decrypt
    crypto_engine = CryptoEngine(key)
    try:
        crypto_engine.decrypt_file(temp_input, output_path)
    except Exception as e:
        os.remove(temp_input)
        if os.path.exists(output_path):
            os.remove(output_path)
        print(f"Error: Decryption failed - incorrect password or corrupted file")
        sys.exit(1)
    
    os.remove(temp_input)
    
    # Verify integrity
    integrity_checker = IntegrityChecker()
    actual_hash = integrity_checker.compute_file_hash(output_path)
    
    if actual_hash.lower() == stored_hash.lower():
        print(f"File decrypted successfully: {output_path}")
        print("Integrity check: PASSED")
    else:
        print(f"File decrypted: {output_path}")
        print("WARNING: Integrity check FAILED - file may be corrupted!")
        print(f"Expected: {stored_hash}")
        print(f"Actual:   {actual_hash}")


def hash_command(args):
    """Compute file hash."""
    if not os.path.exists(args.file):
        print(f"Error: File not found: {args.file}")
        sys.exit(1)
    
    checker = IntegrityChecker(algorithm=args.algorithm)
    file_hash = checker.compute_file_hash(args.file)
    
    print(f"{args.algorithm.upper()}: {file_hash}")
    
    if args.verify:
        if file_hash.lower() == args.verify.lower():
            print("Verification: MATCH")
        else:
            print("Verification: MISMATCH")
            sys.exit(1)


def secure_delete_command(args):
    """Securely delete files."""
    path = args.path
    
    if not os.path.exists(path):
        print(f"Error: Path not found: {path}")
        sys.exit(1)
    
    # Confirm deletion
    if not args.force:
        confirm = input(f"Are you sure you want to securely delete '{path}'? This cannot be undone. [y/N]: ")
        if confirm.lower() != 'y':
            print("Aborted")
            sys.exit(0)
    
    secure_delete = SecureDelete(method=args.method)
    
    def progress_callback(current, total):
        print(f"\rPass {current}/{total}", end='', flush=True)
    
    if os.path.isfile(path):
        print(f"Securely deleting file: {path}")
        secure_delete.secure_delete_file(path, progress_callback)
        print("\nFile securely deleted")
    else:
        print(f"Securely deleting directory: {path}")
        successful, failed = secure_delete.secure_delete_directory(path)
        print(f"\nDeleted {successful} files, {failed} failures")


def backup_command(args):
    """Create encrypted backup."""
    sources = args.sources
    output = args.output
    
    for source in sources:
        if not os.path.exists(source):
            print(f"Error: Source not found: {source}")
            sys.exit(1)
    
    password = get_password(confirm=True)
    
    kdf_type = KDFType.ARGON2 if args.kdf == 'argon2' else KDFType.PBKDF2
    if kdf_type == KDFType.ARGON2 and not KeyManager.is_argon2_available():
        print("Warning: Argon2 not available, using PBKDF2")
        kdf_type = KDFType.PBKDF2
    
    key_manager = KeyManager(kdf_type)
    backup_manager = BackupManager(key_manager)
    
    print(f"Creating backup: {output}")
    metadata = backup_manager.create_backup(
        sources,
        output,
        password,
        compression=args.compression,
        include_hidden=args.include_hidden
    )
    
    print(f"Backup created successfully!")
    print(f"Files backed up: {metadata['files_count']}")
    print(f"Created at: {metadata['created_at']}")


def restore_command(args):
    """Restore from encrypted backup."""
    if not os.path.exists(args.backup):
        print(f"Error: Backup not found: {args.backup}")
        sys.exit(1)
    
    password = get_password()
    
    backup_manager = BackupManager()
    
    print(f"Restoring backup to: {args.destination}")
    result = backup_manager.restore_backup(
        args.backup,
        args.destination,
        password,
        overwrite=args.overwrite
    )
    
    print(f"Restored {len(result['restored_files'])} files")
    
    if result['failed_files']:
        print(f"Failed to restore {len(result['failed_files'])} files:")
        for f in result['failed_files']:
            print(f"  - {f['path']}: {f['reason']}")
    
    if result['integrity_errors']:
        print("WARNING: Integrity errors detected:")
        for f in result['integrity_errors']:
            print(f"  - {f}")


def list_backup_command(args):
    """List backup contents."""
    if not os.path.exists(args.backup):
        print(f"Error: Backup not found: {args.backup}")
        sys.exit(1)
    
    password = get_password()
    
    backup_manager = BackupManager()
    
    try:
        metadata = backup_manager.list_backup_contents(args.backup, password)
        
        print(f"Backup: {args.backup}")
        print(f"Created: {metadata.get('created_at', 'Unknown')}")
        print(f"Files: {metadata.get('files_count', 0)}")
        print(f"Compression: {metadata.get('compression', 'none')}")
        print("\nContents:")
        
        for f in metadata.get('files', []):
            size = f.get('size', 0)
            size_str = f"{size:,} bytes" if size < 1024 else f"{size/1024:.1f} KB"
            print(f"  {f['path']} ({size_str})")
            
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog='cryptexvault',
        description='CryptexVault - Secure File Encryption System'
    )
    parser.add_argument('--version', action='version', version='CryptexVault 1.0.0')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Encrypt command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
    encrypt_parser.add_argument('file', help='File to encrypt')
    encrypt_parser.add_argument('-o', '--output', help='Output file path')
    encrypt_parser.add_argument('--kdf', choices=['pbkdf2', 'argon2'], default='argon2',
                                help='Key derivation function (default: argon2)')
    encrypt_parser.add_argument('--delete-original', action='store_true',
                                help='Delete original file after encryption')
    encrypt_parser.add_argument('--secure-delete', action='store_true',
                                help='Use secure deletion for original file')
    encrypt_parser.add_argument('--secure-delete-method', choices=['simple', 'dod', 'gutmann'],
                                default='dod', help='Secure deletion method')
    encrypt_parser.set_defaults(func=encrypt_command)
    
    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
    decrypt_parser.add_argument('file', help='File to decrypt')
    decrypt_parser.add_argument('-o', '--output', help='Output file path')
    decrypt_parser.set_defaults(func=decrypt_command)
    
    # Hash command
    hash_parser = subparsers.add_parser('hash', help='Compute file hash')
    hash_parser.add_argument('file', help='File to hash')
    hash_parser.add_argument('-a', '--algorithm', choices=['sha256', 'sha384', 'sha512', 'blake2b'],
                             default='sha256', help='Hash algorithm (default: sha256)')
    hash_parser.add_argument('-v', '--verify', help='Verify against expected hash')
    hash_parser.set_defaults(func=hash_command)
    
    # Secure delete command
    delete_parser = subparsers.add_parser('secure-delete', help='Securely delete files')
    delete_parser.add_argument('path', help='File or directory to delete')
    delete_parser.add_argument('-m', '--method', choices=['simple', 'dod', 'gutmann'],
                               default='dod', help='Deletion method (default: dod)')
    delete_parser.add_argument('-f', '--force', action='store_true',
                               help='Skip confirmation prompt')
    delete_parser.set_defaults(func=secure_delete_command)
    
    # Backup command
    backup_parser = subparsers.add_parser('backup', help='Create encrypted backup')
    backup_parser.add_argument('sources', nargs='+', help='Files/directories to backup')
    backup_parser.add_argument('-o', '--output', required=True, help='Output backup file')
    backup_parser.add_argument('--compression', choices=['gz', 'bz2', 'xz', ''],
                               default='gz', help='Compression type (default: gz)')
    backup_parser.add_argument('--kdf', choices=['pbkdf2', 'argon2'], default='argon2',
                               help='Key derivation function')
    backup_parser.add_argument('--include-hidden', action='store_true',
                               help='Include hidden files')
    backup_parser.set_defaults(func=backup_command)
    
    # Restore command
    restore_parser = subparsers.add_parser('restore', help='Restore from encrypted backup')
    restore_parser.add_argument('backup', help='Backup file to restore')
    restore_parser.add_argument('-d', '--destination', required=True,
                                help='Destination directory')
    restore_parser.add_argument('--overwrite', action='store_true',
                                help='Overwrite existing files')
    restore_parser.set_defaults(func=restore_command)
    
    # List backup command
    list_parser = subparsers.add_parser('list-backup', help='List backup contents')
    list_parser.add_argument('backup', help='Backup file to list')
    list_parser.set_defaults(func=list_backup_command)
    
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        sys.exit(0)
    
    args.func(args)


if __name__ == '__main__':
    main()
