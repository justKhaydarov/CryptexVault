# CryptexVault 🔐

**Secure File Encryption System**

CryptexVault is a robust file encryption tool that protects your sensitive files using industry-standard AES-256 encryption with secure password-based key derivation.

## Features

- 🔒 **AES-256 Encryption** - Military-grade encryption for your files
- 🔑 **Secure Key Derivation** - PBKDF2 or Argon2id for password-based key generation
- ✅ **Integrity Verification** - SHA-256 hash verification to detect tampering
- 🗑️ **Secure Deletion** - DoD 5220.22-M and Gutmann methods for secure file wiping
- 📦 **Encrypted Backups** - Create password-protected compressed backups
- 📁 **Folder Support** - Encrypt entire directories with a single command

## Installation

### Prerequisites

- Python 3.10 or higher
- pip package manager

### Install Dependencies

```bash
cd CryptexVault
pip install -r requirements.txt
```

## Usage

### Encrypt a File

```bash
python main.py encrypt secret_document.pdf
```

Options:
- `-o, --output` - Specify output file path
- `--kdf` - Choose key derivation function (`argon2` or `pbkdf2`)
- `--delete-original` - Delete original file after encryption
- `--secure-delete` - Use secure deletion for original file

### Decrypt a File

```bash
python main.py decrypt secret_document.pdf.wncry (reference XD)
```

Options:
- `-o, --output` - Specify output file path

### Compute File Hash

```bash
python main.py hash myfile.txt
python main.py hash myfile.txt -a sha512
python main.py hash myfile.txt -v <expected_hash>
```

### Secure Delete

```bash
python main.py secure-delete sensitive_file.txt
python main.py secure-delete -m gutmann old_data/
```

Methods:
- `simple` - Single random overwrite pass
- `dod` - DoD 5220.22-M 3-pass overwrite (default)
- `gutmann` - 35-pass Gutmann method

### Create Encrypted Backup

```bash
python main.py backup documents/ photos/ -o my_backup.cvbackup
```

Options:
- `--compression` - Compression type (`gz`, `bz2`, `xz`, or none)
- `--include-hidden` - Include hidden files

### Restore Backup

```bash
python main.py restore my_backup.cvbackup -d ./restored/
```

### List Backup Contents

```bash
python main.py list-backup my_backup.cvbackup
```

## Security Details

### Encryption

- **Algorithm**: AES-256-CBC
- **Key Size**: 256 bits
- **IV**: Random 128-bit IV for each encryption
- **Padding**: PKCS7

### Key Derivation

**Argon2id** (recommended):
- Time cost: 3 iterations
- Memory cost: 64 MB
- Parallelism: 4 threads

**PBKDF2**:
- Algorithm: HMAC-SHA256
- Iterations: 600,000
- Salt: 256-bit random

### Integrity

- SHA-256 hash stored with encrypted files
- Automatic verification on decryption
- Manifest support for directory integrity

## Project Structure

```
CryptexVault/
├── main.py                 # CLI entry point
├── requirements.txt        # Python dependencies
├── README.md              # This file
└── cryptexvault/          # Core module
    ├── __init__.py        # Package exports
    ├── crypto_engine.py   # AES encryption/decryption
    ├── key_manager.py     # Key derivation (PBKDF2/Argon2)
    ├── integrity.py       # Hash-based verification
    ├── secure_delete.py   # Secure file deletion
    └── backup.py          # Encrypted backup support
```

## License

MIT License - See LICENSE file for details.

## Security Notice

⚠️ **Important**: 
- Always use strong passwords (12+ characters with mixed case, numbers, and symbols)
- Store your passwords securely - there is no password recovery
- Test decryption before deleting original files
- Keep backups of important data

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

## Author

Created with security in mind 🛡️
