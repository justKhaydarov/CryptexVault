#!/usr/bin/env python3
"""
CryptexVault - GUI Application
Tkinter-based graphical interface for file encryption and decryption
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import threading

from cryptexvault import (
    CryptoEngine,
    KeyManager,
    KDFType,
    IntegrityChecker
)


class CryptexVaultGUI:
    """Main GUI application for CryptexVault."""
    
    def __init__(self, root):
        self.root = root
        self.root.title("CryptexVault - Secure File Encryption")
        self.root.geometry("600x500")
        self.root.resizable(True, True)
        
        # Set dark theme colors
        self.bg_color = "#1e1e1e"
        self.fg_color = "#ffffff"
        self.accent_color = "#007acc"
        self.entry_bg = "#2d2d2d"
        self.button_bg = "#0e639c"
        
        self.root.configure(bg=self.bg_color)
        
        # Configure styles
        self.setup_styles()
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.create_file_tab()
        self.create_text_tab()
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        self.status_bar = tk.Label(
            root, 
            textvariable=self.status_var,
            bg=self.bg_color,
            fg=self.fg_color,
            anchor=tk.W,
            padx=10
        )
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
    
    def setup_styles(self):
        """Configure ttk styles for dark theme."""
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('TNotebook', background=self.bg_color)
        style.configure('TNotebook.Tab', background=self.entry_bg, foreground=self.fg_color, padding=[10, 5])
        style.map('TNotebook.Tab', background=[('selected', self.accent_color)])
        
        style.configure('TFrame', background=self.bg_color)
        style.configure('TLabel', background=self.bg_color, foreground=self.fg_color)
        style.configure('TButton', background=self.button_bg, foreground=self.fg_color)
        style.configure('TEntry', fieldbackground=self.entry_bg, foreground=self.fg_color)
        style.configure('TCombobox', fieldbackground=self.entry_bg, foreground=self.fg_color)
    
    def create_file_tab(self):
        """Create the file encryption/decryption tab."""
        file_frame = ttk.Frame(self.notebook)
        self.notebook.add(file_frame, text="  File Encryption  ")
        
        # File selection
        file_select_frame = ttk.Frame(file_frame)
        file_select_frame.pack(fill=tk.X, padx=20, pady=20)
        
        ttk.Label(file_select_frame, text="Select File:").pack(anchor=tk.W)
        
        file_entry_frame = ttk.Frame(file_select_frame)
        file_entry_frame.pack(fill=tk.X, pady=5)
        
        self.file_path_var = tk.StringVar()
        self.file_entry = tk.Entry(
            file_entry_frame, 
            textvariable=self.file_path_var,
            bg=self.entry_bg,
            fg=self.fg_color,
            insertbackground=self.fg_color,
            width=50
        )
        self.file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        browse_btn = tk.Button(
            file_entry_frame,
            text="Browse",
            command=self.browse_file,
            bg=self.button_bg,
            fg=self.fg_color,
            activebackground=self.accent_color
        )
        browse_btn.pack(side=tk.RIGHT, padx=(10, 0))
        
        # Password
        pass_frame = ttk.Frame(file_frame)
        pass_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(pass_frame, text="Password:").pack(anchor=tk.W)
        self.file_password_var = tk.StringVar()
        self.file_password_entry = tk.Entry(
            pass_frame,
            textvariable=self.file_password_var,
            show="*",
            bg=self.entry_bg,
            fg=self.fg_color,
            insertbackground=self.fg_color
        )
        self.file_password_entry.pack(fill=tk.X, pady=5)
        
        # KDF Selection
        kdf_frame = ttk.Frame(file_frame)
        kdf_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(kdf_frame, text="Key Derivation:").pack(side=tk.LEFT)
        self.kdf_var = tk.StringVar(value="argon2")
        kdf_combo = ttk.Combobox(
            kdf_frame,
            textvariable=self.kdf_var,
            values=["argon2", "pbkdf2"],
            state="readonly",
            width=15
        )
        kdf_combo.pack(side=tk.LEFT, padx=10)
        
        # Buttons
        btn_frame = ttk.Frame(file_frame)
        btn_frame.pack(pady=30)
        
        encrypt_btn = tk.Button(
            btn_frame,
            text="🔒 Encrypt File",
            command=self.encrypt_file,
            bg="#28a745",
            fg=self.fg_color,
            activebackground="#218838",
            width=15,
            height=2
        )
        encrypt_btn.pack(side=tk.LEFT, padx=10)
        
        decrypt_btn = tk.Button(
            btn_frame,
            text="🔓 Decrypt File",
            command=self.decrypt_file,
            bg="#dc3545",
            fg=self.fg_color,
            activebackground="#c82333",
            width=15,
            height=2
        )
        decrypt_btn.pack(side=tk.LEFT, padx=10)
        
        # Progress
        self.file_progress_var = tk.StringVar(value="")
        progress_label = tk.Label(
            file_frame,
            textvariable=self.file_progress_var,
            bg=self.bg_color,
            fg=self.accent_color
        )
        progress_label.pack(pady=10)
    
    def create_text_tab(self):
        """Create the text encryption/decryption tab."""
        text_frame = ttk.Frame(self.notebook)
        self.notebook.add(text_frame, text="  Text Encryption  ")
        
        # Password for text
        pass_frame = ttk.Frame(text_frame)
        pass_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(pass_frame, text="Password:").pack(anchor=tk.W)
        self.text_password_var = tk.StringVar()
        self.text_password_entry = tk.Entry(
            pass_frame,
            textvariable=self.text_password_var,
            show="*",
            bg=self.entry_bg,
            fg=self.fg_color,
            insertbackground=self.fg_color
        )
        self.text_password_entry.pack(fill=tk.X, pady=5)
        
        # Input text area
        input_frame = ttk.Frame(text_frame)
        input_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        ttk.Label(input_frame, text="Input Text:").pack(anchor=tk.W)
        self.input_text = tk.Text(
            input_frame,
            height=6,
            bg=self.entry_bg,
            fg=self.fg_color,
            insertbackground=self.fg_color
        )
        self.input_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Buttons
        btn_frame = ttk.Frame(text_frame)
        btn_frame.pack(pady=10)
        
        encrypt_text_btn = tk.Button(
            btn_frame,
            text="🔒 Encrypt Text",
            command=self.encrypt_text,
            bg="#28a745",
            fg=self.fg_color,
            activebackground="#218838",
            width=15
        )
        encrypt_text_btn.pack(side=tk.LEFT, padx=10)
        
        decrypt_text_btn = tk.Button(
            btn_frame,
            text="🔓 Decrypt Text",
            command=self.decrypt_text,
            bg="#dc3545",
            fg=self.fg_color,
            activebackground="#c82333",
            width=15
        )
        decrypt_text_btn.pack(side=tk.LEFT, padx=10)
        
        clear_btn = tk.Button(
            btn_frame,
            text="Clear",
            command=self.clear_text,
            bg=self.entry_bg,
            fg=self.fg_color,
            width=10
        )
        clear_btn.pack(side=tk.LEFT, padx=10)
        
        # Output text area
        output_frame = ttk.Frame(text_frame)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        ttk.Label(output_frame, text="Output:").pack(anchor=tk.W)
        self.output_text = tk.Text(
            output_frame,
            height=6,
            bg=self.entry_bg,
            fg=self.fg_color,
            insertbackground=self.fg_color
        )
        self.output_text.pack(fill=tk.BOTH, expand=True, pady=5)
    
    def browse_file(self):
        """Open file browser dialog."""
        filepath = filedialog.askopenfilename()
        if filepath:
            self.file_path_var.set(filepath)
    
    def encrypt_file(self):
        """Encrypt the selected file."""
        filepath = self.file_path_var.get()
        password = self.file_password_var.get()
        
        if not filepath:
            messagebox.showerror("Error", "Please select a file")
            return
        
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
        
        if len(password) < 8:
            if not messagebox.askyesno("Warning", "Password is less than 8 characters. Continue anyway?"):
                return
        
        def do_encrypt():
            try:
                self.status_var.set("Encrypting...")
                self.file_progress_var.set("Deriving key...")
                
                kdf_type = KDFType.ARGON2 if self.kdf_var.get() == "argon2" else KDFType.PBKDF2
                if kdf_type == KDFType.ARGON2 and not KeyManager.is_argon2_available():
                    kdf_type = KDFType.PBKDF2
                
                key_manager = KeyManager(kdf_type)
                key, salt = key_manager.derive_key_direct(password)
                
                self.file_progress_var.set("Computing hash...")
                integrity_checker = IntegrityChecker()
                original_hash = integrity_checker.compute_file_hash(filepath)
                
                self.file_progress_var.set("Encrypting file...")
                crypto_engine = CryptoEngine(key)
                
                output_path = filepath + ".wncry"
                temp_output = output_path + ".tmp"
                crypto_engine.encrypt_file(filepath, temp_output)
                
                with open(output_path, 'wb') as f_out:
                    f_out.write(bytes([1]))
                    f_out.write(bytes([0 if kdf_type == KDFType.PBKDF2 else 1]))
                    f_out.write(salt)
                    f_out.write(bytes.fromhex(original_hash))
                    
                    with open(temp_output, 'rb') as f_in:
                        while True:
                            chunk = f_in.read(64 * 1024)
                            if not chunk:
                                break
                            f_out.write(chunk)
                
                os.remove(temp_output)
                
                self.file_progress_var.set(f"Encrypted: {os.path.basename(output_path)}")
                self.status_var.set("Encryption complete!")
                messagebox.showinfo("Success", f"File encrypted successfully!\n\nSaved as:\n{output_path}")
                
            except Exception as e:
                self.file_progress_var.set("")
                self.status_var.set("Encryption failed")
                messagebox.showerror("Error", f"Encryption failed: {str(e)}")
        
        threading.Thread(target=do_encrypt, daemon=True).start()
    
    def decrypt_file(self):
        """Decrypt the selected file."""
        filepath = self.file_path_var.get()
        password = self.file_password_var.get()
        
        if not filepath:
            messagebox.showerror("Error", "Please select a file")
            return
        
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
        
        def do_decrypt():
            try:
                self.status_var.set("Decrypting...")
                self.file_progress_var.set("Reading file header...")
                
                with open(filepath, 'rb') as f:
                    version = f.read(1)[0]
                    kdf_byte = f.read(1)[0]
                    salt = f.read(32)
                    stored_hash = f.read(32).hex()
                    encrypted_start = f.tell()
                
                kdf_type = KDFType.PBKDF2 if kdf_byte == 0 else KDFType.ARGON2
                
                self.file_progress_var.set("Deriving key...")
                key_manager = KeyManager(kdf_type)
                key = key_manager.derive_key(password, salt)
                
                self.file_progress_var.set("Decrypting file...")
                
                temp_input = filepath + ".tmp"
                with open(filepath, 'rb') as f_in:
                    f_in.seek(encrypted_start)
                    with open(temp_input, 'wb') as f_out:
                        while True:
                            chunk = f_in.read(64 * 1024)
                            if not chunk:
                                break
                            f_out.write(chunk)
                
                if filepath.endswith('.wncry'):
                    output_path = filepath[:-6]
                else:
                    output_path = filepath + ".decrypted"
                
                crypto_engine = CryptoEngine(key)
                crypto_engine.decrypt_file(temp_input, output_path)
                os.remove(temp_input)
                
                self.file_progress_var.set("Verifying integrity...")
                integrity_checker = IntegrityChecker()
                actual_hash = integrity_checker.compute_file_hash(output_path)
                
                if actual_hash.lower() == stored_hash.lower():
                    self.file_progress_var.set(f"Decrypted: {os.path.basename(output_path)}")
                    self.status_var.set("Decryption complete - Integrity verified!")
                    messagebox.showinfo("Success", f"File decrypted successfully!\nIntegrity check: PASSED\n\nSaved as:\n{output_path}")
                else:
                    self.file_progress_var.set("Warning: Integrity check failed!")
                    self.status_var.set("Decryption complete - Integrity FAILED")
                    messagebox.showwarning("Warning", f"File decrypted but integrity check FAILED!\nThe file may be corrupted.\n\nSaved as:\n{output_path}")
                
            except Exception as e:
                if os.path.exists(filepath + ".tmp"):
                    os.remove(filepath + ".tmp")
                self.file_progress_var.set("")
                self.status_var.set("Decryption failed")
                messagebox.showerror("Error", f"Decryption failed: {str(e)}\n\nIncorrect password or corrupted file.")
        
        threading.Thread(target=do_decrypt, daemon=True).start()
    
    def encrypt_text(self):
        """Encrypt the input text."""
        password = self.text_password_var.get()
        plaintext = self.input_text.get("1.0", tk.END).strip()
        
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
        
        if not plaintext:
            messagebox.showerror("Error", "Please enter text to encrypt")
            return
        
        try:
            import base64
            
            kdf_type = KDFType.ARGON2 if KeyManager.is_argon2_available() else KDFType.PBKDF2
            key_manager = KeyManager(kdf_type)
            key, salt = key_manager.derive_key_direct(password)
            
            crypto_engine = CryptoEngine(key)
            iv, encrypted_data = crypto_engine.encrypt_data(plaintext.encode('utf-8'))
            
            # Format: base64(version + kdf_type + salt + iv + encrypted_data)
            combined = bytes([1, 0 if kdf_type == KDFType.PBKDF2 else 1]) + salt + iv + encrypted_data
            result = base64.b64encode(combined).decode('ascii')
            
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", result)
            self.status_var.set("Text encrypted successfully")
            
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
    def decrypt_text(self):
        """Decrypt the input text."""
        password = self.text_password_var.get()
        ciphertext = self.input_text.get("1.0", tk.END).strip()
        
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
        
        if not ciphertext:
            messagebox.showerror("Error", "Please enter text to decrypt")
            return
        
        try:
            import base64
            
            combined = base64.b64decode(ciphertext)
            
            version = combined[0]
            kdf_byte = combined[1]
            salt = combined[2:34]
            iv = combined[34:50]
            encrypted_data = combined[50:]
            
            kdf_type = KDFType.PBKDF2 if kdf_byte == 0 else KDFType.ARGON2
            key_manager = KeyManager(kdf_type)
            key = key_manager.derive_key(password, salt)
            
            crypto_engine = CryptoEngine(key)
            decrypted_data = crypto_engine.decrypt_data(iv, encrypted_data)
            
            result = decrypted_data.decode('utf-8')
            
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", result)
            self.status_var.set("Text decrypted successfully")
            
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}\n\nIncorrect password or invalid data.")
    
    def clear_text(self):
        """Clear all text fields."""
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)
        self.status_var.set("Ready")


def main():
    root = tk.Tk()
    app = CryptexVaultGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
