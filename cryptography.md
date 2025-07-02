[Back to Contents](README.md)

# Cryptography: Encoding vs Encryption vs Hashing

> [!IMPORTANT]
> **Don't confuse these!** Encoding ≠ Encryption ≠ Hashing. Each serves different security purposes.

Understanding the differences between encoding, encryption, and hashing is fundamental to application security. These concepts are often confused, but each serves different purposes and provides different security guarantees. This chapter clarifies these concepts and provides practical guidance for developers.

## Table of Contents
- [The Fundamental Differences](#the-fundamental-differences)
- [Encoding](#encoding)
- [Encryption](#encryption)
- [Hashing](#hashing)
- [Digital Signatures](#digital-signatures)
- [Key Management](#key-management)
- [Common Mistakes](#common-mistakes)
- [Practical Implementation Guide](#practical-implementation-guide)

## The Fundamental Differences

> [!NOTE]
> Think of it this way: Encoding is like translating languages, Encryption is like using a secret code, Hashing is like creating a fingerprint.

| Purpose | Encoding | Encryption | Hashing |
|---------|----------|------------|---------|
| **Goal** | Data representation | Data protection | Data integrity |
| **Reversible** | Yes (trivial) | Yes (with key) | No |
| **Key Required** | No | Yes | No |
| **Security** | None | High | Medium-High |
| **Use Cases** | Data transmission | Confidentiality | Passwords, integrity |

### Quick Example

```python
# Encoding - No security, just representation
original = "Hello World"
encoded = base64.b64encode(original.encode()).decode()
decoded = base64.b64decode(encoded).decode()
# encoded = "SGVsbG8gV29ybGQ="
# decoded = "Hello World"

# Encryption - Reversible with key
key = Fernet.generate_key()
f = Fernet(key)
encrypted = f.encrypt(original.encode())
decrypted = f.decrypt(encrypted).decode()
# encrypted = random-looking bytes
# decrypted = "Hello World" (only if you have the key)

# Hashing - One-way function
hashed = hashlib.sha256(original.encode()).hexdigest()
# hashed = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
# Cannot get "Hello World" back from this hash
```

## Encoding

Encoding transforms data from one format to another for compatibility, transmission, or storage purposes. **It provides no security.**

### Common Encoding Schemes

#### Base64 Encoding
```python
import base64

class Base64Handler:
    @staticmethod
    def encode(data):
        """Encode bytes or string to Base64"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return base64.b64encode(data).decode('ascii')
    
    @staticmethod
    def decode(encoded_data):
        """Decode Base64 to bytes"""
        return base64.b64decode(encoded_data)
    
    @staticmethod
    def url_safe_encode(data):
        """URL-safe Base64 encoding"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return base64.urlsafe_b64encode(data).decode('ascii')
    
    @staticmethod
    def url_safe_decode(encoded_data):
        """URL-safe Base64 decoding"""
        return base64.urlsafe_b64decode(encoded_data)

# Usage
handler = Base64Handler()

# Regular Base64
original = "Hello, World! 🌍"
encoded = handler.encode(original)
decoded = handler.decode(encoded).decode('utf-8')
print(f"Original: {original}")
print(f"Encoded: {encoded}")
print(f"Decoded: {decoded}")

# URL-safe Base64 (for URLs and filenames)
url_safe = handler.url_safe_encode("data+with/special=chars")
print(f"URL-safe: {url_safe}")
```

#### Hexadecimal Encoding
```python
class HexHandler:
    @staticmethod
    def encode(data):
        """Encode bytes to hexadecimal string"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return data.hex()
    
    @staticmethod
    def decode(hex_string):
        """Decode hexadecimal string to bytes"""
        return bytes.fromhex(hex_string)

# Usage
hex_handler = HexHandler()
data = "Secret message"
hex_encoded = hex_handler.encode(data)
hex_decoded = hex_handler.decode(hex_encoded).decode('utf-8')
print(f"Hex encoded: {hex_encoded}")
print(f"Hex decoded: {hex_decoded}")
```

#### URL Encoding
```python
from urllib.parse import quote, unquote

class URLHandler:
    @staticmethod
    def encode(text):
        """URL encode text"""
        return quote(text, safe='')
    
    @staticmethod
    def decode(encoded_text):
        """URL decode text"""
        return unquote(encoded_text)

# Usage
url_handler = URLHandler()
original = "Hello World & Friends!"
url_encoded = url_handler.encode(original)
url_decoded = url_handler.decode(url_encoded)
print(f"URL encoded: {url_encoded}")  # Hello%20World%20%26%20Friends%21
print(f"URL decoded: {url_decoded}")
```

### When to Use Encoding

- **Data transmission** over protocols that expect specific formats
- **Web development** (URL encoding, HTML entities)
- **Data storage** in text-based formats
- **Binary data** in text protocols (Base64 in emails)

**Remember: Encoding is NOT security!** Base64 looks scrambled but anyone can decode it instantly.

## Encryption

Encryption transforms data into an unreadable format that can only be reversed with the correct key(s).

### Symmetric Encryption

The same key is used for both encryption and decryption.

```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64

class SymmetricEncryption:
    def __init__(self, password=None):
        if password:
            self.key = self._derive_key_from_password(password)
        else:
            self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
    
    def _derive_key_from_password(self, password, salt=None):
        """Derive encryption key from password using PBKDF2"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,  # Adjust based on security requirements
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def encrypt(self, plaintext):
        """Encrypt plaintext string"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        return self.cipher.encrypt(plaintext)
    
    def decrypt(self, ciphertext):
        """Decrypt to bytes"""
        return self.cipher.decrypt(ciphertext)
    
    def encrypt_file(self, file_path, output_path):
        """Encrypt entire file"""
        with open(file_path, 'rb') as file:
            file_data = file.read()
        
        encrypted_data = self.encrypt(file_data)
        
        with open(output_path, 'wb') as file:
            file.write(encrypted_data)
    
    def decrypt_file(self, encrypted_file_path, output_path):
        """Decrypt entire file"""
        with open(encrypted_file_path, 'rb') as file:
            encrypted_data = file.read()
        
        decrypted_data = self.decrypt(encrypted_data)
        
        with open(output_path, 'wb') as file:
            file.write(decrypted_data)

# Usage examples
# Key-based encryption
encryptor = SymmetricEncryption()
secret_message = "This is a confidential message"

encrypted = encryptor.encrypt(secret_message)
decrypted = encryptor.decrypt(encrypted).decode('utf-8')

print(f"Original: {secret_message}")
print(f"Encrypted: {encrypted}")
print(f"Decrypted: {decrypted}")

# Password-based encryption
password_encryptor = SymmetricEncryption(password="my_secure_password")
encrypted_with_password = password_encryptor.encrypt("Secret data")
```

### AES Encryption (Advanced)

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

class AESEncryption:
    def __init__(self, key=None):
        if key is None:
            self.key = os.urandom(32)  # 256-bit key
        else:
            self.key = key
    
    def encrypt(self, plaintext):
        """Encrypt using AES-CBC with PKCS7 padding"""
        # Generate random IV
        iv = os.urandom(16)
        
        # Pad the plaintext
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode('utf-8'))
        padded_data += padder.finalize()
        
        # Encrypt
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return IV + ciphertext
        return iv + ciphertext
    
    def decrypt(self, encrypted_data):
        """Decrypt AES-CBC encrypted data"""
        # Extract IV and ciphertext
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        # Decrypt
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext)
        plaintext += unpadder.finalize()
        
        return plaintext.decode('utf-8')

# Usage
aes = AESEncryption()
message = "Highly confidential information"
encrypted = aes.encrypt(message)
decrypted = aes.decrypt(encrypted)
```

## Hashing

Hashing is a one-way function that produces a fixed-size output (digest) from variable-size input.

### Cryptographic Hash Functions

```python
import hashlib
import hmac
import secrets
from datetime import datetime

class HashingExamples:
    @staticmethod
    def sha256_hash(data):
        """Simple SHA-256 hash"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha256(data).hexdigest()
    
    @staticmethod
    def sha3_hash(data):
        """SHA-3 hash (more recent standard)"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha3_256(data).hexdigest()
    
    @staticmethod
    def blake2_hash(data, key=None):
        """BLAKE2 hash (fast and secure)"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        if key:
            return hashlib.blake2b(data, key=key.encode()).hexdigest()
        return hashlib.blake2b(data).hexdigest()
    
    @staticmethod
    def hmac_hash(data, key):
        """HMAC for message authentication"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        if isinstance(key, str):
            key = key.encode('utf-8')
        return hmac.new(key, data, hashlib.sha256).hexdigest()
    
    @staticmethod
    def file_hash(file_path, algorithm='sha256'):
        """Hash entire file efficiently"""
        hash_algo = getattr(hashlib, algorithm)()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_algo.update(chunk)
        
        return hash_algo.hexdigest()

# Examples
hasher = HashingExamples()

# Different hash algorithms
data = "Hello, World!"
print(f"SHA-256: {hasher.sha256_hash(data)}")
print(f"SHA-3:   {hasher.sha3_hash(data)}")
print(f"BLAKE2:  {hasher.blake2_hash(data)}")

# HMAC for message authentication
key = "secret_key"
mac = hasher.hmac_hash(data, key)
print(f"HMAC:    {mac}")

# Verify HMAC
def verify_hmac(message, key, expected_mac):
    calculated_mac = hasher.hmac_hash(message, key)
    return hmac.compare_digest(calculated_mac, expected_mac)

is_valid = verify_hmac(data, key, mac)
print(f"HMAC Valid: {is_valid}")
```

### Password Hashing (Secure)

```python
import argon2
import bcrypt
import scrypt

class PasswordHashing:
    def __init__(self, algorithm='argon2id'):
        self.algorithm = algorithm
        if algorithm == 'argon2id':
            self.hasher = argon2.PasswordHasher(
                time_cost=3,      # Number of iterations
                memory_cost=65536, # Memory usage in KB
                parallelism=1,    # Number of threads
                hash_len=32,      # Hash length
                salt_len=16       # Salt length
            )
    
    def hash_password(self, password):
        """Hash password securely"""
        if self.algorithm == 'argon2id':
            return self.hasher.hash(password)
        elif self.algorithm == 'bcrypt':
            salt = bcrypt.gensalt(rounds=12)
            return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
        elif self.algorithm == 'scrypt':
            salt = secrets.token_bytes(32)
            hash_bytes = scrypt.hash(password.encode('utf-8'), salt, N=16384, r=8, p=1)
            return f"scrypt${salt.hex()}${hash_bytes.hex()}"
    
    def verify_password(self, password, hashed):
        """Verify password against hash"""
        try:
            if self.algorithm == 'argon2id':
                return self.hasher.verify(hashed, password)
            elif self.algorithm == 'bcrypt':
                return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
            elif self.algorithm == 'scrypt':
                parts = hashed.split('$')
                salt = bytes.fromhex(parts[1])
                stored_hash = bytes.fromhex(parts[2])
                calculated_hash = scrypt.hash(password.encode('utf-8'), salt, N=16384, r=8, p=1)
                return hmac.compare_digest(stored_hash, calculated_hash)
        except:
            return False
        return False

# Usage
# Argon2id (recommended for new applications)
argon2_hasher = PasswordHashing('argon2id')
password = "my_secure_password123!"
hashed = argon2_hasher.hash_password(password)
is_valid = argon2_hasher.verify_password(password, hashed)
print(f"Argon2id hash: {hashed}")
print(f"Valid: {is_valid}")

# bcrypt (still good, widely supported)
bcrypt_hasher = PasswordHashing('bcrypt')
bcrypt_hash = bcrypt_hasher.hash_password(password)
bcrypt_valid = bcrypt_hasher.verify_password(password, bcrypt_hash)
print(f"bcrypt hash: {bcrypt_hash}")
print(f"Valid: {bcrypt_valid}")
```

### Hashing Speed Comparison

```python
import time
import hashlib

def hash_speed_test():
    """Compare hashing speeds (for educational purposes)"""
    data = "test_password" * 1000  # Larger data for better measurement
    iterations = 1000
    
    algorithms = ['md5', 'sha1', 'sha256', 'sha512', 'blake2b']
    
    print("Hash Algorithm Speed Test (lower is faster, but NOT more secure)")
    print("=" * 60)
    
    for algo_name in algorithms:
        start_time = time.time()
        
        for _ in range(iterations):
            hasher = getattr(hashlib, algo_name)()
            hasher.update(data.encode())
            hasher.hexdigest()
        
        end_time = time.time()
        total_time = end_time - start_time
        
        security_note = ""
        if algo_name in ['md5', 'sha1']:
            security_note = " ⚠️  INSECURE - DO NOT USE"
        elif algo_name in ['sha256', 'sha512']:
            security_note = " ✅ Secure for data integrity"
        elif algo_name == 'blake2b':
            security_note = " ✅ Fast and secure"
        
        print(f"{algo_name:>10}: {total_time:.4f}s{security_note}")

# Run the test
hash_speed_test()
```

## Digital Signatures

Digital signatures provide authentication, non-repudiation, and integrity.

```python
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class DigitalSignature:
    def __init__(self):
        # Generate RSA key pair
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
    
    def sign_message(self, message):
        """Sign a message with private key"""
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    def verify_signature(self, message, signature, public_key=None):
        """Verify signature with public key"""
        if public_key is None:
            public_key = self.public_key
        
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False
    
    def export_public_key(self):
        """Export public key in PEM format"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def export_private_key(self, password=None):
        """Export private key in PEM format"""
        encryption_algorithm = serialization.NoEncryption()
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
        
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )

# Usage
signer = DigitalSignature()
message = "This is an authentic message"

# Sign message
signature = signer.sign_message(message)
print(f"Message: {message}")
print(f"Signature: {signature.hex()}")

# Verify signature
is_valid = signer.verify_signature(message, signature)
print(f"Signature valid: {is_valid}")

# Test with tampered message
tampered_message = "This is a tampered message"
is_valid_tampered = signer.verify_signature(tampered_message, signature)
print(f"Tampered message valid: {is_valid_tampered}")
```

## Key Management

Proper key management is crucial for cryptographic security.

```python
import os
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class KeyManager:
    def __init__(self, master_password=None):
        self.master_password = master_password
        self.keys = {}
    
    def generate_key(self, key_name):
        """Generate and store a new encryption key"""
        key = Fernet.generate_key()
        self.keys[key_name] = key
        return key
    
    def derive_key_from_password(self, password, salt=None):
        """Derive key from password using PBKDF2"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    def save_keys(self, file_path):
        """Save encrypted keys to file"""
        if not self.master_password:
            raise ValueError("Master password required for saving keys")
        
        # Derive encryption key from master password
        master_key, salt = self.derive_key_from_password(self.master_password)
        cipher = Fernet(master_key)
        
        # Encrypt keys
        keys_data = {
            'salt': base64.b64encode(salt).decode(),
            'keys': {}
        }
        
        for name, key in self.keys.items():
            encrypted_key = cipher.encrypt(key)
            keys_data['keys'][name] = base64.b64encode(encrypted_key).decode()
        
        # Save to file
        with open(file_path, 'w') as f:
            json.dump(keys_data, f, indent=2)
    
    def load_keys(self, file_path):
        """Load encrypted keys from file"""
        if not self.master_password:
            raise ValueError("Master password required for loading keys")
        
        with open(file_path, 'r') as f:
            keys_data = json.load(f)
        
        # Derive decryption key
        salt = base64.b64decode(keys_data['salt'])
        master_key, _ = self.derive_key_from_password(self.master_password, salt)
        cipher = Fernet(master_key)
        
        # Decrypt keys
        self.keys = {}
        for name, encrypted_key_b64 in keys_data['keys'].items():
            encrypted_key = base64.b64decode(encrypted_key_b64)
            key = cipher.decrypt(encrypted_key)
            self.keys[name] = key
    
    def get_key(self, key_name):
        """Get a stored key"""
        return self.keys.get(key_name)
    
    def rotate_key(self, old_key_name, new_key_name):
        """Generate new key and mark old one for rotation"""
        new_key = self.generate_key(new_key_name)
        # In production, you'd re-encrypt all data with the new key
        return new_key

# Usage
key_manager = KeyManager(master_password="very_secure_master_password")

# Generate keys
database_key = key_manager.generate_key("database_encryption")
api_key = key_manager.generate_key("api_tokens")

# Save keys securely
key_manager.save_keys("encrypted_keys.json")

# Load keys (in another session)
new_key_manager = KeyManager(master_password="very_secure_master_password")
new_key_manager.load_keys("encrypted_keys.json")

retrieved_key = new_key_manager.get_key("database_encryption")
print(f"Keys match: {database_key == retrieved_key}")
```

## Common Mistakes

### 1. Using Encoding for Security
```python
# ❌ WRONG - Base64 is not encryption!
def encrypt_password(password):
    return base64.b64encode(password.encode()).decode()

# ✅ CORRECT - Use proper hashing
def hash_password(password):
    return argon2.PasswordHasher().hash(password)
```

### 2. Using Weak Hash Functions
```python
# ❌ WRONG - MD5 and SHA1 are broken
def weak_hash(data):
    return hashlib.md5(data.encode()).hexdigest()

# ✅ CORRECT - Use SHA-256 or better
def strong_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()
```

### 3. Rolling Your Own Crypto
```python
# ❌ WRONG - Custom "encryption"
def bad_encrypt(text, shift):
    return ''.join(chr(ord(c) + shift) for c in text)

# ✅ CORRECT - Use established libraries
def good_encrypt(text, key):
    f = Fernet(key)
    return f.encrypt(text.encode())
```

### 4. Hard-coded Keys
```python
# ❌ WRONG - Never hard-code keys
SECRET_KEY = "my_secret_key_123"

# ✅ CORRECT - Use environment variables or key management
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable not set")
```

## Practical Implementation Guide

### Quick Decision Tree

1. **Need to hide data temporarily?** → Use encoding (Base64, URL encoding)
2. **Need to protect data confidentiality?** → Use encryption (AES, Fernet)
3. **Need to verify data integrity?** → Use cryptographic hashing (SHA-256, BLAKE2)
4. **Need to store passwords?** → Use password hashing (Argon2id, bcrypt)
5. **Need authentication/non-repudiation?** → Use digital signatures (RSA, ECDSA)

### Security Checklist

- [ ] Never use encoding (Base64) for security
- [ ] Use Argon2id or bcrypt for password hashing
- [ ] Use AES-256 or Fernet for symmetric encryption
- [ ] Use RSA-2048+ or ECDSA for asymmetric crypto
- [ ] Never implement your own cryptographic algorithms
- [ ] Use cryptographically secure random number generators
- [ ] Rotate keys regularly
- [ ] Store keys securely (environment variables, key management systems)
- [ ] Use HMAC for message authentication
- [ ] Validate all cryptographic inputs
- [ ] Keep cryptographic libraries updated

## Conclusion

Understanding the differences between encoding, encryption, and hashing is crucial for building secure applications. Remember:

- **Encoding** is for data representation, not security
- **Encryption** is for protecting confidentiality
- **Hashing** is for integrity and password storage
- **Always use established cryptographic libraries**
- **Proper key management is essential**

The next chapter will cover [Passwords: dadada, 123456 and cute@123](passwords.md) - implementing secure password policies and storage.