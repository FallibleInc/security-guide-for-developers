[Back to Contents](README.md)

# Public Key Cryptography

> [!NOTE]
> Public key cryptography solves the key distribution problem: how do two parties communicate securely without meeting in person?

Public key cryptography, also known as asymmetric cryptography, is a revolutionary approach to secure communication that uses pairs of keys - one public and one private. This chapter explains how public key systems work, their applications, and implementation best practices.

## Table of Contents
- [How Public Key Cryptography Works](#how-public-key-cryptography-works)
- [RSA Algorithm](#rsa-algorithm)
- [Elliptic Curve Cryptography (ECC)](#elliptic-curve-cryptography-ecc)
- [Digital Signatures](#digital-signatures)
- [Key Exchange Protocols](#key-exchange-protocols)
- [Certificate Management](#certificate-management)
- [Implementation Examples](#implementation-examples)
- [Best Practices](#best-practices)

## How Public Key Cryptography Works

### The Key Pair Concept

> [!IMPORTANT]
> **Mathematical Relationship**: Public and private keys are mathematically related but computationally infeasible to derive one from the other.

```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import base64

class PublicKeyCryptography:
    """Demonstrates public key cryptography concepts"""
    
    def __init__(self):
        # Generate a key pair
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
    
    def encrypt_with_public_key(self, message: str) -> str:
        """Encrypt data with public key (anyone can do this)"""
        message_bytes = message.encode('utf-8')
        
        ciphertext = self.public_key.encrypt(
            message_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return base64.b64encode(ciphertext).decode('utf-8')
    
    def decrypt_with_private_key(self, encrypted_message: str) -> str:
        """Decrypt data with private key (only key owner can do this)"""
        ciphertext = base64.b64decode(encrypted_message)
        
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return plaintext.decode('utf-8')
    
    def export_public_key(self) -> str:
        """Export public key in PEM format"""
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')

# Example usage
crypto = PublicKeyCryptography()

# Alice wants to send a secure message to Bob
message = "Meet me at the secret location at midnight"
encrypted = crypto.encrypt_with_public_key(message)
decrypted = crypto.decrypt_with_private_key(encrypted)

print(f"Original: {message}")
print(f"Encrypted: {encrypted[:50]}...")
print(f"Decrypted: {decrypted}")
```

### Key Properties

| Property | Description | Benefit |
|----------|-------------|---------|
| **Asymmetric** | Different keys for encryption/decryption | No shared secret needed |
| **Non-repudiation** | Private key signatures prove identity | Legal accountability |
| **Key Distribution** | Public keys can be shared openly | Scalable communication |
| **Forward Secrecy** | Session keys don't compromise long-term keys | Limits breach impact |

## RSA Algorithm

### RSA Key Generation

```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

class RSAKeyManager:
    """RSA key generation and management"""
    
    @staticmethod
    def generate_rsa_key_pair(key_size=2048):
        """Generate RSA key pair with recommended parameters"""
        
        # Key sizes and security levels (2025)
        key_security_levels = {
            2048: "Minimum acceptable (until 2030)",
            3072: "Recommended for new systems",
            4096: "High security applications"
        }
        
        if key_size < 2048:
            raise ValueError("RSA keys smaller than 2048 bits are insecure")
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,  # Standard exponent
            key_size=key_size
        )
        
        return private_key, private_key.public_key()
    
    @staticmethod
    def save_key_pair(private_key, public_key, password=None):
        """Save key pair to files securely"""
        
        # Encrypt private key if password provided
        encryption_algorithm = serialization.NoEncryption()
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(
                password.encode('utf-8')
            )
        
        # Save private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        
        with open('private_key.pem', 'wb') as f:
            f.write(private_pem)
        
        # Set restrictive permissions on private key
        os.chmod('private_key.pem', 0o600)
        
        # Save public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open('public_key.pem', 'wb') as f:
            f.write(public_pem)
        
        return private_pem, public_pem

# Generate and save key pair
private_key, public_key = RSAKeyManager.generate_rsa_key_pair(3072)
RSAKeyManager.save_key_pair(private_key, public_key, password="secure_password")
```

### RSA Security Considerations

> [!WARNING]
> **RSA Key Size Requirements**: 2048-bit keys are minimum for 2025. Use 3072-bit for new systems.

| Key Size | Security Level | Recommended Until | Notes |
|----------|---------------|-------------------|-------|
| 1024-bit | **BROKEN** | Never use | Factored in 2020 |
| 2048-bit | Minimum | 2030 | Legacy systems only |
| 3072-bit | Recommended | 2040+ | New deployments |
| 4096-bit | High Security | 2050+ | Government/Military |

## Elliptic Curve Cryptography (ECC)

### ECC Advantages

> [!NOTE]
> **ECC Efficiency**: Provides equivalent security to RSA with much smaller key sizes, making it ideal for mobile and IoT devices.

```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import os

class ECCManager:
    """Elliptic Curve Cryptography implementation"""
    
    # Recommended curves (2025)
    SECURE_CURVES = {
        'P-256': ec.SECP256R1(),     # 128-bit security
        'P-384': ec.SECP384R1(),     # 192-bit security  
        'P-521': ec.SECP521R1(),     # 256-bit security
        'X25519': None,              # Modern curve (Key exchange only)
        'Ed25519': None              # Modern curve (Signatures only)
    }
    
    def __init__(self, curve_name='P-256'):
        if curve_name not in self.SECURE_CURVES:
            raise ValueError(f"Unsupported curve: {curve_name}")
        
        self.curve = self.SECURE_CURVES[curve_name]
        self.private_key = ec.generate_private_key(self.curve)
        self.public_key = self.private_key.public_key()
    
    def generate_shared_secret(self, peer_public_key):
        """Perform ECDH key exchange"""
        shared_key = self.private_key.exchange(
            ec.ECDH(), 
            peer_public_key
        )
        return shared_key
    
    def sign_message(self, message: str) -> bytes:
        """Create digital signature"""
        message_bytes = message.encode('utf-8')
        signature = self.private_key.sign(
            message_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        return signature
    
    def verify_signature(self, message: str, signature: bytes) -> bool:
        """Verify digital signature"""
        try:
            message_bytes = message.encode('utf-8')
            self.public_key.verify(
                signature,
                message_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except:
            return False

# Example: Key exchange between Alice and Bob
alice = ECCManager('P-256')
bob = ECCManager('P-256')

# Exchange public keys
alice_shared = alice.generate_shared_secret(bob.public_key)
bob_shared = bob.generate_shared_secret(alice.public_key)

# Both parties now have the same shared secret
assert alice_shared == bob_shared
print("Key exchange successful!")
```

### ECC vs RSA Comparison

| Security Level | ECC Key Size | RSA Key Size | Performance |
|---------------|--------------|--------------|-------------|
| 128-bit | 256-bit | 2048-bit | ECC 10x faster |
| 192-bit | 384-bit | 7680-bit | ECC 20x faster |
| 256-bit | 521-bit | 15360-bit | ECC 40x faster |

## Digital Signatures

### How Digital Signatures Work

> [!IMPORTANT]
> **Non-repudiation**: Digital signatures prove that a message was created by someone who possesses the private key.

```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import base64
import json
from datetime import datetime

class DigitalSignature:
    """Digital signature implementation"""
    
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072
        )
        self.public_key = self.private_key.public_key()
    
    def sign_document(self, document: dict) -> dict:
        """Sign a document with timestamp and signature"""
        
        # Add timestamp
        document['timestamp'] = datetime.now().isoformat()
        document['signer'] = 'Alice'
        
        # Create canonical representation
        document_json = json.dumps(document, sort_keys=True)
        document_bytes = document_json.encode('utf-8')
        
        # Create signature
        signature = self.private_key.sign(
            document_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Add signature to document
        signed_document = document.copy()
        signed_document['signature'] = base64.b64encode(signature).decode('utf-8')
        
        return signed_document
    
    def verify_document(self, signed_document: dict) -> bool:
        """Verify document signature"""
        try:
            # Extract signature
            signature_b64 = signed_document.pop('signature')
            signature = base64.b64decode(signature_b64)
            
            # Recreate document for verification
            document_json = json.dumps(signed_document, sort_keys=True)
            document_bytes = document_json.encode('utf-8')
            
            # Verify signature
            self.public_key.verify(
                signature,
                document_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return True
            
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False

# Example: Sign and verify a contract
signer = DigitalSignature()

contract = {
    "parties": ["Alice Corp", "Bob Inc"],
    "amount": 50000,
    "currency": "USD",
    "terms": "Net 30 payment terms"
}

# Sign the contract
signed_contract = signer.sign_document(contract)
print("Contract signed successfully!")

# Verify the signature
is_valid = signer.verify_document(signed_contract.copy())
print(f"Signature valid: {is_valid}")

# Tampering detection
signed_contract['amount'] = 500000  # Tamper with amount
is_valid_after_tampering = signer.verify_document(signed_contract.copy())
print(f"Signature valid after tampering: {is_valid_after_tampering}")
```

## Key Exchange Protocols

### Diffie-Hellman Key Exchange

```python
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os

class DHKeyExchange:
    """Diffie-Hellman key exchange implementation"""
    
    def __init__(self):
        # Generate parameters (in practice, use well-known parameters)
        self.parameters = dh.generate_parameters(generator=2, key_size=2048)
        
        # Generate private key
        self.private_key = self.parameters.generate_private_key()
        self.public_key = self.private_key.public_key()
    
    def get_public_key_bytes(self):
        """Get public key for sharing"""
        from cryptography.hazmat.primitives import serialization
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def derive_shared_key(self, peer_public_key, salt=None):
        """Derive shared encryption key"""
        if salt is None:
            salt = os.urandom(16)
        
        # Perform key exchange
        shared_key = self.private_key.exchange(peer_public_key)
        
        # Derive proper encryption key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'secure-chat-app',
        ).derive(shared_key)
        
        return derived_key, salt

# Example: Secure chat application key exchange
class SecureChat:
    """Secure chat using DH key exchange"""
    
    def __init__(self, username):
        self.username = username
        self.dh = DHKeyExchange()
        self.shared_key = None
    
    def initiate_key_exchange(self, peer_public_key):
        """Complete key exchange with peer"""
        self.shared_key, self.salt = self.dh.derive_shared_key(peer_public_key)
        return self.dh.get_public_key_bytes(), self.salt
    
    def encrypt_message(self, message):
        """Encrypt message with shared key"""
        if not self.shared_key:
            raise ValueError("Key exchange not completed")
        
        from cryptography.fernet import Fernet
        import base64
        
        # Use first 32 bytes as Fernet key (base64 encoded)
        fernet_key = base64.urlsafe_b64encode(self.shared_key)
        f = Fernet(fernet_key)
        
        return f.encrypt(message.encode('utf-8'))
    
    def decrypt_message(self, encrypted_message):
        """Decrypt message with shared key"""
        if not self.shared_key:
            raise ValueError("Key exchange not completed")
        
        from cryptography.fernet import Fernet
        import base64
        
        fernet_key = base64.urlsafe_b64encode(self.shared_key)
        f = Fernet(fernet_key)
        
        return f.decrypt(encrypted_message).decode('utf-8')

# Example usage
alice = SecureChat("Alice")
bob = SecureChat("Bob")

# Alice initiates key exchange
alice_public, salt = alice.initiate_key_exchange(bob.dh.public_key)
bob_public, _ = bob.initiate_key_exchange(alice.dh.public_key)

# Now both have the same shared key
message = "Hello Bob, this is a secret message!"
encrypted = alice.encrypt_message(message)
decrypted = bob.decrypt_message(encrypted)

print(f"Original: {message}")
print(f"Decrypted: {decrypted}")
```

## Best Practices

### Key Management

> [!WARNING]
> **Private Key Security**: Private keys are the crown jewels of your security. Compromise = total system compromise.

```python
import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

class SecureKeyManager:
    """Secure key management practices"""
    
    def __init__(self):
        self.key_directory = Path("~/.secure_keys").expanduser()
        self.key_directory.mkdir(mode=0o700, exist_ok=True)
    
    def generate_and_store_key(self, key_name, password):
        """Generate and securely store a private key"""
        
        # Generate key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072
        )
        
        # Encrypt private key
        encrypted_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                password.encode('utf-8')
            )
        )
        
        # Save with secure permissions
        private_key_path = self.key_directory / f"{key_name}_private.pem"
        with open(private_key_path, 'wb') as f:
            f.write(encrypted_private)
        
        # Set restrictive permissions (owner read/write only)
        os.chmod(private_key_path, 0o600)
        
        # Save public key
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        public_key_path = self.key_directory / f"{key_name}_public.pem"
        with open(public_key_path, 'wb') as f:
            f.write(public_pem)
        
        return private_key_path, public_key_path
    
    def load_private_key(self, key_path, password):
        """Load and decrypt private key"""
        with open(key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=password.encode('utf-8')
            )
        return private_key

# Security checklist for public key cryptography
PUBLIC_KEY_SECURITY_CHECKLIST = [
    "✓ Use minimum 2048-bit RSA keys (3072-bit recommended)",
    "✓ Encrypt private keys with strong passphrases",
    "✓ Set restrictive file permissions (600) on private keys",
    "✓ Use hardware security modules (HSMs) for high-value keys",
    "✓ Implement key rotation policies",
    "✓ Use secure random number generation",
    "✓ Validate all public keys before use",
    "✓ Implement certificate pinning for known services",
    "✓ Use established cryptographic libraries",
    "✓ Regularly audit key usage and access"
]

for item in PUBLIC_KEY_SECURITY_CHECKLIST:
    print(item)
```

### Performance Optimization

```python
import time
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def benchmark_algorithms():
    """Compare performance of different algorithms"""
    
    # Test data
    message = b"This is a test message for performance benchmarking"
    
    algorithms = {
        'RSA-2048': rsa.generate_private_key(65537, 2048),
        'RSA-3072': rsa.generate_private_key(65537, 3072),
        'ECC-P256': ec.generate_private_key(ec.SECP256R1()),
        'ECC-P384': ec.generate_private_key(ec.SECP384R1()),
    }
    
    results = {}
    
    for name, private_key in algorithms.items():
        # Time key generation (already done above, but for comparison)
        start = time.time()
        
        if isinstance(private_key, rsa.RSAPrivateKey):
            # RSA signing
            signature = private_key.sign(
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # RSA verification
            public_key = private_key.public_key()
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        else:
            # ECC signing
            signature = private_key.sign(
                message,
                ec.ECDSA(hashes.SHA256())
            )
            
            # ECC verification
            public_key = private_key.public_key()
            public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
        
        end = time.time()
        results[name] = end - start
    
    return results

# Uncomment to run benchmark
# results = benchmark_algorithms()
# for alg, time_taken in results.items():
#     print(f"{alg}: {time_taken:.4f} seconds")
```

## Summary

> [!NOTE]
> **Key Takeaways**: 
> - Use ECC for new systems (better performance)
> - RSA 3072-bit minimum for new deployments
> - Always encrypt private keys
> - Implement proper key rotation
> - Use established cryptographic libraries

Public key cryptography enables secure communication without prior key exchange, making it fundamental to modern internet security. Choose the right algorithm and key size for your security requirements and performance constraints.