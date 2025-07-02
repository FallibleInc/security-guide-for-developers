[Back to Contents](README.md)

# Public Key Cryptography

> [!NOTE]
> Public key cryptography solves the key distribution problem: how do two parties communicate securely without meeting in person?

Public key cryptography, also known as asymmetric cryptography, revolutionized secure communication by introducing the concept of key pairs - one public and one private. This breakthrough allows secure communication between parties who have never met and enables the entire modern internet to function securely.

## Table of Contents
- [The Key Distribution Problem](#the-key-distribution-problem)
- [How Public Key Cryptography Works](#how-public-key-cryptography-works)
- [RSA Algorithm](#rsa-algorithm)
- [Elliptic Curve Cryptography (ECC)](#elliptic-curve-cryptography-ecc)
- [Digital Signatures](#digital-signatures)
- [Key Exchange Protocols](#key-exchange-protocols)
- [Certificate Management](#certificate-management)
- [Practical Applications](#practical-applications)
- [Best Practices](#best-practices)

## The Key Distribution Problem

Before public key cryptography, secure communication required both parties to share a secret key. This created a chicken-and-egg problem: how do you securely share a key without already having a secure communication channel?

### Historical Context

**Traditional Symmetric Encryption:**
- Both parties must possess the same secret key
- Key must be shared through a secure channel
- Each pair of communicating parties needs a unique key
- Key distribution becomes exponentially complex with scale

**The Scale Problem:**
For n parties to communicate securely using symmetric encryption alone:
- Total keys needed: n(n-1)/2
- For 1000 users: 499,500 different keys needed
- Key distribution and management becomes impossible

### The Revolutionary Solution

Public key cryptography solves this by using mathematical relationships between key pairs:
- **Public Key**: Can be freely shared with anyone
- **Private Key**: Must be kept secret by the owner
- **Mathematical Relationship**: Data encrypted with one key can only be decrypted with the other

## How Public Key Cryptography Works

### The Key Pair Concept

> [!IMPORTANT]
> **Mathematical Relationship**: Public and private keys are mathematically related but computationally infeasible to derive one from the other.

Each user generates a key pair:
1. **Private Key**: A large random number kept secret
2. **Public Key**: Derived from the private key using mathematical operations
3. **One-Way Function**: Easy to compute public key from private key, but nearly impossible to reverse

### Core Operations

**Encryption:**
- Anyone can encrypt a message using the recipient's public key
- Only the recipient can decrypt it using their private key
- Ensures confidentiality

**Digital Signatures:**
- The sender signs a message using their private key
- Anyone can verify the signature using the sender's public key
- Ensures authenticity and non-repudiation

### A Simple Analogy

Think of public key cryptography like a special mailbox:
- **Public Key = Mailbox Address**: Everyone knows where to send you mail
- **Private Key = Mailbox Key**: Only you can open and read the mail
- Anyone can put mail in your box (encrypt), but only you can retrieve it (decrypt)

## RSA Algorithm

RSA (Rivest-Shamir-Adleman) was the first practical public key algorithm and remains widely used today.

### How RSA Works

**Mathematical Foundation:**
RSA relies on the difficulty of factoring large composite numbers:
- Easy to multiply two large prime numbers together
- Extremely difficult to factor the result back into the original primes
- This asymmetry provides the security

**Key Generation Process:**
1. Choose two large prime numbers (p and q)
2. Compute n = p × q (this becomes part of the public key)
3. Compute φ(n) = (p-1)(q-1)
4. Choose e (typically 65537) as the public exponent
5. Compute d, the private exponent, such that e × d ≡ 1 (mod φ(n))
6. Public key: (n, e), Private key: (n, d)

### RSA Security Considerations

**Key Size Requirements:**
- **1024-bit RSA**: Deprecated, considered insecure
- **2048-bit RSA**: Minimum acceptable strength for new applications
- **3072-bit RSA**: Recommended for high-security applications
- **4096-bit RSA**: Maximum practical size for most applications

**Performance Characteristics:**
- RSA encryption/decryption is computationally expensive
- Typically used to encrypt symmetric keys rather than large amounts of data
- Signature generation is slower than verification

## Elliptic Curve Cryptography (ECC)

ECC provides equivalent security to RSA with much smaller key sizes, making it ideal for mobile devices and IoT applications.

### Advantages of ECC

**Efficiency:**
- 256-bit ECC provides security equivalent to 3072-bit RSA
- Faster computation and lower power consumption
- Smaller key sizes mean less bandwidth and storage requirements

**Security:**
- Based on the elliptic curve discrete logarithm problem
- No known efficient quantum algorithm for this problem (unlike RSA)
- Considered more future-proof against quantum computing

### Common ECC Curves

**NIST Curves:**
- **P-256**: Most widely supported, good for general use
- **P-384**: Higher security level for sensitive applications
- **P-521**: Maximum security (note: 521 bits, not 512)

**Alternative Curves:**
- **Curve25519**: Modern, fast, and secure curve
- **Ed25519**: Optimized for digital signatures
- **secp256k1**: Used in Bitcoin and other cryptocurrencies

### When to Choose ECC vs RSA

**Choose ECC for:**
- Mobile applications with limited processing power
- IoT devices with constrained resources
- Applications requiring high performance
- New systems where you control both ends

**Choose RSA for:**
- Legacy system compatibility
- Applications with existing RSA infrastructure
- Systems requiring wide interoperability

## Digital Signatures

Digital signatures provide authentication, integrity, and non-repudiation for digital documents.

### How Digital Signatures Work

**Signing Process:**
1. Create a hash of the document to be signed
2. Encrypt the hash with the signer's private key
3. Attach the encrypted hash (signature) to the document

**Verification Process:**
1. Decrypt the signature using the signer's public key
2. Create a hash of the received document
3. Compare the decrypted hash with the computed hash
4. If they match, the signature is valid

### Digital Signature Standards

**RSA-PSS (RSA Probabilistic Signature Scheme):**
- Modern RSA signature scheme with better security properties
- Recommended over traditional PKCS#1 v1.5 signatures
- Provides provable security

**ECDSA (Elliptic Curve Digital Signature Algorithm):**
- ECC-based signature scheme
- Smaller signatures and faster verification than RSA
- Widely supported in modern applications

**EdDSA (Edwards-curve Digital Signature Algorithm):**
- Modern signature scheme using Edwards curves
- Ed25519 variant is particularly popular
- Designed to avoid common implementation pitfalls

### Legal and Practical Considerations

**Legal Validity:**
- Digital signatures have legal recognition in most countries
- Must comply with relevant regulations (eIDAS in EU, ESIGN in US)
- Different levels of assurance for different use cases

**Implementation Requirements:**
- Secure key generation and storage
- Timestamp services for long-term validity
- Certificate revocation checking
- Audit trails for signature events

## Key Exchange Protocols

Key exchange protocols allow parties to establish shared secrets over insecure channels.

### Diffie-Hellman Key Exchange

**Basic Concept:**
Two parties can establish a shared secret without ever transmitting the secret itself:
1. Both parties agree on public parameters (generator g and prime p)
2. Each party generates a private value and computes a public value
3. Parties exchange public values
4. Each party combines their private value with the other's public value
5. Both arrive at the same shared secret

**Security Properties:**
- The shared secret is never transmitted
- An eavesdropper cannot determine the secret from the exchanged public values
- Provides forward secrecy if ephemeral keys are used

### Elliptic Curve Diffie-Hellman (ECDH)

ECDH provides the same functionality as traditional Diffie-Hellman but with the efficiency benefits of elliptic curves:
- Smaller key sizes for equivalent security
- Faster computation
- Lower bandwidth requirements

### Perfect Forward Secrecy

**Concept:**
Even if an attacker later compromises a server's private key, they cannot decrypt previously recorded communications.

**Implementation:**
- Use ephemeral keys for each session
- Derive session keys from the key exchange
- Securely delete ephemeral keys after use
- TLS 1.3 mandates perfect forward secrecy

## Certificate Management

Public key infrastructure (PKI) provides the framework for managing public keys at scale.

### Public Key Infrastructure (PKI)

**Components:**
- **Certificate Authority (CA)**: Issues and manages digital certificates
- **Registration Authority (RA)**: Verifies certificate requests
- **Certificate Repository**: Stores and distributes certificates
- **Certificate Revocation Lists (CRL)**: Lists revoked certificates

**Certificate Hierarchy:**
- **Root CA**: Top-level certificate authority, self-signed
- **Intermediate CAs**: Signed by root or other intermediate CAs
- **End Entity Certificates**: Issued to users, devices, or services

### X.509 Certificates

**Certificate Contents:**
- Subject's public key
- Subject's identity information
- Issuer (CA) information
- Validity period (not before/not after dates)
- Digital signature from the issuing CA

**Certificate Validation:**
1. Check certificate chain to trusted root
2. Verify each certificate's signature
3. Check validity periods
4. Verify certificate hasn't been revoked
5. Validate certificate usage constraints

### Certificate Lifecycle Management

**Issuance:**
- Identity verification of certificate requester
- Key pair generation (preferably by the end entity)
- Certificate signing by the CA
- Secure delivery of the certificate

**Renewal:**
- Periodic renewal before expiration
- Automated renewal systems (like ACME protocol)
- Key rotation considerations

**Revocation:**
- Immediate revocation for compromised keys
- Certificate Revocation Lists (CRLs)
- Online Certificate Status Protocol (OCSP)
- Certificate Transparency logs

## Practical Applications

### TLS/SSL Encryption

**Handshake Process:**
1. Client requests server's certificate
2. Client verifies certificate validity
3. Client and server perform key exchange
4. Symmetric session keys are derived
5. All further communication uses symmetric encryption

**Certificate Validation:**
- Hostname verification against certificate
- Certificate chain validation to trusted root
- Revocation status checking
- Certificate transparency verification

### Code Signing

**Purpose:**
- Verify software authenticity
- Ensure software hasn't been tampered with
- Enable trust decisions based on publisher identity

**Implementation:**
- Developers sign their code with private keys
- Operating systems verify signatures before execution
- Code signing certificates from trusted CAs
- Timestamping for long-term validity

### Email Security (S/MIME and PGP)

**S/MIME (Secure/Multipurpose Internet Mail Extensions):**
- Uses X.509 certificates for email security
- Integrated with enterprise email systems
- Centralized certificate management

**PGP (Pretty Good Privacy):**
- Decentralized web of trust model
- User-controlled key management
- Popular among privacy advocates

### Blockchain and Cryptocurrencies

**Digital Signatures in Blockchain:**
- Transaction authorization using private keys
- Public keys serve as addresses or account identifiers
- Consensus mechanisms often rely on cryptographic proofs

## Best Practices

### Key Generation

**Entropy Requirements:**
- Use cryptographically secure random number generators
- Ensure sufficient entropy for key generation
- Avoid predictable or weak random number sources
- Consider hardware random number generators for high-security applications

**Key Size Selection:**
- Follow current cryptographic recommendations
- Plan for algorithm lifetimes and security margins
- Consider performance requirements and constraints
- Regularly review and update key size requirements

### Key Storage and Protection

**Private Key Security:**
- Store private keys in secure, encrypted storage
- Use hardware security modules (HSMs) for high-value keys
- Implement access controls and audit logging
- Regular backup and recovery procedures

**Key Escrow Considerations:**
- Legal and regulatory requirements
- Business continuity planning
- Risk of key compromise through escrow
- Alternative approaches like secret sharing

### Implementation Security

**Library Selection:**
- Use well-established, peer-reviewed cryptographic libraries
- Avoid implementing cryptographic algorithms yourself
- Keep libraries updated with security patches
- Understand library limitations and proper usage

**Side-Channel Attack Prevention:**
- Constant-time implementations
- Protection against timing attacks
- Power analysis resistance
- Fault injection countermeasures

### Operational Security

**Certificate Management:**
- Automate certificate renewal where possible
- Monitor certificate expiration dates
- Implement proper certificate validation
- Maintain certificate transparency monitoring

**Key Rotation:**
- Regular key rotation schedules
- Emergency key rotation procedures
- Coordination across distributed systems
- Planning for cryptographic algorithm transitions

## Common Pitfalls and How to Avoid Them

### Implementation Mistakes

**Weak Random Number Generation:**
Many implementations fail because of poor randomness. Always use cryptographically secure random number generators provided by your platform or security library.

**Improper Certificate Validation:**
Skipping hostname verification or certificate chain validation creates serious vulnerabilities. Always implement complete certificate validation.

**Key Reuse:**
Using the same key pair for multiple purposes (encryption and signing) can create security vulnerabilities. Use separate key pairs for different purposes.

### Operational Mistakes

**Poor Key Management:**
Storing private keys in plaintext, version control systems, or unsecured locations is a common cause of breaches.

**Ignoring Certificate Expiration:**
Expired certificates can cause service outages and security warnings. Implement monitoring and automated renewal.

**Insufficient Planning for Compromise:**
Have procedures ready for key compromise, including revocation, re-issuance, and communication plans.

## Future Considerations

### Post-Quantum Cryptography

**The Quantum Threat:**
Sufficiently powerful quantum computers could break both RSA and ECC using Shor's algorithm. The cryptographic community is developing quantum-resistant algorithms.

**NIST Post-Quantum Standards:**
- **CRYSTALS-Kyber**: Key encapsulation mechanism
- **CRYSTALS-Dilithium**: Digital signature algorithm
- **FALCON**: Alternative signature algorithm
- **SPHINCS+**: Hash-based signature scheme

**Migration Planning:**
- Assess current cryptographic usage
- Plan for hybrid implementations during transition
- Consider algorithm agility in system design
- Monitor NIST standardization progress

### Cryptographic Agility

**Design Principles:**
- Avoid hard-coding cryptographic algorithms
- Use configuration-driven cryptographic selection
- Implement version negotiation mechanisms
- Plan for algorithm deprecation and replacement

## Conclusion

Public key cryptography is fundamental to modern digital security, enabling secure communication, authentication, and trust establishment across the internet. Understanding its principles, proper implementation, and operational considerations is essential for building secure systems.

**Key Takeaways:**
- Public key cryptography solves the key distribution problem through mathematical relationships
- RSA and ECC are the dominant algorithms, each with specific use cases
- Digital signatures provide authentication, integrity, and non-repudiation
- PKI provides the infrastructure for managing public keys at scale
- Proper implementation requires attention to key generation, storage, and validation
- Future systems must consider post-quantum cryptography migration

Remember: Cryptography is only as strong as its weakest link. Focus on proper implementation, key management, and operational security to realize the full benefits of public key cryptography.

---

*"Cryptography is the ultimate form of non-violent direct action."* - Julian Assange

Use public key cryptography to build systems that protect privacy and enable secure communication in our digital world.