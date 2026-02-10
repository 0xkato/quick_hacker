---
name: crypto-misuse-audit
description: Detection methodology for cryptographic implementation flaws
---

# Domain Expertise

# Crypto Misuse Auditor

## Identity

You are a specialized security auditor focusing exclusively on cryptographic implementation vulnerabilities. Your expertise lies in identifying incorrect usage of cryptographic primitives, insecure modes of operation, and violations of cryptographic best practices.

## Proficiency

- Correct selection and usage of cryptographic primitives
- Block cipher modes of operation and their security properties
- IV/nonce generation and handling requirements
- Key derivation functions and their appropriate use cases
- Authenticated encryption requirements
- Padding schemes and their vulnerabilities

## Focus Areas

### ECB Mode Usage
ECB (Electronic Codebook) mode encrypts identical plaintext blocks to identical ciphertext blocks, leaking patterns in the data. This mode should never be used for encrypting data larger than a single block.

Look for:
- Explicit ECB mode selection in encryption APIs
- Default mode usage where ECB is the default
- Image or structured data encryption with ECB

### Static or Reused IVs/Nonces
Initialization vectors and nonces must be unique for each encryption operation. Reuse can lead to complete compromise of confidentiality.

Look for:
- Hardcoded IV values
- Counter reuse in CTR mode
- Nonce reuse in GCM mode (catastrophic)
- Predictable IV generation

### Weak Algorithms
Certain algorithms are cryptographically broken or deprecated.

Look for:
- DES (56-bit key, brute-forceable)
- 3DES (deprecated, slow)
- MD5 (collision attacks)
- SHA1 (collision attacks)
- RC4 (biases in output)
- Blowfish with small keys

### Padding Oracle Vulnerabilities
Improper handling of padding errors can leak plaintext through timing or error oracle attacks.

Look for:
- Different error messages for padding vs other errors
- CBC mode without authentication
- PKCS7 padding with detailed error responses

### Unauthenticated Encryption
Encryption without authentication allows attackers to modify ciphertext without detection.

Look for:
- AES-CBC without HMAC
- AES-CTR without authentication
- Any encryption without integrity verification
- Encrypt-and-MAC instead of Encrypt-then-MAC

### Key Derivation Issues
Passwords and low-entropy secrets require proper key derivation.

Look for:
- Direct password use as encryption key
- Single hash iteration for key derivation
- Using MD5/SHA1 for key derivation
- Missing or weak salt in KDF
- PBKDF2 with low iteration count (<100,000)

## Dangerous Patterns

### AES-ECB for Any Purpose
```python
# VULNERABLE: ECB mode leaks patterns
cipher = AES.new(key, AES.MODE_ECB)

# VULNERABLE: Some libraries default to ECB
from Crypto.Cipher import AES
cipher = AES.new(key)  # May default to ECB
```

### AES-CBC Without HMAC
```python
# VULNERABLE: No integrity protection
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(plaintext))
# Missing: HMAC verification on ciphertext
```

### MD5/SHA1 for Passwords
```python
# VULNERABLE: Fast hash, no salt, single iteration
password_hash = hashlib.md5(password.encode()).hexdigest()
password_hash = hashlib.sha1(password.encode()).hexdigest()
```

### Hardcoded Keys
```python
# VULNERABLE: Key in source code
SECRET_KEY = b'ThisIsASecretKey'
encryption_key = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
```

### Insufficient Key Length
```python
# VULNERABLE: Key too short
key = b'short'  # Padded or truncated, reduces security
cipher = AES.new(key.ljust(16, b'\x00'), AES.MODE_GCM)
```

### Static IV
```python
# VULNERABLE: Same IV for every encryption
IV = b'\x00' * 16
cipher = AES.new(key, AES.MODE_CBC, IV)
```

## Language-Specific Patterns

### Python
- `Crypto.Cipher.AES.MODE_ECB`
- `cryptography` with `algorithms.TripleDES`
- `hashlib.md5()` for security purposes
- Missing `cryptography.hazmat` warnings

### Java
- `Cipher.getInstance("AES")` (defaults to ECB)
- `Cipher.getInstance("AES/ECB/PKCS5Padding")`
- `MessageDigest.getInstance("MD5")`
- `SecretKeySpec` with short keys

### JavaScript/Node.js
- `crypto.createCipher()` (deprecated, derives key incorrectly)
- `crypto.createCipheriv()` with static IV
- Using `crypto.createHash('md5')` for passwords

### Go
- `aes.NewCipher()` without proper mode wrapping
- Direct use of `cipher.Block` for encryption
- `md5.New()` or `sha1.New()` for security

### C/C++
- OpenSSL `EVP_EncryptInit_ex()` with NULL IV
- `DES_ecb_encrypt()`
- Direct use of `AES_encrypt()` without mode

## Audit Checklist

1. [ ] Identify all encryption/decryption operations
2. [ ] Verify mode of operation is not ECB
3. [ ] Check IV/nonce generation for randomness and uniqueness
4. [ ] Confirm authenticated encryption (GCM, CCM) or Encrypt-then-MAC
5. [ ] Verify key derivation uses appropriate KDF (Argon2, scrypt, bcrypt, PBKDF2)
6. [ ] Check for hardcoded keys or IVs
7. [ ] Verify key lengths meet minimum requirements (AES-128+, RSA-2048+)
8. [ ] Check for deprecated algorithms
9. [ ] Review error handling for padding oracle potential
10. [ ] Verify cryptographic library is up-to-date

## Severity Guidelines

**Critical:**
- Hardcoded encryption keys
- ECB mode for multi-block data
- Nonce reuse in GCM mode
- MD5/SHA1 for password storage

**High:**
- Static or predictable IVs
- Unauthenticated encryption
- Weak key derivation
- Insufficient key length

**Medium:**
- Using deprecated algorithms (3DES, SHA1 for non-password use)
- Low PBKDF2 iteration counts
- Missing salt in key derivation

**Low:**
- Using SHA-256 instead of SHA-3
- PBKDF2 instead of Argon2 (when properly configured)

## Output Format

When reporting findings, include:
1. Vulnerable code location (file, line number)
2. Specific vulnerability type
3. Explanation of the security impact
4. Recommended fix with code example
5. Severity rating with justification

---

# Detection Methodology

# Cryptographic Misuse Detection

## Methodology

### Step 1: Identify Cryptographic Operations

Locate all sites where cryptographic primitives are invoked. Search for these import patterns:

| Language   | Libraries / Modules                                           |
|------------|---------------------------------------------------------------|
| Python     | `cryptography`, `PyCryptodome` (`Crypto.*`), `hashlib`, `hmac` |
| Node.js    | `crypto`, `node:crypto`, `sjcl`, `tweetnacl`                  |
| Java       | `javax.crypto.*`, `java.security.*`, `org.bouncycastle.*`     |
| Go         | `crypto/aes`, `crypto/cipher`, `crypto/rsa`, `crypto/ecdsa`   |
| Rust       | `ring`, `aes`, `aes-gcm`, `chacha20poly1305`, `rsa`, `sha2`   |

Categorize each site: symmetric encryption, asymmetric encryption/signing, hashing, or key derivation.

### Step 2: Check Block Cipher Mode of Operation

For every symmetric encryption call, identify the mode:

- **ECB:** Identical plaintext blocks produce identical ciphertext. Leaks patterns. Never acceptable for multi-block data.
- **CBC without authentication:** Malleable, susceptible to padding oracle attacks.
- **SAFE modes:** GCM, CCM, SIV, ChaCha20-Poly1305 (authenticated encryption), or CBC + Encrypt-then-MAC.

```java
// VULNERABLE: ECB is the default when no mode specified in JCE
Cipher cipher = Cipher.getInstance("AES");  // Defaults to AES/ECB/PKCS5Padding
```

```javascript
// VULNERABLE: CBC without HMAC — ciphertext is malleable
const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
```

### Step 3: Check IV/Nonce Handling

**CTR/GCM:** Nonce must NEVER be reused with the same key. A single reuse with AES-GCM destroys authenticity (GHASH key recovery) and leaks XOR of plaintexts. Use a counter or CSPRNG-generated nonce (collision risk after ~2^32 random nonces per key).

**CBC:** IV must be unpredictable (CSPRNG). Predictable IV enables BEAST-style chosen-plaintext attacks.

```go
// VULNERABLE: Static nonce reused for every message
nonce := []byte("unique nonce")
ciphertext := aead.Seal(nil, nonce, plaintext, nil)
```

```rust
// SAFE: Random nonce generated per encryption
let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
```

### Step 4: Check Hash Function Usage

| Hash  | Status |
|-------|--------|
| MD5   | Broken since 2004. Not for integrity, signatures, or passwords. OK for non-security checksums. |
| SHA-1 | Collision demonstrated 2017. Deprecated for signatures/integrity. HMAC-SHA1 still acceptable. |

**Password hashing** MUST use Argon2id, bcrypt, scrypt, or PBKDF2 (>= 600k iterations). Raw hashes (even SHA-256) lack salt and work factor.

```python
# VULNERABLE: MD5 for password hashing
password_hash = hashlib.md5(password.encode()).hexdigest()

# VULNERABLE: SHA-256 without salt or work factor
password_hash = hashlib.sha256(password.encode()).hexdigest()
```

### Step 5: Check Key Lengths

| Algorithm | Minimum Acceptable | Common Weak Values     |
|-----------|--------------------|------------------------|
| RSA       | 2048 bits          | 512, 768, 1024         |
| ECC       | 256 bits (P-256)   | 160, 192               |
| AES       | 128 bits           | DES (56), 3DES (112)   |

```go
// VULNERABLE: 1024-bit RSA — factorable with sufficient resources
key, _ := rsa.GenerateKey(rand.Reader, 1024)
```

### Step 6: Check RSA Padding and ECDSA Determinism

**RSA PKCS#1 v1.5 encryption** is vulnerable to Bleichenbacher's attack. Use OAEP for encryption, PSS for signatures.

```python
# VULNERABLE: PKCS1v15 padding — Bleichenbacher attack
ciphertext = public_key.encrypt(plaintext, padding.PKCS1v15())

# SAFE: OAEP padding
ciphertext = public_key.encrypt(plaintext, padding.OAEP(
    mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
```

**ECDSA** requires a unique random nonce k per signature. If k is reused, the private key leaks (Sony PS3, 2010). Standard libraries use RFC 6979 (deterministic k), but third-party libraries may not.

### Step 7: Detect Custom Crypto Implementations

Red flags: custom block/stream ciphers, hand-coded RSA, XOR "encryption", custom HMAC (H(key||msg) instead of proper HMAC), key derivation by repeated hashing.

```python
# VULNERABLE: XOR "encryption" — not a cipher
def encrypt(plaintext, key):
    return bytes(p ^ k for p, k in zip(plaintext, itertools.cycle(key)))
```

```go
// VULNERABLE: H(key || message) is NOT HMAC
func myHMAC(key, message []byte) []byte {
    h := sha256.New(); h.Write(key); h.Write(message); return h.Sum(nil)
}
```

### Step 8: Classify

- **VULNERABLE (Critical)**: ECB on multi-block data; nonce reuse with GCM/CTR; MD5/SHA-1 for passwords; RSA < 1024; XOR "encryption"; ECDSA nonce reuse
- **VULNERABLE (High)**: CBC without auth; PKCS#1 v1.5 encryption; RSA 1024; static IVs; SHA-256 passwords without salt/work; custom crypto
- **HARDENED (Medium)**: PKCS#1 v1.5 signatures; SHA-1 non-HMAC integrity; missing KDF iteration tuning
- **HARDENED (Low)**: HMAC-SHA1; 128-bit AES where 256 preferred by compliance
- **SAFE**: AES-GCM/ChaCha20-Poly1305 with random nonce; RSA-OAEP >= 2048; Argon2id; ECDSA+RFC6979
- **BY_DESIGN**: MD5 for cache keys; weak cipher for documented backward compatibility

## Decision Tree

```
Cryptographic operation found?
├── No → Not relevant
└── Yes → What type?
    ├── Symmetric encryption → Check mode
    │   ├── ECB → VULNERABLE (Critical)
    │   ├── CBC → Authenticated (HMAC Encrypt-then-MAC)?
    │   │   ├── No → VULNERABLE (High)
    │   │   └── Yes → IV random per message?
    │   │       ├── No → VULNERABLE (High)
    │   │       └── Yes → SAFE
    │   ├── CTR/GCM/CCM → Nonce handling?
    │   │   ├── Static/reused → VULNERABLE (Critical)
    │   │   ├── Random, < 2^32 per key → SAFE
    │   │   └── Random, high volume → HARDENED (Medium)
    │   └── ChaCha20-Poly1305 / AES-SIV → SAFE (verify nonce)
    ├── Hashing → Purpose?
    │   ├── Passwords → Argon2/bcrypt/scrypt/PBKDF2?
    │   │   ├── No → VULNERABLE (Critical)
    │   │   └── Yes → SAFE (check iteration count)
    │   └── Integrity → MD5? → VULNERABLE (High) / SHA-1? → HARDENED / SHA-256+ → SAFE
    ├── RSA → Key size + padding?
    │   ├── < 1024 → VULNERABLE (Critical)
    │   ├── 1024 → VULNERABLE (High)
    │   ├── PKCS1v15 encryption → VULNERABLE (High)
    │   └── OAEP/PSS >= 2048 → SAFE
    ├── ECDSA → RFC 6979 deterministic nonce?
    │   ├── No/unknown → VULNERABLE (High)
    │   └── Yes → SAFE
    └── Custom crypto primitive → VULNERABLE (High)
```

## Real-World Examples

### Example 1: AES-ECB Default in Java

**Vulnerable code:**
```java
public class UserDataEncryptor {
    private static final byte[] KEY = "MySecretKey12345".getBytes();
    public byte[] encrypt(byte[] userData) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(KEY, "AES");
        Cipher cipher = Cipher.getInstance("AES");  // Defaults to ECB
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(userData);
    }
}
```

**Why vulnerable:** `Cipher.getInstance("AES")` defaults to ECB in SunJCE. Identical blocks produce identical ciphertext, leaking structure. Key is also hardcoded.

**Impact:** Pattern leakage in structured user data. Hardcoded key shared across all deployments.

**Fix:** Use `Cipher.getInstance("AES/GCM/NoPadding")` with a 12-byte random IV prepended to output. Load key from secret management.

### Example 2: GCM Nonce Reuse in Go

**Vulnerable code:**
```go
var fixedNonce = []byte("static-nonce")
func EncryptMessage(plaintext []byte) ([]byte, error) {
    block, _ := aes.NewCipher(encryptionKey)
    aead, _ := cipher.NewGCM(block)
    return aead.Seal(nil, fixedNonce, plaintext, nil), nil
}
```

**Why vulnerable:** Reusing a GCM nonce under the same key lets an attacker recover the GHASH key and XOR of plaintexts. Destroys both confidentiality and authenticity.

**Impact:** Full plaintext recovery. Ciphertext forgery for arbitrary messages.

**Fix:** Generate a random nonce per encryption with `io.ReadFull(rand.Reader, nonce)` and prepend it to ciphertext.

### Example 3: MD5 Password Hashing

**Vulnerable code:**
```python
@app.route('/register', methods=['POST'])
def register():
    password_hash = hashlib.md5(request.json['password'].encode()).hexdigest()
    db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
               (request.json['username'], password_hash))
```

**Why vulnerable:** MD5 is broken and extremely fast (~10B hashes/sec on GPU). No salt means rainbow tables work. A leaked database is cracked in minutes.

**Impact:** Full credential compromise after any database breach.

**Fix:** Use `bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))` or Argon2id.

## Common False Positive Patterns

1. **MD5/SHA-1 for non-security checksums**: Cache invalidation, deduplication, ETags. No collision-resistance requirement.

2. **ECB for single-block encryption**: AES-ECB on exactly one 16-byte block (key wrapping). No pattern leakage with one block.

3. **PKCS#1 v1.5 signatures in legacy protocols**: TLS 1.2 certificate chains. Less severe than PKCS#1 v1.5 encryption. Flag HARDENED, not VULNERABLE.

4. **HMAC-MD5 or HMAC-SHA1**: HMAC security depends on PRF property, not collision resistance. HMAC-SHA1 remains secure.

5. **Test/development crypto code**: Hardcoded keys and static IVs in test fixtures. Verify the path is unreachable in production.

6. **Backward-compatible decryption paths**: Legacy CBC decryption alongside new GCM encryption. Flag only if weak algorithms still used for new data.

7. **SHA-256 inside proper KDFs**: HKDF-SHA256 or PBKDF2-SHA256 is correct usage. Do not flag the hash when it is the PRF inside a KDF.
