# Weak Randomness Detection

## Methodology

### Step 1: Identify Security-Sensitive Random Value Generation

Search for all locations where random values are generated for security-critical purposes:

**Authentication and session material:**
- Session IDs, CSRF tokens, password reset tokens, email verification tokens
- API keys, OAuth nonces, JWT signing secrets
- "Remember me" tokens, device fingerprint salts

**Cryptographic material:**
- Encryption keys, initialization vectors (IVs), key-derivation salts
- HMAC secrets, signing keys for webhooks or internal messages

**Access control tokens:**
- OTP codes (TOTP/HOTP seeds, SMS codes), invite codes, temporary passwords
- Unguessable URLs (file sharing links, magic login links)
- File access tokens, pre-signed URL generation secrets

**Financial and integrity-sensitive:**
- Transaction IDs used as idempotency keys with security implications
- Lottery/raffle selection in any context where fairness matters

### Step 2: Check the Random Source

For each generation site, identify the random source function and classify it.

**UNSAFE sources (predictable / non-cryptographic PRNG):**

| Language   | Unsafe Function                              | Algorithm / Why Predictable                              |
|------------|----------------------------------------------|----------------------------------------------------------|
| Python     | `random.random()`, `random.randint()`, `random.choice()`, `random.getrandbits()` | Mersenne Twister — full state recoverable after 624 consecutive 32-bit outputs |
| JavaScript | `Math.random()`                              | V8 uses xorshift128+, SpiderMonkey uses similar — state recoverable from a few outputs |
| Java       | `java.util.Random`, `ThreadLocalRandom`      | 48-bit LCG — next output predictable from one observed output |
| Go         | `math/rand.Intn()`, `math/rand.Int63()`     | Predictable if seeded with time or small entropy source  |
| Ruby       | `rand()`, `Random.new`                       | Mersenne Twister — same weakness as Python               |
| C/C++      | `rand()`, `srand(time(NULL))`, `random()`    | LCG or similar — trivially predictable                   |
| PHP        | `rand()`, `mt_rand()`, `array_rand()`        | Mersenne Twister — `mt_rand` state recoverable; `uniqid()` is time-based, not random |
| Rust       | `rand::thread_rng()` used via `rand::Rng` trait | ChaCha-based, actually CSRNG — but check if `rand::rngs::SmallRng` or `StdRng::seed_from_u64(constant)` is used instead |

**SAFE sources (cryptographically secure PRNG / CSPRNG):**

| Language   | Safe Function                                |
|------------|----------------------------------------------|
| Python     | `secrets.token_hex()`, `secrets.token_urlsafe()`, `secrets.token_bytes()`, `os.urandom()`, `secrets.choice()` |
| JavaScript | `crypto.randomBytes()` (Node), `crypto.getRandomValues()` (browser), `crypto.randomUUID()` |
| Java       | `java.security.SecureRandom`                 |
| Go         | `crypto/rand.Read()`, `crypto/rand.Int()`    |
| Ruby       | `SecureRandom.hex()`, `SecureRandom.uuid()`, `SecureRandom.random_bytes()` |
| C/C++      | `getrandom()` (Linux), `/dev/urandom`, `BCryptGenRandom()` (Windows), `arc4random_buf()` (BSD/macOS) |
| PHP        | `random_bytes()`, `random_int()` (PHP 7+)   |
| Rust       | `rand::rngs::OsRng`, `ring::rand::SystemRandom`, `getrandom` crate |

### Step 3: Check for Seeding Issues

Even when a CSPRNG is used, bad seeding can destroy security:

- **Seeded with time:** `srand(time(NULL))` or `new Random(System.currentTimeMillis())` — attacker who knows approximate time can brute-force the seed (typically < 2^32 search space)
- **Seeded with PID:** `srand(getpid())` — PID range is typically 0-65535, trivially brute-forceable
- **Seeded with constant:** `random.seed(42)` or `new Random(12345)` — deterministic output, identical across every run
- **Combined weak seeds:** `srand(time(NULL) ^ getpid())` — still a tiny search space
- **Not explicitly seeded:** Language-dependent behavior:
  - Go `math/rand` before Go 1.20: defaults to seed 1 (deterministic!). Go 1.20+: auto-seeds from crypto/rand
  - Python `random`: auto-seeds from os.urandom on import (unpredictable seed, but Mersenne Twister state is still recoverable from outputs)
  - Java `java.util.Random()`: seeds from `System.nanoTime()` — predictable in server environments

### Step 4: Check for Truncation and Reduction Issues

A secure random source can still produce guessable values if post-processed badly:

**Insufficient entropy after truncation:**
- 6-digit numeric OTP from CSPRNG: only 10^6 = 1M possibilities — brute-forceable in minutes without rate limiting
- 4-character alphanumeric token: 36^4 = ~1.7M possibilities
- Rule of thumb: security tokens need at least 128 bits of entropy (e.g., 32 hex chars, 22 base64url chars)

**Modulo bias:**
```python
# BIASED — values 0-7 appear slightly more often than 8-9
digit = secure_random_byte() % 10
```
When the random range is not evenly divisible by the modulus, lower values have a higher probability. For security tokens this usually has negligible impact, but for cryptographic key material or gambling applications, use rejection sampling.

**UUID as security token:**
- UUIDv4: 122 random bits — generally sufficient entropy, but check it is actually v4 and not v1 (time-based, predictable)
- UUIDv1: encodes MAC address + timestamp — NOT random, NOT suitable as a secret

### Step 5: Classify

- **VULNERABLE (Critical)**: Security token (session ID, password reset, API key) generated from non-CSPRNG and reachable by external users
- **VULNERABLE (High)**: CSPRNG used but seeded with constant or time — deterministic or low-entropy output in production
- **VULNERABLE (High)**: Encryption key or IV generated from non-CSPRNG
- **HARDENED (Medium)**: CSPRNG but token truncated to < 64 bits without rate limiting
- **HARDENED (Medium)**: UUIDv1 used as access token (predictable components but large space)
- **HARDENED (Low)**: Modulo bias in token generation from CSPRNG (usually negligible)
- **SAFE**: CSPRNG with sufficient output length (>= 128 bits) and no bad seeding
- **BY_DESIGN**: Non-CSPRNG used explicitly for non-security purpose (documented, no security impact)

## Decision Tree

```
Is a random value generated?
├── No → Not relevant
└── Yes → Is it used for a security purpose? (auth token, key, OTP, access control)
    ├── No → BY_DESIGN (verify it truly has no security impact)
    └── Yes → Is the random source a CSPRNG?
        ├── No (Math.random, random.randint, java.util.Random, etc.) → VULNERABLE
        │   ├── Token reachable by external users → Critical
        │   └── Internal only → High
        └── Yes (secrets, crypto.randomBytes, SecureRandom, etc.) → Check seeding
            ├── Seeded with constant/time/PID → VULNERABLE (High)
            ├── Properly seeded or auto-seeded from OS entropy → Check output length
            │   ├── Token < 64 bits (e.g., 6-digit OTP) without rate limiting → HARDENED (Medium)
            │   ├── Token 64-127 bits → HARDENED (Low) for long-lived tokens, SAFE for short-lived
            │   └── Token >= 128 bits → SAFE
            └── Seeding unclear → Investigate further
```

## Real-World Examples

### Example 1: Password Reset Token Using Math.random()

**Vulnerable pattern:**
```javascript
// routes/auth.js
const express = require('express');
const router = express.Router();

router.post('/forgot-password', async (req, res) => {
    const user = await User.findOne({ email: req.body.email });
    if (!user) return res.status(200).json({ message: 'If account exists, email sent' });

    // VULNERABLE: Math.random() is xorshift128+, predictable
    const resetToken = Math.random().toString(36).substring(2, 15)
                     + Math.random().toString(36).substring(2, 15);

    user.resetToken = resetToken;
    user.resetExpires = Date.now() + 3600000;
    await user.save();

    await sendEmail(user.email, `https://app.example.com/reset?token=${resetToken}`);
    res.json({ message: 'If account exists, email sent' });
});
```

**Why vulnerable:** `Math.random()` in V8 uses xorshift128+. An attacker who can observe a few random outputs (e.g., from any feature on the same server that exposes Math.random() values) can recover the internal state and predict all future outputs, including password reset tokens for any user.

**Impact:** Full account takeover. Attacker requests password reset for victim, predicts the token, and resets the password.

**Fix:**
```javascript
const crypto = require('crypto');

const resetToken = crypto.randomBytes(32).toString('hex');  // 256 bits, CSPRNG
```

### Example 2: Session ID from random.randint() with Time-Based Seed

**Vulnerable pattern:**
```python
import random
import time

# Seeded at application startup
random.seed(int(time.time()))

def create_session(user_id):
    # VULNERABLE: Mersenne Twister seeded with startup timestamp
    session_id = ''.join(
        random.choice('abcdefghijklmnopqrstuvwxyz0123456789')
        for _ in range(32)
    )
    sessions[session_id] = {'user_id': user_id, 'created': time.time()}
    return session_id
```

**Why vulnerable:** The seed is `int(time.time())` at startup. If an attacker knows the approximate server start time (from deploy logs, uptime headers, or simply trying timestamps within a plausible window), they can reproduce the entire Mersenne Twister state and predict every session ID the server has ever generated. Even without knowing the seed, observing 624 consecutive 32-bit outputs from the Twister recovers the full state.

**Impact:** Session hijacking for any user. Attacker predicts valid session IDs and impersonates users.

**Fix:**
```python
import secrets

def create_session(user_id):
    session_id = secrets.token_urlsafe(32)  # 256 bits from os.urandom
    sessions[session_id] = {'user_id': user_id, 'created': time.time()}
    return session_id
```

### Example 3: False Positive — Math.random() for UI Shuffling

```javascript
// components/Dashboard.jsx
function shuffleWidgets(widgets) {
    // Non-security use: randomize the order of dashboard widgets for visual variety
    return widgets
        .map(w => ({ widget: w, sort: Math.random() }))
        .sort((a, b) => a.sort - b.sort)
        .map(({ widget }) => widget);
}

function Dashboard({ widgets }) {
    const shuffled = React.useMemo(() => shuffleWidgets(widgets), [widgets]);
    return (
        <div className="grid">
            {shuffled.map(w => <WidgetCard key={w.id} widget={w} />)}
        </div>
    );
}
```

**Why safe:** `Math.random()` is used purely for cosmetic UI shuffling. The order of dashboard widgets has no security implications. No tokens, keys, or access-control decisions depend on this value. An attacker who predicts the shuffle order gains nothing.

## Common False Positive Patterns

1. **Test/fixture data generation**: `random.randint()` in test factories or seed scripts to create sample data — not used in production, no security impact
2. **UI randomization**: `Math.random()` for shuffling display order, animation delays, A/B test bucketing — cosmetic only, no security purpose
3. **Load balancing / jitter**: Random delay added to retry loops (`time.sleep(random.uniform(0.5, 1.5))`) or random selection of backend servers — unpredictability is nice-to-have, not security-critical
4. **Non-security identifiers**: `uuid.uuid4()` for database primary keys or correlation IDs where the ID is never used as an access-control gate — the ID being guessable does not grant access because authorization checks exist independently
5. **Sampling and analytics**: `random.random() < 0.01` for 1% sampling of logs or metrics — no security impact if the sampling rate is predictable
6. **Game/entertainment features**: Random selection for non-monetary features like "random avatar color" or "random motivational quote" — no financial or security impact
7. **Feature flags with random rollout**: `Math.random() < 0.5` to decide if a user sees a new feature — even if predictable, the worst outcome is seeing or not seeing a UI feature, not a security breach
