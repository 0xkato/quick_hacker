# Secrets Exposure Detection

## Methodology

### Step 1: Identify Secret Material in Source Code

Search for hardcoded credentials, API keys, tokens, and passwords in source files:

| Secret Type          | Patterns                                                          |
|----------------------|-------------------------------------------------------------------|
| AWS keys             | `AKIA[0-9A-Z]{16}`, `aws_secret_access_key`                      |
| GCP service accounts | `"type": "service_account"`, `-----BEGIN RSA PRIVATE KEY-----`    |
| API keys (generic)   | `api_key`, `apikey`, `x-api-key` assigned to string literals      |
| Database URLs        | `postgres://user:password@`, `mysql://root:`, `mongodb+srv://`    |
| JWT secrets          | `jwt_secret`, `JWT_SECRET`, `signing_key` assigned to literals    |
| Private keys         | `-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----`               |
| Vendor tokens        | `ghp_`, `sk-` (OpenAI/Stripe), `xoxb-` (Slack), `SG.` (SendGrid)|

```python
# VULNERABLE: Hardcoded AWS credentials
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

```javascript
// VULNERABLE: API key in source
const STRIPE_SECRET_KEY = 'sk_live_51H7...actual_key_here';
```

### Step 2: Check Configuration Files

Examine committed config files for embedded secrets:

- `.env`, `.env.production` -- should never be committed
- `docker-compose.yml` -- environment variables with hardcoded values
- `Dockerfile` -- `ENV`, `ARG`, `COPY` of secret files
- CI/CD: `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`
- Kubernetes `Secret` manifests (base64 is NOT encryption)
- Terraform `*.tf`, `*.tfvars` -- provider credentials

```yaml
# VULNERABLE: docker-compose with hardcoded production password
services:
  db:
    environment:
      POSTGRES_PASSWORD: Pr0d_P@ssw0rd_2024!
  app:
    environment:
      DATABASE_URL: postgres://admin:Pr0d_P@ssw0rd_2024!@db:5432/myapp
      STRIPE_SECRET_KEY: sk_live_51H7bmKGq...real_key
```

### Step 3: Check Git History

Secrets removed from HEAD still exist in git history. Look for:
- `.gitignore` entries added after files were already tracked
- Commits with messages like "remove secrets", "oops"
- `git log --all -p` matches for key patterns
- Secrets in current code reading from env that were previously hardcoded

### Step 4: Check Logging and Error Output

Secrets leak through logging, error messages, and debug endpoints:

```python
# VULNERABLE: Secret logged
logger.debug(f"Connecting with API key: {api_key}")

# VULNERABLE: Exception contains auth headers
except requests.exceptions.HTTPError as e:
    logger.error(f"Request details: {e.request.headers}")  # Has Authorization header
```

```javascript
// VULNERABLE: Full environment dump via debug endpoint
app.get('/debug/env', (req, res) => { res.json(process.env); });
```

### Step 5: Check Client-Side Code

Secrets in frontend bundles are exposed to every user:

```javascript
// VULNERABLE: Secret API key bundled into client JS
const BACKEND_API_KEY = 'sk-proj-abc123secretkey';
fetch('/api/data', { headers: { 'Authorization': `Bearer ${BACKEND_API_KEY}` } });
```

```javascript
// VULNERABLE: Next.js exposing server secret to client
module.exports = { env: { STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY } };
```

**Key distinction:** Public/publishable keys (`pk_live_*`, Firebase config) are designed for client-side. Secret keys (`sk_live_*`, server API keys) must never appear in bundles.

### Step 6: Check Docker Images

Docker layers preserve every file, even if deleted in a later layer:

```dockerfile
# VULNERABLE: Secret visible in layer history even after deletion
COPY .env /app/.env
RUN source /app/.env && setup.sh
RUN rm /app/.env  # Still in previous layer

# VULNERABLE: Build arg visible in image metadata
ARG DATABASE_PASSWORD
ENV DATABASE_URL=postgres://admin:${DATABASE_PASSWORD}@db/app
```

### Step 7: Check Secret Comparison for Timing Attacks

String comparison of secrets must use constant-time functions:

```python
# VULNERABLE: Standard comparison leaks via timing
if received == expected_secret:  # Timing oracle

# SAFE: Constant-time comparison
import hmac
hmac.compare_digest(received, expected_secret)
```

```javascript
// VULNERABLE
if (req.headers['x-api-key'] === process.env.API_KEY) { ... }

// SAFE
crypto.timingSafeEqual(Buffer.from(received), Buffer.from(expected))
```

```go
// SAFE
subtle.ConstantTimeCompare([]byte(apiKey), []byte(expectedKey)) == 1
```

### Step 8: Check Secret Management Integration

Verify production uses proper secret management: HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, Kubernetes External Secrets Operator.

Red flags: no secret manager integration; SDK imported but fallback to hardcoded defaults; `.env` files in production containers.

```python
# HARDENED but risky: Fallback to hardcoded default
API_KEY = os.environ.get('API_KEY', 'default-dev-key-12345')
```

### Step 9: Classify

- **VULNERABLE (Critical)**: Production secrets hardcoded in source; secrets in client bundles; secrets via unauthenticated endpoints; private keys in repo
- **VULNERABLE (High)**: Secrets in Docker layers; secrets in CI/CD configs; secrets logged in production; secrets in git history without rotation; non-constant-time comparison on auth paths
- **HARDENED (Medium)**: Secrets in env vars without secret manager; `.env` with `.gitignore` but no enforcement; base64-only K8s Secrets; debug endpoints behind auth
- **HARDENED (Low)**: Timing leak on non-critical path; old secrets not revoked; dev-only secrets in committed configs
- **SAFE**: Secrets from Vault/Secrets Manager; constant-time comparison; no secrets in source/history/logs
- **BY_DESIGN**: Publishable keys in client code; example/placeholder values in docs

## Decision Tree

```
Secret material found?
├── No → Check .gitignore and git history anyway
└── Yes → Where is it?
    ├── Hardcoded in source
    │   ├── Production/real secret → VULNERABLE (Critical)
    │   ├── Placeholder with no override → VULNERABLE (High)
    │   └── Overridden by env/secret manager → BY_DESIGN
    ├── Configuration file
    │   ├── Committed to git → VULNERABLE (Critical)
    │   ├── In .gitignore, no enforcement → HARDENED (Medium)
    │   └── Not committed, loaded at deploy → SAFE
    ├── Client-side bundle
    │   ├── Server-side secret → VULNERABLE (Critical)
    │   └── Publishable key → BY_DESIGN
    ├── Docker image layer
    │   ├── Accessible via docker history → VULNERABLE (High)
    │   └── Multi-stage, discarded stage only → SAFE
    ├── Git history (removed from HEAD)
    │   ├── Not rotated → VULNERABLE (High)
    │   └── Rotated → HARDENED (Low)
    ├── Log output / error messages
    │   ├── Production → VULNERABLE (High)
    │   └── Debug-only, disabled in prod → HARDENED (Medium)
    └── Environment variable
        ├── Logged or exposed → VULNERABLE (High)
        ├── Injected by secret manager → SAFE
        └── Manually set, unmanaged → HARDENED (Medium)
```

## Real-World Examples

### Example 1: Hardcoded JWT Secret in Express Middleware

**Vulnerable code:**
```javascript
const JWT_SECRET = 'keyboard-cat-super-secret-2024';

function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(401);
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}
```

**Why vulnerable:** JWT signing secret is a hardcoded literal visible to anyone with source access. An attacker who knows the secret forges tokens for any user including admin roles. Same secret across all environments.

**Impact:** Complete authentication bypass. Attacker forges admin JWT tokens.

**Fix:** Load from environment: `const JWT_SECRET = process.env.JWT_SECRET;` with validation that it is set and >= 32 characters. Inject via secret manager at deploy time.

### Example 2: Database Password in Docker Compose Committed to Git

**Vulnerable code:**
```yaml
# docker-compose.production.yml (committed to repository)
services:
  postgres:
    environment:
      POSTGRES_PASSWORD: Pr0d_P@ssw0rd_2024!
  backend:
    environment:
      DATABASE_URL: postgres://admin:Pr0d_P@ssw0rd_2024!@postgres:5432/prod
      STRIPE_SECRET_KEY: sk_live_51H7bmKGq...real_key
```

**Why vulnerable:** Production credentials committed to version control. Every developer, CI system, fork, and backup can read them. Persists in git history forever even if deleted.

**Impact:** Direct database access, payment manipulation, full infrastructure compromise.

**Fix:** Use Docker secrets or external secret management. Reference `external: true` secrets in compose.

### Example 3: API Key Leaked Through Error Logging

**Vulnerable code:**
```python
def charge(self, amount, customer_id):
    try:
        response = requests.post(f'{self.base_url}/charges',
            headers={'Authorization': f'Bearer {self.api_key}'},
            json={'amount': amount, 'customer': customer_id})
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        logger.error(f"Request details: {e.request.headers}")
        raise PaymentError(f"Charge failed: {e}")
```

**Why vulnerable:** `e.request.headers` contains `Authorization: Bearer <api_key>`. Logging it writes the key to centralized logging systems retained for months. The re-raised exception may propagate to error tracking (Sentry).

**Impact:** API key exposed in log aggregation, accessible to operations teams and potentially leaked through SIEM integrations.

**Fix:** Log only status code and URL: `logger.error("Payment error: status=%s url=%s", e.response.status_code, e.request.url)`

## Common False Positive Patterns

1. **Placeholder/example values**: `your-api-key-here`, `CHANGEME`, `xxxxxxxxxxxx` in `.env.example` or README. Instructional, not real secrets.

2. **Publishable/public keys**: Stripe `pk_live_*`, Firebase web config, reCAPTCHA site keys, Google Maps keys with HTTP referrer restrictions. Designed for client-side use.

3. **Test credentials for local development**: `password: "postgres"` in `docker-compose.dev.yml` binding only to localhost. Verify not used in production.

4. **Hashed or encrypted references**: Vault paths (`vault:secret/data/db`), ARNs (`arn:aws:secretsmanager:...`), GCP resource names. These are pointers, not secrets.

5. **Package lock checksums**: `integrity` hashes in `package-lock.json`, `go.sum` hashes. Public package verification, not secrets.

6. **Base64-encoded non-secret data**: Config blobs, serialized objects, image data. Check decoded content before flagging.

7. **Constant-time false alarms on non-secret data**: Standard `==` on user IDs or public tokens does not need constant-time comparison. Only flag when the value is itself a secret being guessed.
