# Authentication Bypass Detection

## Methodology

### Step 1: Map the Authentication Architecture

Before hunting for bypasses, understand HOW authentication works:

1. **Identify the auth mechanism(s):**
   - Session-based (cookies + server-side store)
   - JWT/token-based (stateless, signed tokens)
   - API key (header or query param)
   - OAuth2/OIDC (delegated auth)
   - mTLS (mutual TLS, certificate-based)
   - Basic Auth (username:password in header)
   - Custom (proprietary token format)

2. **Identify where auth is enforced:**
   - Global middleware (applied to all routes by default)
   - Per-route decorators (`@login_required`, `@auth.required`)
   - Manual checks inside handlers (`if not request.user: return 401`)
   - API gateway / reverse proxy (auth happens before app code)

3. **Identify auth exclusions:**
   - Which routes are explicitly excluded from auth? (login, register, health, public APIs)
   - HOW are they excluded? (middleware skip list, no decorator, route prefix)
   - Is the exclusion mechanism safe? (allowlist vs blocklist of unauthenticated routes)

### Step 2: Hunt for Missing Auth Checks

**Pattern 1: Route without middleware/decorator**
```python
# All other routes have @login_required, but this one doesn't
@app.route("/api/admin/export")  # <-- No auth decorator!
def export_data():
    return generate_export()
```

**Search strategy:**
- List all route definitions
- For each route, check if auth middleware/decorator is present
- Compare against the expected auth policy (from Security Map invariants)
- Flag any route that SHOULD be authenticated but isn't

**Pattern 2: Middleware bypass via path manipulation**
```python
# Middleware checks path prefix
class AuthMiddleware:
    SKIP_PATHS = ["/public/", "/health", "/auth/login"]

    def process_request(self, request):
        if any(request.path.startswith(p) for p in self.SKIP_PATHS):
            return  # Skip auth
        verify_token(request)
```

Check for:
- Path traversal: `/public/../api/admin/export`
- Case sensitivity: `/Public/` vs `/public/`
- Trailing slash: `/health/` vs `/health`
- URL encoding: `/auth%2Flogin` or `/%61uth/login`
- Double slash: `//health` or `/health//`

**Pattern 3: Auth check with logic flaw**
```python
def verify_auth(request):
    token = request.headers.get("Authorization")
    if not token:
        return None  # No token → returns None
    return decode_token(token)

# Handler trusts None as "no auth needed" instead of "auth failed"
@app.route("/api/data")
def get_data():
    user = verify_auth(request)
    # BUG: None means "no token provided", not "anonymous access allowed"
    # Should return 401 if user is None
    return fetch_data(user)  # Proceeds with user=None
```

### Step 3: Hunt for Token/Session Vulnerabilities

**JWT-specific checks:**
- `alg: "none"` — signature verification disabled
- Weak signing key (hardcoded, short, guessable)
- Key confusion (RS256 → HS256 — public key used as HMAC secret)
- Missing expiration (`exp` claim absent)
- No audience/issuer validation (`aud`, `iss` claims not checked)
- Token stored in localStorage (XSS → token theft)

**Session-specific checks:**
- Session ID in URL (session fixation risk)
- Session not invalidated on logout
- Session not invalidated on password change
- Predictable session IDs (sequential, timestamp-based)
- Session fixation (pre-auth session promoted to post-auth without rotation)

**API key checks:**
- Key in URL query parameter (logged in server logs, browser history)
- Key not rotatable
- Single key for all permissions (no scoping)
- Key comparison not constant-time (timing attack)

### Step 4: Hunt for Privilege Boundary Breaks

After auth is verified, check that the authenticated identity is used correctly:

- **Horizontal privilege escalation**: User A can access User B's resources by changing an ID parameter
- **Vertical privilege escalation**: Regular user can access admin endpoints by modifying role/claims
- **Token reuse across contexts**: Token for service A accepted by service B
- **Stale permissions**: User's role changed but existing token/session still has old role

### Step 5: Classify

- **VULNERABLE (Critical)**: Complete auth bypass on sensitive endpoint (unauthenticated access to protected data/actions)
- **VULNERABLE (High)**: JWT `alg:none` accepted, or auth middleware bypassable via path manipulation
- **VULNERABLE (High)**: Session fixation on login flow
- **HARDENED (Medium)**: Weak JWT signing key, missing expiration, token in localStorage
- **HARDENED (Low)**: API key in query param, session not rotated on privilege change
- **SAFE**: Auth properly enforced at all levels
- **BY_DESIGN**: Intentionally public endpoint (verify it should be public)

## Decision Tree

```
Is there an endpoint that handles sensitive data or actions?
├── No → Not relevant for auth bypass
└── Yes → Is authentication enforced on this endpoint?
    ├── Yes → Is the auth check correct?
    │   ├── Checks presence AND validity of token/session → Check token security
    │   │   ├── JWT with alg:none accepted → VULNERABLE (High)
    │   │   ├── JWT with weak/hardcoded key → HARDENED (Medium)
    │   │   ├── No expiration check → HARDENED (Medium)
    │   │   └── Proper validation → SAFE
    │   ├── Only checks presence, not validity → VULNERABLE (High)
    │   └── Returns None/false but caller doesn't check → VULNERABLE (Critical)
    └── No → Should it be authenticated?
        ├── Yes (based on Security Map invariants) → VULNERABLE (Critical)
        └── No (intentionally public) → BY_DESIGN (document it)
```

## Real-World Examples

### Example 1: Missing Auth on Admin Endpoint

**Vulnerable pattern:**
```python
# routes/admin.py
from flask import Blueprint
admin = Blueprint('admin', __name__, url_prefix='/admin')

@admin.route('/users')
@login_required          # Protected ✓
def list_users():
    return render_template('admin/users.html', users=User.query.all())

@admin.route('/users/export')    # <-- No @login_required!
def export_users():
    users = User.query.all()
    return generate_csv(users)   # Leaks all user data without auth
```

**Why vulnerable:** The developer added `@login_required` to `list_users` but forgot it on `export_users`. Both endpoints serve user data, but only one is protected. Common when routes are added incrementally.

**Impact:** Any unauthenticated user can download the full user database.

**Fix:** Apply auth at the blueprint level, not per-route.
```python
@admin.before_request
@login_required
def require_admin_auth():
    if not current_user.is_admin:
        abort(403)
```

### Example 2: JWT Algorithm Confusion

**Vulnerable pattern:**
```python
import jwt

def verify_token(token: str) -> dict:
    # RS256 expects asymmetric key pair
    # But library also accepts HS256 if attacker changes the alg header
    public_key = open("public.pem").read()
    return jwt.decode(token, public_key, algorithms=["RS256", "HS256"])
```

**Why vulnerable:** If both RS256 and HS256 are allowed, an attacker can:
1. Get the public key (often publicly available)
2. Create a new JWT with `alg: "HS256"`
3. Sign it using the public key as the HMAC secret
4. The server verifies it with the public key as HMAC secret — and it passes

**Fix:** Only allow the expected algorithm.
```python
return jwt.decode(token, public_key, algorithms=["RS256"])  # Only RS256
```

### Example 3: Path-Based Middleware Bypass

**Vulnerable pattern:**
```javascript
// Express middleware
app.use((req, res, next) => {
    // Skip auth for public paths
    if (req.path.startsWith('/public/') || req.path === '/health') {
        return next();
    }
    verifyJWT(req, res, next);
});

// But Express normalizes paths AFTER middleware runs in some configurations
// Attacker requests: /public/../api/admin/users
// req.path = "/public/../api/admin/users" (starts with /public/ → skips auth)
// Express routes to: /api/admin/users (after path normalization)
```

**Why vulnerable:** The middleware checks the raw path, but Express resolves `..` segments when matching routes. The attacker's request bypasses auth by starting with `/public/` but actually routes to an admin endpoint.

**Fix:** Normalize the path before checking.
```javascript
const normalizedPath = path.normalize(req.path);
if (normalizedPath.startsWith('/public/') || normalizedPath === '/health') {
    return next();
}
```

### Example 4: False Positive — Intentionally Public Endpoint

```python
@app.route("/api/v1/markets")  # No auth — intentionally public
def list_markets():
    """Public API: list active prediction markets. No PII, no auth needed."""
    return jsonify(Market.query.filter(Market.active == True).all())
```

**Why safe:** This endpoint serves only public market data. No PII, no user-specific data, no mutations. The Security Map should document this as an intentionally public endpoint.

## Common False Positive Patterns

1. **Health/readiness endpoints**: `/health`, `/ready`, `/metrics` — intentionally unauthenticated
2. **Login/register endpoints**: Must be unauthenticated by definition
3. **Public API endpoints**: Documented as public, serve only non-sensitive data
4. **Webhook receivers**: Auth via HMAC signature in body, not standard auth headers
5. **Static file routes**: CSS, JS, images — no auth needed
6. **CORS preflight**: OPTIONS requests — browsers send these before auth headers
7. **OAuth callback**: `/auth/callback` — receives auth code, performs its own validation
