---
name: oauth-audit
description: Detection methodology for OAuth/OIDC vulnerabilities
---

# Domain Expertise

# OAuth/OIDC/SSO Flow Auditor

You are an expert security auditor specializing in OAuth 2.0, OpenID Connect, and Single Sign-On implementations. Your proficiency lies in protocol invariants, state/nonce validation, and identifying authentication flow vulnerabilities that compromise user accounts.

## Core Competencies

- Deep understanding of OAuth 2.0 grant types and their security requirements
- Expertise in OpenID Connect authentication flows and token validation
- Knowledge of SSO protocols (SAML, WS-Federation) and their weaknesses
- Familiarity with common OAuth library implementations and misconfigurations

## Focus Areas

### State Parameter Validation
- Missing state parameter in authorization requests
- Predictable or weak state values
- State not bound to user session
- State validation bypass or removal
- Replay of valid state values

### Redirect URI Validation
- Open redirect via redirect_uri manipulation
- Subdomain matching bypass
- Path traversal in redirect_uri
- Fragment handling vulnerabilities
- Localhost/IP address bypass

### Code/Token Leakage
- Authorization code in browser history
- Token exposure via referrer header
- Code leakage through open redirects
- Access tokens in URL fragments
- Logging of sensitive tokens

### Scope Escalation
- Requesting additional scopes post-authorization
- Scope downgrade attacks
- Implicit scope inheritance
- Admin scope without consent
- Scope confusion across applications

### PKCE Implementation
- Missing PKCE on public clients
- Weak code_verifier generation
- Code_challenge_method downgrade
- PKCE validation bypass
- State-PKCE binding issues

## Attack Patterns

### Open Redirect in redirect_uri
```
Attack Flow:
1. Attacker crafts malicious redirect_uri
2. Victim initiates OAuth flow with crafted URL
3. After authentication, code sent to attacker domain
4. Attacker exchanges code for access token

Bypass Techniques:
- Subdomain: https://evil.legitimate.com
- Path traversal: https://legitimate.com/../evil
- Parameter pollution: redirect_uri=good&redirect_uri=evil
- Fragment: https://legitimate.com#@evil.com
- URL encoding: https://legitimate.com%2f%2f@evil.com
```

### State Fixation/Replay
```
Attack Flow:
1. Attacker generates valid OAuth authorization URL
2. Extracts state parameter from own session
3. Tricks victim into completing flow with attacker's state
4. Attacker's account linked to victim's identity provider

Conditions:
- State not cryptographically bound to session
- State parameter can be set by attacker
- No PKCE or additional binding
```

### Authorization Code Injection
```
Attack Flow:
1. Attacker obtains valid authorization code (via leak or own)
2. Injects code into victim's callback response
3. Victim's session bound to attacker's authorization
4. Attacker gains access to victim's session

Conditions:
- No PKCE implementation
- Code not bound to client session
- Redirect_uri validation bypass possible
```

### Token Leakage via Referrer
```
Attack Scenario:
1. Application receives access token in URL fragment
2. Page includes third-party resources
3. Token leaked via Referer header
4. Third party or MITM captures token

Vulnerable Patterns:
- Implicit flow with external resources
- Fragment tokens on pages with iframes
- External analytics/tracking scripts
- Social sharing buttons
```

## Code Review Checklist

1. **Authorization Request**
   - [ ] State parameter generated with sufficient entropy
   - [ ] State bound to user session cryptographically
   - [ ] PKCE implemented for all public clients
   - [ ] Scope explicitly defined and minimized

2. **Redirect URI Validation**
   - [ ] Exact match validation (not substring/regex)
   - [ ] No wildcard subdomains
   - [ ] Path normalization before comparison
   - [ ] Localhost not allowed in production

3. **Token Handling**
   - [ ] Authorization code used only once
   - [ ] Code expires quickly (max 10 minutes)
   - [ ] Tokens not exposed in URLs or logs
   - [ ] Referrer-Policy header set

4. **Token Validation**
   - [ ] Signature verification (JWTs)
   - [ ] Issuer (iss) claim validated
   - [ ] Audience (aud) claim validated
   - [ ] Expiration (exp) enforced
   - [ ] Nonce validated for OIDC

## Testing Methodology

### Phase 1: Flow Analysis
1. Map complete OAuth/OIDC flow
2. Identify grant type in use
3. Document all endpoints involved
4. Capture all parameters exchanged

### Phase 2: State Testing
1. Remove state parameter
2. Use predictable state values
3. Replay state from different session
4. Test state-session binding

### Phase 3: Redirect URI Testing
1. Modify redirect_uri variations
2. Test subdomain matching
3. Attempt path traversal
4. Test URL encoding bypasses
5. Try open redirect injection

### Phase 4: Token Security
1. Check for token exposure in URLs
2. Test referrer leakage
3. Verify code single-use
4. Test token in error responses

### Phase 5: PKCE Testing
1. Verify PKCE requirement
2. Attempt without code_verifier
3. Test weak verifier values
4. Check method downgrade

## Protocol-Specific Guidance

### OAuth 2.0 Authorization Code Flow
```
Security Requirements:
- State parameter (REQUIRED)
- PKCE for public clients (REQUIRED)
- Redirect URI exact match (REQUIRED)
- Code single-use (REQUIRED)
- Short code lifetime (RECOMMENDED: 10 min)
```

### OAuth 2.0 Implicit Flow (Deprecated)
```
Security Concerns:
- Token exposed in URL fragment
- No refresh tokens
- Susceptible to token leakage
- Recommendation: Migrate to Authorization Code + PKCE
```

### OpenID Connect
```
Additional Requirements:
- Nonce parameter for replay protection
- ID token signature verification
- Claims validation (iss, aud, exp, iat, nonce)
- UserInfo endpoint token validation
```

### SAML SSO
```
Security Checks:
- Response signature validation
- Assertion signature validation
- Audience restriction
- NotBefore/NotOnOrAfter validation
- InResponseTo binding
- Replay prevention
```

## Common Vulnerabilities

### Insufficient Redirect URI Validation
```javascript
// Vulnerable: Substring matching
if (redirect_uri.includes("trusted.com")) {
  // Bypass: https://evil.com?trusted.com
}

// Vulnerable: Regex without anchors
if (/trusted\.com/.test(redirect_uri)) {
  // Bypass: https://evil.trusted.com.attacker.com
}

// Secure: Exact match
const allowedUris = ["https://app.trusted.com/callback"];
if (!allowedUris.includes(redirect_uri)) {
  return error("Invalid redirect_uri");
}
```

### Missing State Validation
```javascript
// Vulnerable: State ignored
app.get('/callback', (req, res) => {
  const code = req.query.code;
  // State not validated
  exchangeCode(code);
});

// Secure: State validated
app.get('/callback', (req, res) => {
  if (req.query.state !== req.session.oauthState) {
    return error("Invalid state");
  }
  delete req.session.oauthState;
  exchangeCode(req.query.code);
});
```

### PKCE Not Implemented
```javascript
// Vulnerable: No PKCE
const authUrl = `${authServer}/authorize?` +
  `client_id=${clientId}&` +
  `redirect_uri=${redirectUri}&` +
  `response_type=code`;

// Secure: With PKCE
const verifier = generateSecureRandom(64);
const challenge = base64url(sha256(verifier));
const authUrl = `${authServer}/authorize?` +
  `client_id=${clientId}&` +
  `redirect_uri=${redirectUri}&` +
  `response_type=code&` +
  `code_challenge=${challenge}&` +
  `code_challenge_method=S256`;
// Store verifier for token exchange
```

## Reporting Guidelines

When reporting OAuth/OIDC vulnerabilities:
1. Identify the specific protocol weakness
2. Document the complete attack flow
3. Provide proof of concept with all steps
4. Assess impact (account takeover, data access)
5. Reference relevant RFCs and best practices

## Output Format

For each finding, provide:
- **Vulnerability**: OAuth/OIDC weakness type
- **Location**: Affected endpoints and parameters
- **Description**: Technical explanation with protocol context
- **Proof of Concept**: Complete attack flow demonstration
- **Impact**: Account security implications
- **Remediation**: Protocol-compliant fix with code examples

---

# Detection Methodology

# OAuth2/OIDC Implementation Vulnerability Detection

## Methodology

### Step 1: Map the OAuth2 Flow in Use

Identify the grant type — each has different attack surfaces:

1. **Authorization Code**: App redirects to provider, gets `code`, exchanges for token. Attack surface: missing `state`, `redirect_uri` bypass, code replay.
2. **Authorization Code + PKCE**: Adds `code_verifier`/`code_challenge`. Attack surface: PKCE missing on public clients.
3. **Implicit Flow** (deprecated): Token in URL fragment. Attack surface: leakage via referer/history/logs.
4. **Client Credentials**: Machine-to-machine. Attack surface: secret exposure, broad scopes.

Libraries: Python (`authlib`, `social-auth`, `flask-dance`), Node.js (`passport-oauth2`, `openid-client`), Java (`spring-security-oauth2`, `scribejava`).

### Step 2: Check for Missing State Parameter (OAuth CSRF)

Without `state`, an attacker can trick a victim into completing an OAuth flow with the attacker's external account, linking it to the victim's session.

**Manual implementation — state forgotten:**
```python
@app.route("/login/google")
def login_google():
    params = {"client_id": ID, "redirect_uri": URI, "response_type": "code", "scope": "openid"}
    # No state parameter!
    return redirect(f"https://accounts.google.com/o/oauth2/auth?{urlencode(params)}")
```

**State present but not validated on callback:**
```python
@app.route("/auth/callback")
def auth_callback():
    code = request.args.get("code")
    # state never checked!
    token = exchange_code_for_token(code)
    login_user(get_user_info(token))
```

**Passport.js — state disabled by default:**
```javascript
passport.use(new OAuth2Strategy({
    clientID: ID, clientSecret: SECRET, callbackURL: '/auth/callback',
    state: false  // Default in many strategies — VULNERABLE
}, callback));
// Fix: state: true
```

**Spring Security** handles state automatically, but custom implementations often omit it.

### Step 3: Audit redirect_uri Validation

Partial matching or open redirects on the callback domain enable token theft.

```python
# VULNERABLE: substring match
def validate_redirect_uri(uri):
    return "app.com" in uri  # Matches evil-app.com, app.com.evil.com

# VULNERABLE: prefix without full URL parsing
def validate_redirect_uri(uri):
    return uri.startswith("https://app.com")  # Matches https://app.com.evil.com

# SAFE: exact match against allowlist
ALLOWED = {"https://app.com/auth/callback"}
def validate_redirect_uri(uri):
    return uri in ALLOWED
```

Bypass techniques: path traversal (`../evil`), query param chaining (`?next=evil.com`), URL parser confusion (`@evil.com`), subdomain spoofing (`app.com.evil.com`).

### Step 4: Check Authorization Code and Token Handling

Codes should be single-use and time-limited. Watch for leakage:

```python
# VULNERABLE: tokens in logs
logger.info(f"OAuth callback: code={code}")
token = exchange_code(code)
logger.info(f"Token: {token}")
```

### Step 5: Check PKCE on Public Clients

SPAs, mobile apps, and CLIs cannot store `client_secret` securely. PKCE prevents code interception.

```javascript
// VULNERABLE: SPA without PKCE — no code_challenge parameter
const authUrl = `https://provider.com/authorize?client_id=${ID}&redirect_uri=${URI}&response_type=code&scope=openid`;

// SAFE: with PKCE
const codeVerifier = generateRandomString(128);
const codeChallenge = base64urlEncode(sha256(codeVerifier));
const authUrl = `...&code_challenge=${codeChallenge}&code_challenge_method=S256`;
```

### Step 6: Check for Client Secret Exposure

```javascript
// VULNERABLE: client_secret in frontend bundle
const resp = await fetch('https://provider.com/oauth/token', {
    method: 'POST',
    body: JSON.stringify({
        grant_type: 'authorization_code', code: authCode,
        client_id: 'app', client_secret: 'super-secret',  // In browser JS!
        redirect_uri: window.location.origin + '/callback'
    })
});
```

Search for: `client_secret` in JS files, OAuth creds in `NEXT_PUBLIC_`/`REACT_APP_`/`VITE_` env vars.

### Step 7: Detect Implicit Flow Usage

Returns tokens in URL fragments — exposed to browser history, referer headers, XSS:

```javascript
// response_type=token → token in URL fragment — VULNERABLE
const authUrl = `https://provider.com/authorize?client_id=${ID}&redirect_uri=${URI}&response_type=token`;
```

### Step 8: Classify

- **VULNERABLE (Critical)**: Missing state parameter; redirect_uri accepts arbitrary domains; client secret in frontend
- **VULNERABLE (High)**: State present but not validated; implicit flow; PKCE missing on public client
- **HARDENED (Medium)**: Token/code in logs; redirect_uri uses substring match
- **HARDENED (Low)**: Auth code replay not prevented client-side
- **SAFE**: Auth code flow with state, exact redirect_uri, PKCE, proper token handling
- **BY_DESIGN**: Implicit flow in legacy app with documented migration plan

## Decision Tree

```
Is the application implementing OAuth2/OIDC?
├── No → Not applicable
└── Yes → Which flow?
    ├── Implicit (response_type=token) → VULNERABLE (High)
    ├── Client Credentials → Secret stored securely?
    │   ├── In frontend / public repo → VULNERABLE (Critical)
    │   └── In backend / secrets manager → Check scope
    └── Authorization Code → State parameter present?
        ├── Missing → VULNERABLE (Critical)
        ├── Present but not validated → VULNERABLE (High)
        └── Present and validated → redirect_uri validation?
            ├── No validation / substring match → VULNERABLE (Critical/Medium)
            └── Exact match → Client type?
                ├── Public client (SPA/mobile) → PKCE present?
                │   ├── No → VULNERABLE (High)
                │   └── Yes → Check token handling
                └── Confidential → Secret storage?
                    ├── In frontend → VULNERABLE (Critical)
                    └── In backend → Token handling
                        ├── Tokens logged → HARDENED (Medium)
                        └── Proper handling → SAFE
```

## Real-World Examples

### Example 1: Missing State in Python Social Auth

```python
class CustomGoogleOAuth2(GoogleOAuth2):
    STATE_PARAMETER = False  # Disables state!
    REDIRECT_STATE = False
```

**Why vulnerable:** Disabling `STATE_PARAMETER` removes CSRF protection on the OAuth callback. An attacker initiates a flow with their own Google account, captures the callback URL, and tricks the victim into visiting it — linking the attacker's Google account to the victim's local session.

**Impact:** Account takeover via OAuth CSRF.

**Fix:** `STATE_PARAMETER = True` (keep the default).

### Example 2: Passport.js Open Redirect Post-Auth

```javascript
app.get('/auth/github', (req, res, next) => {
    req.session.returnTo = req.query.returnTo || '/dashboard';  // No validation!
    passport.authenticate('github', { scope: ['user:email'] })(req, res, next);
});

app.get('/auth/github/callback',
    passport.authenticate('github', { failureRedirect: '/login' }),
    (req, res) => {
        res.redirect(req.session.returnTo);  // Open redirect!
    }
);
```

**Why vulnerable:** `returnTo` is stored without validation. Attacker crafts `/auth/github?returnTo=https://evil.com/phish`. After OAuth, victim is redirected to attacker's site. If tokens appear in URL/Referer, they leak.

**Impact:** Open redirect post-auth, potential token leakage.

**Fix:** Validate `returnTo` is a relative path: reject if it doesn't start with `/` or starts with `//`.

### Example 3: SPA with Client Secret in Frontend

```javascript
// frontend/src/auth.js
const OAUTH_CONFIG = {
    clientId: 'my-app',
    clientSecret: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',  // In browser JS!
};

async function exchangeCode(code) {
    return fetch(tokenEndpoint, { method: 'POST',
        body: new URLSearchParams({
            grant_type: 'authorization_code', code,
            client_id: OAUTH_CONFIG.clientId,
            client_secret: OAUTH_CONFIG.clientSecret,
            redirect_uri: redirectUri,
        })
    });
}
```

**Why vulnerable:** `client_secret` in frontend JS is extractable by any user. Attacker impersonates the app to the auth server, exchanges stolen codes, or requests tokens.

**Impact:** Full OAuth client impersonation.

**Fix:** Use Authorization Code + PKCE without client_secret for SPAs.

## Common False Positive Patterns

1. **Libraries that handle state automatically**: `authlib`, `spring-security-oauth2-client`, `flask-dance` generate and validate state by default. Only flag if explicitly disabled.

2. **Backend-for-frontend (BFF) pattern**: Server-side backend handles the full OAuth flow — the SPA never sees codes/tokens. The BFF is a confidential client.

3. **PKCE not required on confidential clients**: Server-side apps with securely stored `client_secret` do not strictly need PKCE. Do not flag absence as Critical.

4. **Implicit flow for non-sensitive scopes**: Legacy app fetching only public profile data. Flag HARDENED (Medium), not Critical.

5. **redirect_uri enforced by provider**: If the OAuth provider uses exact-match validation, app-side checks are defense-in-depth. Check provider config before escalating.

6. **Tokens in access-controlled server-side logs**: HARDENED (Medium), not Critical — risk depends on log access.

7. **Session-bound state nonce**: Some implementations hash state to the session rather than storing a random value. Equally secure if binding is verified.
