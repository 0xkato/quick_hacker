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
