# Cross-Site Request Forgery (CSRF) Detection

## Methodology

### Step 1: Identify State-Changing Endpoints and Auth Mechanism

CSRF only matters for endpoints that modify state via cookie-based auth. For each state-changing route:

1. **Collect all POST/PUT/PATCH/DELETE routes** plus GET endpoints with side effects
2. **Determine auth mechanism:**
   - Cookie-based sessions → CSRF relevant
   - Bearer token / API key in header → CSRF-immune (browser won't auto-attach)
3. **Identify CSRF defense:** Synchronizer token, double-submit cookie, SameSite attribute, custom header, Referer/Origin check

### Step 2: Check CSRF Token Presence and Validation

**Django — csrf_exempt bypass:**
```python
@csrf_exempt  # Disables CSRF protection!
@login_required
@require_POST
def transfer_funds(request):
    execute_transfer(request.user, request.POST["recipient"], request.POST["amount"])
```

**Flask-WTF — CSRF exemption:**
```python
csrf = CSRFProtect(app)
@csrf.exempt  # Dangerous if cookie-auth is used
@app.route("/api/transfer", methods=["POST"])
def transfer():
    pass
```

**Express — inconsistent csurf application:**
```javascript
app.post('/transfer', csrfProtection, handler);     // Protected
app.post('/api/settings', handler);                  // VULNERABLE — no csrfProtection
```

**Spring Security — global disable:**
```java
http.csrf().disable();  // Disables CSRF for entire app — dangerous with cookie auth
// Targeted: http.csrf().ignoringAntMatchers("/api/webhooks/**");
```

### Step 3: Detect Token Validation Bypasses

**Bypass 1: Token read but never validated**
```python
def transfer():
    csrf_token = request.form.get("csrf_token")  # Read but never checked!
    execute_transfer(current_user, request.form["recipient"], request.form["amount"])
```

**Bypass 2: GET-based state changes**
```python
@app.route("/api/delete/<int:item_id>")  # GET — no CSRF token
def delete_item(item_id):
    Item.query.filter_by(id=item_id, owner=current_user.id).delete()
# Attacker embeds: <img src="/api/delete/42">
```

**Bypass 3: Referer-only validation (substring match)**
```python
def check_csrf(request):
    referer = request.headers.get("Referer", "")
    if "mysite.com" in referer: return True  # Matches mysite.com.evil.com!
```

**Bypass 4: JSON Content-Type assumption**
```python
# Assumes only JS can send JSON — but <form enctype="text/plain"> and
# navigator.sendBeacon() can send arbitrary content types cross-origin
data = request.get_json()
execute_transfer(current_user, data["recipient"], data["amount"])
```

### Step 4: Analyze SameSite Cookie Attributes

```
SameSite=Strict → Never sent cross-site (breaks OAuth flows)
SameSite=Lax   → Sent on top-level GET only, not POST/XHR (modern browser default)
SameSite=None  → Always sent (requires Secure) — no CSRF protection
```

Lax gaps: top-level GET navigations still send cookies (GET-based state changes vulnerable), subdomain cookie injection possible, older browsers ignore SameSite.

### Step 5: Check CORS Configuration for CSRF Enablement

```python
# VULNERABLE: reflects any origin with credentials
@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response
# Attacker's site makes authenticated requests AND reads responses

# SAFE: strict allowlist
ALLOWED = {"https://myapp.com", "https://admin.myapp.com"}
origin = request.headers.get("Origin")
if origin in ALLOWED:
    response.headers["Access-Control-Allow-Origin"] = origin
```

### Step 6: Classify

- **VULNERABLE (Critical)**: Missing CSRF token on state-changing endpoint with cookie auth
- **VULNERABLE (High)**: Token present but not validated server-side
- **VULNERABLE (High)**: GET-based state changes (deletion/modification via GET)
- **VULNERABLE (High)**: CORS reflects arbitrary origin with credentials
- **HARDENED (Medium)**: Referer-only validation; JSON Content-Type assumption as sole defense
- **HARDENED (Low)**: SameSite=Lax without token backup on POST endpoints
- **SAFE**: Synchronizer token properly validated on all state-changing endpoints
- **SAFE**: Bearer/API-key auth only (no cookies)
- **BY_DESIGN**: `csrf_exempt` on webhook with HMAC signature verification

## Decision Tree

```
Is the endpoint state-changing (POST/PUT/PATCH/DELETE, or GET with side effects)?
├── No (read-only) → Not applicable
└── Yes → How does it authenticate?
    ├── Bearer token / API key in header → SAFE (not CSRF-relevant)
    ├── No authentication → Not a CSRF issue
    └── Cookie-based session → CSRF token required?
        ├── No defense at all → VULNERABLE (Critical)
        └── Token present → Validated server-side?
            ├── Read but not checked → VULNERABLE (High)
            ├── Only Referer/Origin checked → HARDENED (Medium)
            └── Properly validated → Check for bypasses
                ├── GET-based state changes → VULNERABLE (High)
                ├── csrf_exempt on sensitive endpoint → VULNERABLE (Critical)
                │   └── Alt auth (HMAC, IP allowlist)? → BY_DESIGN
                ├── CORS reflects origin + credentials → VULNERABLE (High)
                └── All checks pass → SAFE
```

## Real-World Examples

### Example 1: Django csrf_exempt on Money Transfer

```python
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required

@csrf_exempt
@login_required
@require_POST
def transfer_funds(request):
    data = json.loads(request.body)
    sender = request.user
    sender.balance -= data["amount"]
    recipient = User.objects.get(username=data["recipient"])
    recipient.balance += data["amount"]
    sender.save(); recipient.save()
    return JsonResponse({"status": "success"})
```

**Why vulnerable:** `@csrf_exempt` disables Django CSRF protection on a cookie-authenticated endpoint. An attacker hosts a page that submits a form to this endpoint; the victim's browser auto-attaches the session cookie.

**Impact:** Complete financial loss — attacker drains victim's balance from any page the victim visits while logged in.

**Fix:** Remove `@csrf_exempt`. For AJAX, send the `X-CSRFToken` header from the frontend.

### Example 2: Express App Missing CSRF on Settings

```javascript
app.use(session({ secret: 'secret', resave: false, saveUninitialized: false }));

app.post('/settings/email', (req, res) => {
    if (!req.session.userId) return res.status(401).send('Unauthorized');
    db.users.update(req.session.userId, { email: req.body.email });
    res.json({ success: true });
});
```

**Why vulnerable:** No CSRF middleware. Session cookie authenticates automatically. Attacker changes victim's email, then triggers password reset for account takeover.

**Impact:** Full account takeover via email change + password reset chain.

**Fix:** Apply `csurf` middleware globally or per-route for all cookie-authenticated state-changing endpoints.

### Example 3: Spring Security CSRF Disabled Globally

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.csrf().disable()                     // CSRF off globally
        .authorizeRequests().anyRequest().authenticated()
        .and().formLogin().loginPage("/login");  // Cookie-based auth!
}
```

**Why vulnerable:** CSRF globally disabled but app uses form-based login with session cookies. Every state-changing endpoint is exposed. Common when API config is copy-pasted into a web app.

**Impact:** All state-changing actions forgeable: settings, data deletion, privilege changes.

**Fix:** Enable CSRF, exempt only webhooks: `http.csrf().ignoringAntMatchers("/api/webhooks/**").csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())`

## Common False Positive Patterns

1. **Pure API with Bearer token auth**: No cookies for auth means no CSRF risk. Verify no cookie-based fallback exists.

2. **DRF with TokenAuthentication/JWTAuthentication**: Only flag if `SessionAuthentication` is in the authentication classes.

3. **csrf_exempt on webhooks with HMAC validation**: External services (Stripe, GitHub) cannot provide CSRF tokens. Safe if handler verifies webhook signature.

4. **Login endpoint without CSRF**: Many frameworks skip CSRF on login (no session to protect yet). Typically HARDENED (Low).

5. **SameSite=Lax as sole defense**: Effective for POST-only state changes on modern browsers. Acceptable defense-in-depth, though tokens are stronger.

6. **CORS preflight blocking custom-header POST**: If all state-changing endpoints require a custom header (`X-Requested-With`), CORS preflight blocks cross-origin requests. Valid defense if Content-Type check is strict.

7. **GraphQL with mandatory Content-Type: application/json**: CSRF-safe due to CORS preflight, unless the endpoint also accepts `application/x-www-form-urlencoded`.
