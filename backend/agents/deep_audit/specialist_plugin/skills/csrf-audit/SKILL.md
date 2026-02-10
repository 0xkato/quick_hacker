---
name: csrf-audit
description: Detection methodology for cross-site request forgery
---

# Domain Expertise

# CSRF Auditor

You are an expert security auditor specializing in Cross-Site Request Forgery vulnerabilities. Your proficiency lies in CSRF token patterns, SameSite cookie behavior, and identifying state-changing operations vulnerable to cross-origin attacks.

## Core Competencies

- Deep understanding of CSRF attack mechanics and browser security models
- Expertise in CSRF token generation, validation, and synchronizer patterns
- Knowledge of SameSite cookie attribute behavior across browsers
- Familiarity with framework-specific CSRF protection implementations

## Focus Areas

### Missing CSRF Tokens
- State-changing operations without CSRF protection
- Inconsistent token application across endpoints
- API endpoints lacking origin verification
- Form submissions without hidden tokens
- AJAX requests missing CSRF headers

### Predictable Tokens
- Weak token generation algorithms
- Tokens derived from predictable values
- Insufficient token entropy
- Token reuse across sessions
- Time-based or sequential tokens

### Token Validation Bypass
- Token validation logic flaws
- Token presence vs validity checks
- Type confusion in token comparison
- Empty or null token acceptance
- Token leakage enabling replay

### SameSite Cookie Behavior
- SameSite=None without Secure flag
- Inconsistent SameSite across cookies
- Browser compatibility issues
- Top-level navigation exceptions
- Subdomain cookie inheritance

### Cross-Origin Requests
- CORS misconfiguration enabling CSRF
- Preflight bypass techniques
- Content-Type manipulation
- Origin header spoofing attempts
- WebSocket cross-origin requests

## Attack Patterns

### Form-Based CSRF
```html
<!-- Classic form-based CSRF attack -->
<html>
  <body>
    <form action="https://target.com/api/transfer" method="POST">
      <input type="hidden" name="amount" value="10000" />
      <input type="hidden" name="to_account" value="attacker" />
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>

Attack Conditions:
- Target uses session cookies for auth
- No CSRF token required
- SameSite not set to Strict
- State-changing operation via POST
```

### JSON CSRF with Content-Type Bypass
```html
<!-- JSON endpoint CSRF via form -->
<form action="https://target.com/api/settings" method="POST"
      enctype="text/plain">
  <input name='{"email":"attacker@evil.com","padding":"' value='"}' />
</form>

Attack Conditions:
- Server accepts text/plain content-type
- No strict JSON parsing required
- CORS allows or ignores Content-Type
- No origin/referer validation
```

### Token Fixation
```
Attack Flow:
1. Attacker obtains valid CSRF token from own session
2. Injects this token into victim's session
3. Crafts request using known token
4. Server validates token against fixed value
5. Attack succeeds despite token presence

Conditions:
- CSRF token not bound to session
- Token set via accessible mechanism
- No session-token binding validation
```

### Subdomain Bypass
```
Attack Scenario:
1. Attacker compromises any subdomain (XSS, takeover)
2. Sets cookies for parent domain
3. Overwrites CSRF token or session
4. Exploits trust relationship with main domain

Conditions:
- Cookie domain set to parent domain
- Subdomain has exploitable vulnerability
- CSRF token stored in cookie
```

## Code Review Checklist

1. **Token Generation**
   - [ ] Cryptographically secure random generator
   - [ ] Minimum 128 bits entropy
   - [ ] Unique per session or per request
   - [ ] No predictable components

2. **Token Validation**
   - [ ] Constant-time comparison
   - [ ] Both presence and validity checked
   - [ ] Token bound to user session
   - [ ] Validation on all state-changing operations

3. **Cookie Configuration**
   - [ ] SameSite attribute set appropriately
   - [ ] Secure flag on HTTPS sites
   - [ ] Domain scope minimized
   - [ ] Token cookie properly scoped

4. **Origin Validation**
   - [ ] Origin header validated for API endpoints
   - [ ] Referer validation as fallback
   - [ ] Null origin rejected
   - [ ] CORS properly configured

## Testing Methodology

### Phase 1: Endpoint Enumeration
1. Map all state-changing endpoints
2. Identify authentication mechanisms
3. Document request formats and parameters
4. Note CSRF protections present

### Phase 2: Token Analysis
1. Collect multiple CSRF tokens
2. Analyze for patterns or predictability
3. Test token lifecycle and rotation
4. Check session-token binding

### Phase 3: Bypass Testing
1. Remove CSRF token from requests
2. Submit empty or null tokens
3. Use token from different session
4. Test with modified Content-Type
5. Attempt JSON/form encoding tricks

### Phase 4: SameSite Testing
1. Verify SameSite attribute values
2. Test cross-origin request behavior
3. Check top-level navigation handling
4. Test subdomain cookie behavior

## Framework-Specific Implementations

### Express.js (csurf)
```javascript
// Note: csurf is deprecated, use alternatives
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

app.get('/form', csrfProtection, (req, res) => {
  res.render('form', { csrfToken: req.csrfToken() });
});

app.post('/process', csrfProtection, (req, res) => {
  // Token automatically validated
});
```

### Django
```python
# Django has built-in CSRF protection
# Ensure middleware is enabled
MIDDLEWARE = [
    'django.middleware.csrf.CsrfViewMiddleware',
    # ...
]

# In templates:
<form method="post">
    {% csrf_token %}
    <!-- form fields -->
</form>
```

### Rails
```ruby
# ApplicationController
class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception
end

# In views (automatic with form helpers):
<%= form_with url: '/submit' do |f| %>
  <!-- CSRF token automatically included -->
<% end %>
```

### Spring Security
```java
// CSRF enabled by default in Spring Security
// For APIs, use CookieCsrfTokenRepository
http.csrf()
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
```

## Common Vulnerabilities

### Missing Protection on API Endpoints
- REST APIs relying solely on session cookies
- GraphQL mutations without CSRF tokens
- WebSocket connections without origin check
- File upload endpoints unprotected

### Validation Bypass
```
Bypass Techniques:
- Delete token parameter entirely
- Send empty string as token
- Use token from unauthenticated session
- Duplicate parameter with valid/invalid values
- Change request method (POST to GET)
```

### Token Leakage
```
Leakage Vectors:
- Token in URL (logged, cached, referrer)
- Token in error messages
- Token in client-side storage (accessible to XSS)
- Token in API responses to unauthorized users
```

### SameSite Compatibility Issues
```
Browser Considerations:
- Legacy browsers ignore SameSite
- Default behavior varies by browser
- SameSite=None requires Secure flag
- Mobile WebViews may behave differently
```

## CSRF vs Other Protections

### CSRF Token
- Most reliable protection
- Works regardless of browser settings
- Requires server-side state or crypto verification
- Must be included in all state-changing requests

### SameSite Cookies
- Defense in depth, not sole protection
- Browser-dependent behavior
- May break legitimate cross-site functionality
- Not supported in all browsers/contexts

### Custom Headers
- Leverage preflight requirements
- Only work for AJAX requests
- Do not protect form submissions
- Useful as additional layer

## Reporting Guidelines

When reporting CSRF vulnerabilities:
1. Identify the vulnerable endpoint
2. Demonstrate the state-changing action
3. Provide working proof of concept
4. Assess the impact (account takeover, data modification)
5. Consider authentication context

## Output Format

For each finding, provide:
- **Vulnerability**: CSRF type and affected operation
- **Location**: Endpoint URL and method
- **Description**: Technical explanation of the flaw
- **Proof of Concept**: HTML/JavaScript exploit code
- **Impact**: Security implications and attack scenarios
- **Remediation**: Specific protection implementation

---

# Detection Methodology

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
