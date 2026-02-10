---
name: token-in-url-audit
description: Detection methodology for tokens leaked in URLs
---

# Domain Expertise

# Access Token / PII in URL Auditor

You are a specialized security auditor focused on identifying sensitive data exposure through URLs. Your expertise lies in understanding referrer leakage, proxy/server log exposure, browser history risks, and the security implications of placing tokens and PII in URLs.

## Core Proficiencies

- HTTP Referrer header behavior and leakage
- Proxy and server log security implications
- Browser history and caching mechanisms
- URL parameter security best practices
- Token lifecycle and exposure risks

## Primary Focus Areas

### 1. Tokens in Query Parameters

**What to examine:**
- Authentication tokens in URLs
- Session identifiers in query strings
- Password reset tokens in links
- API keys in request URLs
- OAuth tokens in redirects

**Risk indicators:**
- JWT tokens as query parameters
- Session IDs in URL (jsessionid, PHPSESSID)
- API keys in GET request URLs
- Permanent tokens in bookmarkable URLs

### 2. Session IDs in URLs

**What to examine:**
- Session management implementation
- Cookie-less session fallbacks
- URL rewriting for sessions
- Cross-site session handling

**Risk indicators:**
- Framework configured for URL sessions
- jsessionid, sid, or similar in URLs
- Session tokens in redirects
- Mobile app deep links with sessions

### 3. PII in URLs

**What to examine:**
- User identifiers in paths
- Email addresses in parameters
- Phone numbers in URLs
- Personal data in search/filter params

**Risk indicators:**
- /users/john.doe@email.com patterns
- ?email=user@domain.com parameters
- Social security numbers in URLs
- Financial data in query strings

### 4. Referrer Header Leakage

**What to examine:**
- Links to external sites
- Embedded third-party content
- Referrer-Policy headers
- Cross-origin resource loading

**Risk indicators:**
- Missing Referrer-Policy header
- External links from authenticated pages
- Third-party scripts on sensitive pages
- Analytics/tracking pixels receiving full URLs

### 5. Browser History Exposure

**What to examine:**
- Sensitive URLs in browser history
- Shared device scenarios
- Browser sync implications
- Autocomplete data

**Risk indicators:**
- Tokens in URLs that persist in history
- Sensitive operations via GET requests
- Password reset links bookmarkable
- Session URLs shareable

## Attack Patterns

### Token Theft via Referrer

```
Attack Vector:
1. Authenticated page contains link to external site
2. User clicks link while URL contains token
3. External site receives full URL in Referrer header
4. Attacker extracts token from Referrer logs

Detection Points:
- Check for external links on authenticated pages
- Verify Referrer-Policy header
- Look for tokens in current URL patterns
```

### Session Hijacking via Shared URL

```
Attack Vector:
1. Session ID embedded in URL
2. User shares URL (copy/paste, bookmark, etc.)
3. Recipient gains user's session
4. Session compromise without credentials

Detection Points:
- Check session management configuration
- Look for session in URL patterns
- Verify cookie-only session handling
```

### Credential Leakage via Logs

```
Attack Vector:
1. Credentials/tokens passed as URL parameters
2. Logged by proxy servers, load balancers, CDN
3. Logs accessed by attacker or leaked
4. Mass credential compromise from logs

Detection Points:
- Audit URL parameter usage
- Check proxy/CDN logging configuration
- Verify sensitive params use POST/headers
```

### Password Reset Token Exposure

```
Attack Vector:
1. Password reset token in URL
2. User clicks reset link, lands on page
3. Page contains external resources or links
4. Token leaked via Referrer or shared

Detection Points:
- Check reset link format
- Verify Referrer-Policy on reset page
- Look for external resources on reset page
```

## Audit Methodology

### Phase 1: URL Pattern Analysis

```
1. Identify all URL patterns in the application
2. Catalog query parameters and path segments
3. Find tokens, IDs, and PII in URLs
4. Map authentication/session URL usage
```

### Phase 2: Referrer Policy Review

```
1. Check Referrer-Policy header configuration
2. Identify external links from sensitive pages
3. Find third-party resources loaded
4. Verify referrer control on forms
```

### Phase 3: Log Exposure Analysis

```
1. Identify all logging points for URLs
2. Check proxy/CDN logging configuration
3. Review access log retention
4. Verify log access controls
```

### Phase 4: Token Lifecycle Review

```
1. Track token generation and transmission
2. Identify token exposure points
3. Verify token invalidation
4. Check for short-lived tokens
```

## Code Patterns to Identify

### Token in URL

```python
# Vulnerable: token in query parameter
def generate_auth_link(user):
    token = generate_token(user)
    return f"https://app.com/login?token={token}"  # Token in URL

# Secure: token in cookie/header after redirect
def generate_auth_link(user):
    code = generate_short_code(user)
    return f"https://app.com/login?code={code}"  # Short-lived code

def handle_login(code):
    user = validate_code(code)  # Code exchanged for cookie-based session
    set_session_cookie(user)
```

### Session in URL

```java
// Vulnerable: URL rewriting enabled
// web.xml
<session-config>
    <tracking-mode>URL</tracking-mode>  // Sessions in URL
</session-config>

// Secure: cookie-only sessions
<session-config>
    <tracking-mode>COOKIE</tracking-mode>
    <cookie-config>
        <http-only>true</http-only>
        <secure>true</secure>
    </cookie-config>
</session-config>
```

### Missing Referrer Policy

```html
<!-- Vulnerable: no referrer policy, leaks full URL -->
<html>
<head>
    <title>Dashboard</title>
</head>
<body>
    <a href="https://external-site.com">External Link</a>
</body>
</html>

<!-- Secure: strict referrer policy -->
<html>
<head>
    <meta name="referrer" content="strict-origin-when-cross-origin">
    <title>Dashboard</title>
</head>
<body>
    <a href="https://external-site.com" referrerpolicy="no-referrer">External Link</a>
</body>
</html>
```

### PII in URL

```python
# Vulnerable: PII in URL
@app.route('/users/<email>')
def get_user(email):
    return User.query.filter_by(email=email).first()

# Secure: opaque identifiers
@app.route('/users/<user_id>')
def get_user(user_id):
    return User.query.get(user_id)
```

### Password Reset Token Exposure

```python
# Vulnerable: long-lived token in URL, no referrer protection
def send_reset_email(user):
    token = generate_reset_token(user, expires_in=86400)  # 24 hours
    link = f"https://app.com/reset?token={token}"
    send_email(user.email, f"Reset your password: {link}")

# Secure: short-lived, one-time, with referrer protection
def send_reset_email(user):
    token = generate_reset_token(user, expires_in=900, one_time=True)  # 15 min
    link = f"https://app.com/reset/{token}"  # Token in path, not query
    send_email(user.email, f"Reset your password: {link}")
    # Reset page includes: Referrer-Policy: no-referrer
```

### API Key in URL

```javascript
// Vulnerable: API key in URL
fetch(`https://api.example.com/data?api_key=${API_KEY}`)

// Secure: API key in header
fetch('https://api.example.com/data', {
    headers: {
        'Authorization': `Bearer ${API_KEY}`
    }
})
```

## Questions to Answer

1. Are authentication tokens ever passed in URLs?
2. Are session IDs transmitted via URL parameters?
3. Is there PII (email, phone, SSN) in URL paths or parameters?
4. Is a Referrer-Policy header configured?
5. Do authenticated pages link to external sites?
6. Are password reset tokens in URLs short-lived?
7. Are API keys passed as query parameters?
8. Do proxy/CDN logs capture sensitive URL parameters?
9. Can sensitive URLs be bookmarked or shared?
10. Are sensitive operations using GET instead of POST?

## Output Format

For each identified exposure, document:

```
## [Category]: [Specific Finding]

**Severity:** Critical/High/Medium/Low
**Data Type:** Token/Session/PII
**Location:** URL pattern/endpoint

### Exposure Vector
[How sensitive data is exposed in URL]

### Leakage Channels
[Where the URL could be leaked: Referrer/Logs/History/etc.]

### Impact
[Potential harm from exposure]

### Evidence
[Specific URL patterns showing the issue]

### Remediation
[Specific changes needed]

### Verification
[How to confirm the fix]
```

## Security Headers Checklist

```http
# Essential headers for URL data protection
Referrer-Policy: strict-origin-when-cross-origin
# Or for sensitive pages:
Referrer-Policy: no-referrer

# Prevent caching of sensitive URLs
Cache-Control: no-store, private
```

## URL Data Exposure Checklist

- [ ] No authentication tokens in URL parameters
- [ ] Sessions managed via cookies, not URL
- [ ] No PII in URL paths or query strings
- [ ] Referrer-Policy header configured
- [ ] External links use rel="noreferrer"
- [ ] Password reset tokens are short-lived
- [ ] API keys transmitted via headers
- [ ] Sensitive pages block caching
- [ ] GET requests don't modify state
- [ ] Proxy/CDN logs redact sensitive params
- [ ] No sensitive URLs in browser history
- [ ] OAuth tokens use POST for token exchange

---

# Detection Methodology

# Tokens and Secrets in URL Detection

Detect session tokens, API keys, reset tokens, JWTs, or other secrets in URL
query parameters or path segments. Tokens in URLs leak via Referer headers,
browser history, server/proxy/CDN access logs, and URL shortener databases.

## Methodology

### Step 1 — Identify Token-Bearing URL Patterns

Scan route definitions, URL builders, redirect constructors, and link generators
for parameters carrying auth material.

```javascript
// VULNERABLE — session token as query param
app.get("/dashboard", (req, res) => {
  const token = req.query.token;
  const session = validateToken(token);
});
// VULNERABLE — API key in path segment
router.get("/api/data/:apiKey/records", dataController.getRecords);
```

```python
# VULNERABLE — reset token as GET param, no expiry check
# /reset-password/?token=abc123def456
path("reset-password/", views.reset_password, name="reset_password"),
```

```java
// VULNERABLE — API key as query parameter
@GetMapping("/api/v1/data")
public ResponseEntity<List<Data>> getData(@RequestParam("api_key") String apiKey) {
    validateApiKey(apiKey);
    return ResponseEntity.ok(dataService.findAll());
}
```

```python
# VULNERABLE — JWT in query string
@app.route("/api/export")
def export_data():
    token = request.args.get("jwt")
    payload = decode_jwt(token)
    return generate_export(payload["user_id"])
```

### Step 2 — Trace Redirect Chains

Redirects leak tokens via Referer. When a page with `?token=X` loads external
resources, the full URL is sent in the Referer header.

```javascript
// VULNERABLE — redirect preserves token in query string
app.get("/auth/callback", (req, res) => {
  const accessToken = exchangeCode(req.query.code);
  res.redirect(`/app?access_token=${accessToken}`);
});
// SAFE — token in HttpOnly cookie, clean redirect
app.get("/auth/callback", (req, res) => {
  const accessToken = exchangeCode(req.query.code);
  res.cookie("session", accessToken, { httpOnly: true, secure: true });
  res.redirect("/app");
});
```

Multi-hop redirects compound the risk — each hop logs the full URL:
`/login?token=X -> 302 /verify?token=X -> 302 /dashboard?token=X`

### Step 3 — Check OAuth Flows for Token Placement

Fragment (`#`) values are not sent in Referer; query (`?`) values are.

```python
# VULNERABLE — response_mode=query with token response type
OAUTH_CONFIG = {
    "response_type": "token",
    "response_mode": "query",  # token after ?, leaked via Referer
}
# SAFER — fragment mode (implicit flow still deprecated; use code+PKCE)
OAUTH_CONFIG = {
    "response_type": "token",
    "response_mode": "fragment",  # token after #, not in Referer
}
```

### Step 4 — Inspect URL Construction in Frontend Code

Search client-side JS for token interpolation into URLs.

```javascript
// VULNERABLE — API key in fetch URL
await fetch(`https://api.example.com/data?api_key=${API_KEY}&q=${q}`);
// VULNERABLE — share link embeds auth token
function getShareLink(docId) {
  return `${origin}/doc/${docId}?token=${authToken}`;
}
// VULNERABLE — token in browser history via navigation
window.location.href = `/dashboard?session_token=${token}`;
```

### Step 5 — Evaluate Token Lifetime and Scope

| Property  | Lower Risk             | Higher Risk                |
|-----------|------------------------|----------------------------|
| Lifetime  | < 15 min               | Hours/days/no expiry       |
| Usage     | Single-use             | Reusable                   |
| Scope     | Single action          | Full session/API access    |
| Rotation  | Per-request            | Static/long-lived          |

```python
# BY_DESIGN — pre-signed S3 URL, 5-min expiry, single object
url = s3.generate_presigned_url("get_object",
    Params={"Bucket": "docs", "Key": "report.pdf"}, ExpiresIn=300)
# VULNERABLE — permanent API key in URL
url = f"https://api.example.com/v1/data?key={PERMANENT_API_KEY}"
```

### Step 6 — Check Server Access Log Configuration

Most defaults (nginx combined, Apache, cloud LBs) log the full request URI.

```nginx
# Default nginx — logs full query string
log_format combined '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent"';
# GET /api?token=secret123 -> token in log file
```

```python
# Common Django middleware — logs full path including tokens
class RequestLoggingMiddleware:
    def __call__(self, request):
        logger.info(f"Request: {request.method} {request.get_full_path()}")
        return self.get_response(request)
```

### Step 7 — Inspect URL Shortener and Caching Behavior

```javascript
// VULNERABLE — shortener stores full URL with embedded token permanently
async function createShareLink(docId) {
  const fullUrl = `https://app.example.com/doc/${docId}?auth=${token}`;
  return await urlShortener.shorten(fullUrl);
}
```

Token-bearing URLs must not be cacheable by proxies:

```python
# VULNERABLE — no Cache-Control, proxies may cache keyed by full URL
@app.route("/api/report")
def get_report():
    token = request.args.get("token")
    validate(token)
    return jsonify(report_data)
# SAFE — no-store prevents proxy caching
resp.headers["Cache-Control"] = "no-store"
```

## Decision Tree

```
START
  |
  v
URL contains token/key/secret in query string or path?
  |NO            |YES
  v              v
SAFE          Token in fragment (#) only, never in query/path?
                |YES           |NO
                v              v
             HARDENED       Token lifetime?
             (Low)            |
                    +---------+---------+
                    |                   |
                 <= 15 min           > 15 min or
                 AND single-use      no expiry
                    |                   |
                    v                   v
                 Pre-signed URL?     Token type?
                  |YES   |NO         |          |         |        |
                  v      v        Session    API key   Reset    JWT/Bearer
               BY_    HARDENED    token                token
               DESIGN (Medium)      |          |         |        |
                                    v          v         v        v
                                 VULN       VULN      VULN     VULN
                                 (Crit)     (High)    (High)   (Crit)
                                    |
                                    v
                              Also leaks via Referer to external origins?
                                |YES          |NO
                                v             v
                             Escalate      Keep original
                             severity      severity
```

## Real-World Examples

### Example 1 — Session Token in Query Parameter (Express)

```javascript
function authenticate(req, res, next) {
  const token = req.query.token || req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  req.user = jwt.verify(token, SECRET);
  next();
}
// Users bookmark: https://app.example.com/dashboard?token=eyJhbGci...
// Appears in: browser history, server logs, Referer headers, proxy logs
```

**Why vulnerable:** The JWT in the query string is a long-lived session token.
Every system seeing the URL captures a valid credential. On shared computers the
token persists in browser history indefinitely.

**Impact:** Critical. Session hijacking via log access, browser history, shoulder
surfing, or Referer leakage across the token's entire lifetime.

**Fix:** Accept tokens only via `Authorization` header or HttpOnly Secure cookie.

### Example 2 — Password Reset Token Without Expiry (Django)

```python
def request_reset(request):
    user = User.objects.get(email=request.POST["email"])
    token = secrets.token_urlsafe(32)
    user.reset_token = token  # no expiry, no single-use
    user.save()
    send_mail("Reset", f"https://app.example.com/reset-password/?token={token}",
              None, [user.email])

def reset_password(request):
    token = request.GET.get("token")  # GET query string
    user = User.objects.get(reset_token=token)
    if request.method == "POST":
        user.set_password(request.POST["new_password"])
        user.save()  # token NOT invalidated
```

**Why vulnerable:** No expiry, no single-use invalidation. The token persists in
server logs, proxy logs, and browser history permanently. Any log access yields
a permanent password reset capability.

**Impact:** High. Permanent account takeover via any log source.

**Fix:** Add 15-min expiry, invalidate after use, move token to path segment.

### Example 3 — API Key Leaked via Redirect Chain (Flask)

```python
@app.route("/proxy/weather")
def weather_proxy():
    api_key = os.environ["WEATHER_API_KEY"]
    upstream = f"https://api.weather.com/v1/forecast?key={api_key}&city={city}"
    resp = requests.get(upstream)  # follows redirects by default
    return jsonify(resp.json())
# Upstream 301 -> https://cdn.weather.com/...?key=abc123
# CDN access log now contains the permanent API key
```

**Why vulnerable:** Permanent API key in URL query string. The requests library
follows redirects, sending the full URL (with key) to the redirect target. Key
appears in access logs at every hop in the chain.

**Impact:** High. Permanent key compromise. Any party with log access at any hop
can use the key until rotation.

**Fix:** Send key in `Authorization` header; set `allow_redirects=False`.

## Common False Positive Patterns

1. **Pre-signed cloud storage URLs with short expiry.** S3 pre-signed URLs, GCS
   signed URLs, Azure SAS tokens are designed this way. Under 15 min expiry and
   single-object scope = BY_DESIGN.

2. **One-time email verification links.** `/verify-email?token=abc123` with
   single-use and sub-24h expiry is standard. Verify invalidation and expiry
   before classifying as SAFE.

3. **CSRF tokens in form action URLs.** Not session credentials; tied to a
   specific form submission. SAFE.

4. **Webhook verification tokens.** `/webhooks/stripe?verify=whsec_abc123` for
   setup-time endpoint verification. Short-lived, single-purpose. BY_DESIGN.

5. **OAuth authorization codes (not tokens).** `/callback?code=abc123` per
   RFC 6749 is single-use, short-lived, requires client secret. BY_DESIGN. Only
   flag if code has no expiry or is reusable.

6. **UUID path segments that are resource IDs, not tokens.** `/documents/a3f8b2c1`
   may look like a token but is a non-secret identifier behind authentication.
   Check if the ID alone grants access (bearer) vs requires separate auth. SAFE
   if auth-gated.

7. **Synthetic tokens in test/dev code.** `test_token_123` in test directories
   and fixtures is not real credential exposure.
