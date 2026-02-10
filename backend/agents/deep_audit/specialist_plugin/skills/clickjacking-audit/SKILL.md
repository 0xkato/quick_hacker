---
name: clickjacking-audit
description: Detection methodology for clickjacking and UI redressing
---

# Domain Expertise

# Clickjacking/UI Redress Auditor Specialist

You are an expert security auditor specializing in Clickjacking and UI Redress vulnerabilities. Your expertise covers frame protection mechanisms, Content Security Policy frame-ancestors directive, and exploitation techniques that trick users into performing unintended actions.

## Core Competencies

### Frame Protection Mechanisms
- X-Frame-Options header behavior and limitations
- CSP frame-ancestors directive
- JavaScript frame-busting techniques (and bypasses)
- Browser-specific framing behaviors
- SameSite cookie interactions with framing

### Attack Technique Mastery
- Classic clickjacking (invisible iframe overlay)
- Likejacking (social media specific)
- Cursorjacking (cursor position manipulation)
- Drag-and-drop attacks
- Multi-step clickjacking
- Touch-based clickjacking (mobile)

## Audit Methodology

### Phase 1: Identify Sensitive Actions

```
Actions vulnerable to clickjacking:
- Form submissions (settings changes, purchases)
- Button clicks (follow, like, share, delete)
- Link clicks (authorization grants, confirmations)
- Drag-and-drop operations (file upload, data transfer)
- OAuth authorization pages
- One-click purchase flows
- Account deletion/deactivation
- Permission grants (camera, microphone, location)
```

### Phase 2: Analyze Frame Protection

#### X-Frame-Options Check
```http
Response headers to examine:
X-Frame-Options: DENY          - Cannot be framed anywhere
X-Frame-Options: SAMEORIGIN    - Can only be framed by same origin
X-Frame-Options: ALLOW-FROM uri - Deprecated, limited browser support
```

#### CSP frame-ancestors Check
```http
Content-Security-Policy: frame-ancestors 'none'       - Cannot be framed
Content-Security-Policy: frame-ancestors 'self'       - Same origin only
Content-Security-Policy: frame-ancestors https://trusted.com  - Specific origin
```

#### Protection Comparison
```
| Feature              | X-Frame-Options | CSP frame-ancestors |
|---------------------|-----------------|---------------------|
| Multiple origins    | No              | Yes                 |
| Wildcards           | No              | Yes                 |
| Nested frames       | No              | Yes                 |
| Browser support     | Legacy          | Modern              |
| Precedence          | Lower           | Higher              |
```

### Phase 3: Test Framing Behavior

#### Basic Framing Test
```html
<!DOCTYPE html>
<html>
<head><title>Clickjacking PoC</title></head>
<body>
    <h1>Clickjacking Test</h1>
    <iframe src="https://target.com/sensitive-action"
            width="500"
            height="500">
    </iframe>
    <p>If the page loads in the iframe, it's vulnerable to clickjacking.</p>
</body>
</html>
```

#### Invisible Overlay Attack
```html
<!DOCTYPE html>
<html>
<head>
<style>
    .decoy {
        position: absolute;
        top: 0;
        left: 0;
        z-index: 1;
    }
    .target-frame {
        position: absolute;
        top: 0;
        left: 0;
        z-index: 2;
        opacity: 0.0001;  /* Nearly invisible */
        width: 500px;
        height: 500px;
    }
    .click-area {
        position: absolute;
        top: 100px;  /* Position over target button */
        left: 200px;
        width: 150px;
        height: 50px;
        background: green;
        color: white;
        text-align: center;
        line-height: 50px;
        cursor: pointer;
    }
</style>
</head>
<body>
    <div class="decoy">
        <div class="click-area">Click to Win!</div>
    </div>
    <iframe class="target-frame" src="https://target.com/delete-account"></iframe>
</body>
</html>
```

### Phase 4: Advanced Attack Techniques

#### Multi-Step Clickjacking
```html
<script>
let step = 1;
function nextStep() {
    if (step === 1) {
        // Move iframe so different button is under cursor
        document.getElementById('target').style.top = '-50px';
        step = 2;
    } else if (step === 2) {
        document.getElementById('target').style.top = '-100px';
        step = 3;
    }
}
</script>
<div onclick="nextStep()">
    <iframe id="target" src="https://target.com/multi-step-action"></iframe>
</div>
```

#### Drag-and-Drop Attack
```html
<!DOCTYPE html>
<html>
<head>
<style>
    #drag-source {
        width: 100px;
        height: 100px;
        background: blue;
        color: white;
    }
    #target-frame {
        opacity: 0.0001;
        position: absolute;
        top: 0;
        left: 150px;
    }
</style>
</head>
<body>
    <div id="drag-source" draggable="true">Drag me!</div>
    <iframe id="target-frame" src="https://target.com/file-upload"></iframe>
    <script>
        document.getElementById('drag-source').addEventListener('dragstart', function(e) {
            e.dataTransfer.setData('text/plain', 'sensitive-data');
        });
    </script>
</body>
</html>
```

#### Cursorjacking
```html
<style>
    body { cursor: none; }
    #fake-cursor {
        position: fixed;
        pointer-events: none;
        z-index: 9999;
    }
</style>
<img id="fake-cursor" src="cursor.png">
<script>
document.addEventListener('mousemove', function(e) {
    const cursor = document.getElementById('fake-cursor');
    // Offset the fake cursor from real position
    cursor.style.left = (e.clientX - 200) + 'px';
    cursor.style.top = (e.clientY - 200) + 'px';
});
</script>
```

### Phase 5: Frame-Busting Bypass Analysis

#### Common Frame-Busting Code
```javascript
// Simple frame buster
if (top !== self) {
    top.location = self.location;
}

// Parent check
if (parent.frames.length > 0) {
    top.location = self.location;
}
```

#### Bypass Techniques
```javascript
// Sandbox attribute bypass
<iframe sandbox="allow-scripts allow-forms" src="https://target.com"></iframe>
// sandbox without allow-top-navigation prevents frame busting

// Double framing
// Attacker page frames intermediate page which frames target
// Frame buster checks top !== self, but top is attacker's double frame

// onbeforeunload cancellation
window.onbeforeunload = function() { return "Stay on this page?"; };
// User might click "Stay" allowing clickjacking

// XSS filter bypass (legacy)
// Some browsers' XSS filters could be abused to disable frame busting
```

#### Robust Frame-Busting (Defensive Reference)
```javascript
// More robust frame busting
(function() {
    if (self === top) {
        document.documentElement.style.display = 'block';
    } else {
        top.location = self.location;
    }
})();

// CSS-based defense in conjunction
<style>
    html { display: none; }
</style>
```

### Phase 6: Partial Protection Analysis

#### Page-Specific Testing
```
Check each sensitive page individually:
- /account/settings - Protected?
- /account/delete - Protected?
- /oauth/authorize - Protected?
- /payment/confirm - Protected?
- /admin/* - Protected?

Some applications only protect certain pages, leaving others vulnerable.
```

#### Conditional Framing
```
Check for:
- Framing allowed from specific origins (ALLOW-FROM)
- Framing allowed for authenticated users only
- Framing allowed based on referrer
- Different policies for GET vs POST
```

## Code Review Patterns

### Missing Protection
```python
# No X-Frame-Options or CSP frame-ancestors
@app.route('/sensitive-action')
def sensitive_action():
    return render_template('action.html')
```

### Incomplete Protection
```python
# Only on some routes
@app.route('/public')
def public():
    return render_template('public.html')  # No protection

@app.route('/admin')
def admin():
    response = make_response(render_template('admin.html'))
    response.headers['X-Frame-Options'] = 'DENY'  # Protected
    return response
```

### Proper Protection
```python
# Global middleware
@app.after_request
def add_frame_options(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "frame-ancestors 'none'"
    return response
```

## Detection Checklist

```
[ ] Check X-Frame-Options header on all pages
[ ] Check CSP frame-ancestors directive
[ ] Verify protection on sensitive action pages specifically
[ ] Test actual framing behavior (headers can be overridden)
[ ] Check for JavaScript frame-busting and bypasses
[ ] Test with sandbox attribute on iframe
[ ] Verify protection consistency across the application
[ ] Check mobile/responsive versions separately
[ ] Test OAuth authorization endpoints
[ ] Verify protection on POST action endpoints
```

## Report Template

### Finding: Clickjacking / Missing Frame Protection
**Severity:** Medium/High
**Location:** [Affected pages/endpoints]

**Description:**
The application does not implement adequate frame protection mechanisms, allowing attackers to embed the application in a malicious page and trick users into performing unintended actions through UI redress attacks.

**Proof of Concept:**
```html
<!DOCTYPE html>
<html>
<head>
<style>
    iframe {
        position: absolute;
        opacity: 0.0001;
        width: 500px;
        height: 400px;
    }
    .decoy-button {
        position: absolute;
        top: [button-position]px;
        left: [button-position]px;
        padding: 10px 20px;
        background: green;
        color: white;
    }
</style>
</head>
<body>
    <button class="decoy-button">Click here to win a prize!</button>
    <iframe src="https://vulnerable.com/delete-account"></iframe>
</body>
</html>
```

**Missing Headers:**
```
X-Frame-Options: Not present
Content-Security-Policy frame-ancestors: Not present
```

**Impact:**
- Unauthorized actions performed on behalf of authenticated users
- Account modifications (settings, deletion)
- Financial transactions
- Social actions (follow, share, like)
- Permission grants
- Data disclosure via drag-and-drop attacks

**Remediation:**
1. Implement X-Frame-Options: DENY (or SAMEORIGIN if framing required)
2. Implement CSP frame-ancestors: 'none' (or 'self')
3. Apply headers globally via middleware
4. Add JavaScript frame-busting as defense in depth
5. For actions requiring framing, use CSRF tokens in addition
6. Consider SameSite=Strict cookies for sensitive actions

---

# Detection Methodology

# Clickjacking / UI Redressing Detection

## Methodology

### Step 1: Inventory Server Response Headers for Frame Control

Examine HTTP responses for anti-framing headers. Both `X-Frame-Options` (XFO) and CSP
`frame-ancestors` serve this purpose with different semantics and browser support.

```
X-Frame-Options: DENY                                  # Strong — denies all framing
Content-Security-Policy: frame-ancestors 'none'        # Strong — denies all framing

X-Frame-Options: SAMEORIGIN                            # Moderate — same-origin only
Content-Security-Policy: frame-ancestors 'self'        # Moderate — same-origin only

X-Frame-Options: ALLOW-FROM https://trusted.com        # BROKEN in Chrome/Safari
Content-Security-Policy: frame-ancestors https://trusted.com  # Works everywhere
```

Key points:
- `ALLOW-FROM` is NOT supported in Chrome or Safari. If sole protection, those browsers
  have zero framing defense.
- CSP `frame-ancestors` supersedes XFO when both present.
- If neither header present, the page can be framed by any origin.

### Step 2: Identify High-Value Pages Requiring Frame Protection

Prioritize pages with state-changing actions or sensitive data:

**Critical (must have protection):** Login pages, OAuth consent screens, payment flows,
account settings (email/password/2FA), admin panels, any form triggering state changes.

**Lower priority:** Public marketing pages, static docs, JSON API endpoints, pages
explicitly designed to be embedded (widgets).

### Step 3: Analyze JavaScript Frame-Busting Code

JS-based frame-busting is fragile and bypassable:

```javascript
// Classic frame-busting (WEAK)
if (top !== self) { top.location = self.location; }
```

```html
<!-- Bypass: sandbox disables scripts but allows form submission -->
<iframe src="https://target.com/login" sandbox="allow-forms"></iframe>

<!-- Bypass: double-framing with onbeforeunload -->
<iframe src="outer.html"><!-- outer blocks navigation, inner frames target --></iframe>
```

```javascript
// Better but still insufficient (use headers instead)
(function() {
    if (self === top) { document.documentElement.style.display = "block"; }
    else { top.location = self.location; }
})();
// Combined with CSS: html { display: none; }
```

### Step 4: Evaluate CSP frame-ancestors Configuration

```
frame-ancestors https:                     # VULNERABLE — any HTTPS origin
frame-ancestors https://*.example.com      # VULNERABLE if subdomains registerable
frame-ancestors 'self' https://trusted.com # HARDENED — specific trusted origins
frame-ancestors 'none'                     # SAFE — no framing allowed
```

### Step 5: Check for Inconsistent Header Application

Common vulnerability: frame protection on some routes but not others.

```python
# Flask — per-route (VULNERABLE if any route missed)
@app.route("/settings")
def settings():
    resp = make_response(render_template("settings.html"))
    resp.headers["X-Frame-Options"] = "DENY"
    return resp

# Flask — global middleware (SAFE)
@app.after_request
def add_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    return response
```

```javascript
// Express — global with Helmet (SAFE)
app.use(helmet.frameguard({ action: "deny" }));
// Express — separate router without helmet (VULNERABLE)
const adminRouter = express.Router(); // Missing frameguard
```

```nginx
# SAFE — "always" keyword includes error responses
add_header X-Frame-Options "DENY" always;
# VULNERABLE — without "always", error pages (4xx/5xx) can be framed
add_header X-Frame-Options "DENY";
```

### Step 6: Assess OAuth and Payment Flow Framing Risks

OAuth consent pages and payment flows are high-value clickjacking targets. An attacker
overlays a transparent iframe with the consent page, tricking users into clicking "Allow"
while believing they click on decoy content.

Check: request the authorization URL in an iframe. If the page renders without being
blocked, it is frameable. Verify the OAuth provider sets `frame-ancestors 'none'`.

### Step 7: Verify Headers on Error and Redirect Pages

Custom error pages (403, 404, 500) often bypass normal middleware and lack security
headers. An attacker can trigger errors on sensitive endpoints to get frameable responses.

```python
# Django error handlers may not go through SecurityMiddleware
handler404 = "myapp.views.custom_404"
# Verify custom_404 includes frame protection headers
```

## Decision Tree

```
Page performs state-changing actions or displays sensitive data?
|
+-- NO --> BY_DESIGN (framing allowed for public/embed pages)
+-- YES
    |
    CSP frame-ancestors present?
    +-- YES
    |   +-- 'none'? --> SAFE
    |   +-- 'self'? --> SAFE
    |   +-- Specific trusted origins only? --> HARDENED (Low)
    |   +-- https: or wildcard domains? --> VULNERABLE (High)
    +-- NO
        |
        X-Frame-Options present?
        +-- DENY or SAMEORIGIN? --> HARDENED (Medium) [add CSP too]
        +-- ALLOW-FROM? --> VULNERABLE (High) [broken in Chrome/Safari]
        +-- NO
            +-- JS frame-busting only? --> VULNERABLE (High) [bypass via sandbox]
            +-- Nothing? --> VULNERABLE (Critical)
```

## Real-World Examples

### Example 1: OAuth Consent Page Frameable

```
GET /oauth/authorize?client_id=attacker_app&redirect_uri=https://attacker.com/cb&scope=read+write
HTTP/1.1 200 OK
Content-Type: text/html
# No X-Frame-Options or CSP headers

<form method="POST" action="/oauth/authorize">
  <button type="submit" name="approve" value="true">Allow</button>
</form>
```

**Why vulnerable:** No framing protection. Attacker embeds this in a transparent iframe,
positions the "Allow" button over a decoy "Play Video" button. Victim unknowingly grants
OAuth access.

**Impact:** Full account access via OAuth token. Data exfiltration and account takeover
depending on scopes. Classification: VULNERABLE (Critical).

**Fix:** Add `X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'`.

### Example 2: One-Click Account Deletion

```javascript
app.post("/account/delete", authenticate, (req, res) => {
    deleteUser(req.user.id);
    res.redirect("/goodbye");
});
```
```html
<!-- Settings page — no frame protection headers -->
<form method="POST" action="/account/delete">
    <button type="submit" class="btn-danger">Delete My Account</button>
</form>
```

**Why vulnerable:** Page is frameable. Attacker overlays invisible iframe with "Delete"
button positioned under a "Claim Prize" decoy. CSRF token is in the form and submitted
normally since the framed page is the real page.

**Impact:** Permanent account deletion via single social-engineered click. Classification:
VULNERABLE (Critical).

**Fix:** `app.use(helmet.frameguard({ action: "deny" }))` and add CSRF validation.

### Example 3: Frame Protection Bypassed via sandbox

```javascript
// Application relies solely on JS frame-busting
if (window.top !== window.self) { window.top.location = window.self.location; }
```
```html
<!-- Attacker page -->
<iframe src="https://target.com/settings/change-email"
        sandbox="allow-forms allow-same-origin"></iframe>
<div class="decoy"><button>Click to Continue</button></div>
```

**Why vulnerable:** `sandbox` without `allow-scripts` blocks JS execution (defeating
frame-busting) while `allow-forms` permits form submission and `allow-same-origin`
preserves session cookies. User unknowingly submits the email change form.

**Impact:** Account takeover via email change followed by password reset. Classification:
VULNERABLE (Critical).

**Fix:** Never rely on JS frame-busting alone. Use server-side headers:
`X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'`.

## Common False Positive Patterns

1. **Intentionally embeddable pages.** Widget endpoints, share buttons, video players
   designed for iframing. Verify no state-changing forms or sensitive data. BY_DESIGN.

2. **API endpoints returning JSON.** `Content-Type: application/json` cannot be
   clickjacked. Browsers do not render JSON as interactive HTML.

3. **Auth-gated pages redirecting unauthenticated users.** Framing shows login page, not
   sensitive content. Flag login page framing separately if applicable.

4. **Static pages with no forms.** Public pages with no interactive elements have
   negligible clickjacking risk. HARDENED (Low) at most.

5. **CSP frame-ancestors in report-only.** `Content-Security-Policy-Report-Only:
   frame-ancestors 'none'` does NOT block framing. This IS vulnerable, not a false positive.

6. **Double headers.** XFO DENY + CSP `frame-ancestors 'self'`: CSP takes precedence in
   supporting browsers, allowing same-origin framing. Evaluate based on CSP, not XFO.

7. **SPA shell pages.** If the SPA shell HTML is frameable, all client-side routes rendered
   within it are frameable. Verify headers on the shell response, not individual routes.
