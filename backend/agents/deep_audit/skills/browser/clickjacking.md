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
