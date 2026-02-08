# CRLF Injection Detection

## Methodology

### Step 1: Identify HTTP Header Construction Points

CRLF injection occurs when user input containing `\r` (`%0d`) and `\n` (`%0a`) is included in HTTP response headers.

**Python (Flask / Django / FastAPI):**
```python
resp.headers['Location'] = user_url        # Injection target
return redirect(user_url)                  # Injection target
response['Set-Cookie'] = cookie_val        # Injection target
```

**Node.js (Express / native http):**
```javascript
res.set('Location', userUrl);              // Injection target
res.redirect(userUrl);                     // Injection target
res.setHeader('Location', userUrl);        // Injection target
```

**Java (Spring / Servlet):**
```java
response.setHeader("Location", userUrl);       // Injection target
response.sendRedirect(userUrl);                // Injection target
response.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");
```

### Step 2: Understand CRLF Injection Mechanics

HTTP headers are terminated by `\r\n`. Injecting CRLF allows:
1. **Additional headers** -- `Set-Cookie` injection for session fixation
2. **Body injection** -- double CRLF (`\r\n\r\n`) starts the response body
3. **Response splitting** -- create a second full HTTP response

```
# Header injection: /profile?user=alice%0d%0aSet-Cookie:%20admin=true
# Body injection: /page%0d%0a%0d%0a<script>alert(1)</script>
```

### Step 3: Trace User Input to Header Values

```python
# VULNERABLE: redirect from query param
@app.route('/redirect')
def redirect_handler():
    return redirect(request.args.get('url', '/'))

# VULNERABLE: reflecting request header in response
resp.headers['X-Request-Id'] = request.headers.get('X-Request-Id', '')

# VULNERABLE: reflecting origin in CORS
res.set('Access-Control-Allow-Origin', req.headers.origin);
```

### Step 4: Check Framework-Level Protections

| Framework | Version | Protection |
|---|---|---|
| Express 4.x | 4.x+ | Throws on `\n` in header values |
| Flask/Werkzeug | 2.1+ | Rejects CRLF in header values |
| Django | 3.2+ | Strips newlines from headers |
| Spring Boot | 5.1+ | URL-encodes Location for redirects |
| Node.js http | 14+ | Throws ERR_INVALID_CHAR |
| Tomcat | 8.5+ | Rejects CRLF in sendRedirect |

Raw socket writes (`socket.write`, `net.Socket`) bypass all framework protections.

### Step 5: Check for Encoded CRLF Bypasses

```
%0d%0a            standard URL-encoded CRLF
%250d%250a         double encoding (if app decodes twice)
%E5%98%8A%E5%98%8D UTF-8 overlong encoding
%0a                bare LF (some servers accept)
```

### Step 6: Assess Impact Context

Severity depends on the affected header and protocol. HTTP/2 uses binary framing (HPACK) and is not vulnerable to response splitting.

**Impact matrix by injected header:**
```
Set-Cookie        --> Session fixation, auth bypass (Critical)
Location          --> Open redirect + header injection (High)
Content-Type      --> MIME confusion, XSS via type override (High)
Content-Disposition --> Reflected file download (Medium)
X-Custom headers  --> Information leak, cache poisoning (Medium)
CORS headers      --> Cross-origin data theft (High)
```

## Decision Tree

```
User input reaches HTTP response header value?
|
+-- NO --> SAFE
|
+-- YES
    |
    Framework auto-rejects CRLF (modern version)?
    |
    +-- YES
    |   |
    |   Raw socket/stream writes bypass framework?
    |   +-- YES --> VULNERABLE (High)
    |   +-- NO  --> SAFE
    |
    +-- NO / UNKNOWN
        |
        Application strips \r and \n (including encoded variants)?
        +-- YES --> HARDENED (Low)
        +-- Partial --> HARDENED (Medium)
        +-- NO
            |
            +-- Set-Cookie affected --> VULNERABLE (Critical)
            +-- Location affected --> VULNERABLE (High)
            +-- Other headers --> VULNERABLE (High)
```

## Real-World Examples

### Example 1: Session Fixation via Location Header

```python
@app.route('/lang')
def set_language():
    next_url = request.args.get('next', '/')
    resp = redirect(next_url)
    resp.set_cookie('lang', request.args.get('lang', 'en'))
    return resp
```

**Why vulnerable:** On Flask/Werkzeug < 2.1, `next_url` goes directly into the Location header. Attacker crafts `next=/home%0d%0aSet-Cookie:%20session=attacker_session_id`. Victim receives injected session cookie; after login, attacker uses the same session ID.

**Impact:** Session fixation leading to account takeover.

**Fix:**
```python
from urllib.parse import urlparse
next_url = request.args.get('next', '/')
parsed = urlparse(next_url)
if parsed.netloc or '\r' in next_url or '\n' in next_url:
    next_url = '/'
return redirect(next_url)
```

### Example 2: Response Splitting in Legacy Node.js

```javascript
// Node.js < 14
http.createServer((req, res) => {
    const name = new URL(req.url, 'http://localhost').searchParams.get('name');
    res.writeHead(200, { 'X-Greeting': 'Hello ' + name });
    res.end('<h1>Welcome</h1>');
}).listen(3000);
```

**Why vulnerable:** Node.js < 14 does not validate header values. `name=Guest%0d%0a%0d%0a<script>alert(document.cookie)</script>` terminates headers and injects script.

**Impact:** XSS via response splitting. Cookie theft, session hijacking.

**Fix:**
```javascript
const safeName = (name || 'Guest').replace(/[\r\n]/g, '');
res.writeHead(200, { 'X-Greeting': 'Hello ' + safeName });
// Better: upgrade to Node.js 14+
```

### Example 3: Content-Disposition Injection in Java

```java
@GetMapping("/download")
public void downloadFile(@RequestParam String filename, HttpServletResponse response) {
    response.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");
    // ... stream file
}
```

**Why vulnerable:** `filename` injected into Content-Disposition. On older servlet containers: `filename=x%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>`.

**Impact:** Response splitting for XSS. Reflected file download attacks even without CRLF.

**Fix:**
```java
String safeName = record.getOriginalName().replaceAll("[^a-zA-Z0-9._-]", "_");
response.setHeader("Content-Disposition", "attachment; filename=\"" + safeName + "\"");
```

## Common False Positive Patterns

1. **Modern framework with CRLF rejection** -- Express 4.x, Flask 2.1+, Django 3.2+, Node.js 14+, Spring 5.1+ reject CRLF by default. Verify version.

2. **HTTP/2-only deployments** -- Binary framing prevents response splitting (but header injection semantics may still apply).

3. **Headers from internal/trusted sources** -- Response headers from database records or config files not user-controllable.

4. **Content-Disposition with server-generated filenames** -- UUID or ID-based filenames, not user input.

5. **CORS headers with whitelist validation** -- `Access-Control-Allow-Origin` from validated allowlist, not reflected Origin.

6. **Redirect URLs validated against allowlist** -- Target URL checked against allowed domains before setting Location.

7. **Logging of header values** -- Reading and logging request headers is a log injection concern (see `log_injection.md`), not CRLF response injection.
