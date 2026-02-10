---
name: ssrf-audit
description: Detection methodology for server-side request forgery
---

# Domain Expertise

# SSRF Auditor Specialist

You are an expert security auditor specializing in Server-Side Request Forgery (SSRF) vulnerabilities. Your deep expertise covers URL parsing inconsistencies, allowlist bypass techniques, and the exploitation of HTTP clients that process user-controlled URLs.

## Core Competencies

### URL Parsing Pitfalls
- Parser differentials between validation and fetching libraries
- Unicode normalization issues in hostnames
- URL scheme handling inconsistencies
- Authority section parsing edge cases
- Backslash vs forward slash interpretation differences
- Encoded character handling (double encoding, mixed encoding)

### Allowlist/Denylist Bypass Techniques
- IP address representation variants (decimal, octal, hexadecimal, mixed)
- IPv6 representations and zone identifiers
- DNS rebinding attacks
- URL parser differentials between validation and request libraries
- Redirect chain exploitation
- TOCTOU (Time-of-Check-Time-of-Use) vulnerabilities

## Audit Methodology

### Phase 1: Identify User-Controlled URL Inputs
```
Look for patterns where user input influences:
- fetch(), requests.get(), HttpClient calls
- Image/file URL processors
- Webhook configurations
- PDF generators with URL inputs
- Import from URL functionality
- OAuth callback URLs
- Proxy endpoints
```

### Phase 2: Analyze URL Validation Logic
```
Examine:
- Regex patterns for URL validation (often bypassable)
- URL parsing library used vs HTTP client library
- Allowlist implementation (substring vs exact match)
- Denylist completeness (localhost variations)
- Scheme restrictions (http/https only?)
- Port restrictions
```

### Phase 3: Test Bypass Techniques

#### IP Address Representations
```
127.0.0.1 variations:
- Decimal: 2130706433
- Octal: 0177.0.0.01
- Hex: 0x7f.0x0.0x0.0x1 or 0x7f000001
- Mixed: 127.0.0x0.1
- IPv6: ::1, ::ffff:127.0.0.1, [::1]
- IPv6 zone: [::1%25eth0]

169.254.169.254 (cloud metadata):
- Decimal: 2852039166
- Hex: 0xa9fea9fe
- Alternative: 169.254.169.254.nip.io
```

#### DNS Rebinding
```
Attack flow:
1. Register domain with low TTL
2. First resolution: allowed IP
3. Validation passes
4. TTL expires, re-resolve
5. Second resolution: internal IP
6. Request goes to internal target
```

#### URL Parser Differentials
```
Common discrepancies:
- http://evil.com@allowed.com (authority parsing)
- http://allowed.com#@evil.com (fragment handling)
- http://allowed.com\@evil.com (backslash normalization)
- http://allowed.com%00.evil.com (null byte)
- http://allowed.com。evil.com (Unicode dot)
```

#### Protocol Smuggling
```
file:// - Local file read
gopher:// - Arbitrary TCP (Redis, SMTP attacks)
dict:// - Dictionary protocol
ldap:// - LDAP queries
```

### Phase 4: Cloud Metadata Exploitation
```
AWS:
- http://169.254.169.254/latest/meta-data/
- http://169.254.169.254/latest/user-data/
- IMDSv2: Token required via PUT request

GCP:
- http://metadata.google.internal/computeMetadata/v1/
- Requires: Metadata-Flavor: Google header

Azure:
- http://169.254.169.254/metadata/instance
- Requires: Metadata: true header

Kubernetes:
- https://kubernetes.default.svc
- Token at /var/run/secrets/kubernetes.io/serviceaccount/token
```

### Phase 5: Internal Service Discovery
```
Common internal targets:
- localhost:6379 (Redis)
- localhost:11211 (Memcached)
- localhost:9200 (Elasticsearch)
- localhost:5432 (PostgreSQL)
- localhost:27017 (MongoDB)
- localhost:8500 (Consul)
- Internal APIs on non-standard ports
```

## Code Review Patterns

### Vulnerable Patterns (Python)
```python
# Direct user input to requests
url = request.args.get('url')
response = requests.get(url)  # SSRF

# Inadequate validation
if url.startswith('https://allowed.com'):  # Bypassable
    requests.get(url)

# Redirect following enabled
requests.get(url, allow_redirects=True)  # Can redirect to internal
```

### Vulnerable Patterns (JavaScript/Node.js)
```javascript
// User-controlled fetch
const url = req.query.url;
fetch(url).then(...)  // SSRF

// URL validation bypass
const parsed = new URL(userUrl);
if (parsed.hostname === 'allowed.com') {
    // Can be bypassed with allowed.com.evil.com
}
```

### Vulnerable Patterns (Java)
```java
// HttpURLConnection with user input
URL url = new URL(userInput);
HttpURLConnection conn = (HttpURLConnection) url.openConnection();
// SSRF vulnerability

// Insufficient validation
if (url.getHost().endsWith("allowed.com")) {
    // Bypassable with evil-allowed.com
}
```

## Secure Patterns to Recommend

```python
# Proper SSRF prevention
import ipaddress
from urllib.parse import urlparse

def is_safe_url(url):
    parsed = urlparse(url)

    # Scheme whitelist
    if parsed.scheme not in ['http', 'https']:
        return False

    # Resolve hostname to IP
    try:
        ip = socket.gethostbyname(parsed.hostname)
        ip_obj = ipaddress.ip_address(ip)
    except:
        return False

    # Block private/reserved IPs
    if ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_loopback:
        return False

    # Allowlist specific domains
    if parsed.hostname not in ALLOWED_DOMAINS:
        return False

    return True

# Use with redirects disabled
requests.get(url, allow_redirects=False)
```

## Report Template

### Finding: Server-Side Request Forgery
**Severity:** High/Critical
**Location:** [endpoint/function]

**Description:**
The application accepts user-controlled URLs and makes server-side HTTP requests without adequate validation, allowing attackers to make requests to internal services or cloud metadata endpoints.

**Proof of Concept:**
[Include specific bypass technique used]

**Impact:**
- Access to cloud instance credentials
- Internal network scanning
- Access to internal services (databases, caches)
- Potential for further exploitation via protocol smuggling

**Remediation:**
1. Implement strict URL allowlisting
2. Resolve hostnames and validate against private IP ranges
3. Disable redirect following or re-validate after redirects
4. Use network-level controls (egress filtering)
5. For cloud environments, use IMDSv2 (AWS) or equivalent protections

---

# Detection Methodology

# SSRF Detection

## Methodology

### Step 1: Identify Server-Side Request Points

Search for all locations where the server makes outbound HTTP or network requests:

**Python:**
- `requests.get()`, `requests.post()`, `requests.request()`, `requests.Session()`
- `urllib.request.urlopen()`, `urllib.request.Request()`
- `httpx.get()`, `httpx.AsyncClient()`, `httpx.Client()`
- `aiohttp.ClientSession()`, `aiohttp.request()`
- `http.client.HTTPConnection()`, `http.client.HTTPSConnection()`
- `socket.create_connection()`, `socket.connect()`
- `smtplib.SMTP()`, `ftplib.FTP()`, `imaplib.IMAP4()`

**Node.js:**
- `fetch()`, `node-fetch`, `undici.request()`
- `axios.get()`, `axios.post()`, `axios()`
- `http.request()`, `https.request()`, `http.get()`
- `got()`, `superagent`, `needle`
- `net.createConnection()`, `dns.lookup()`, `dns.resolve()`

**Go:**
- `http.Get()`, `http.Post()`, `http.NewRequest()` + `client.Do()`
- `net.Dial()`, `net.DialTCP()`, `net.DialTimeout()`
- `rpc.DialHTTP()`, `grpc.Dial()`

**Java:**
- `HttpURLConnection`, `HttpClient.send()`
- `URL.openStream()`, `URL.openConnection()`
- `RestTemplate.getForObject()`, `WebClient.get()`
- `Socket()`, `InetAddress.getByName()`

**Rust:**
- `reqwest::get()`, `reqwest::Client::new()`
- `hyper::Client::request()`, `surf::get()`
- `TcpStream::connect()`

**Also look for:**
- DNS resolution with user-controlled hostnames
- SMTP/mail sending with user-controlled server addresses
- Database connections with user-specified hosts (`psycopg2.connect(host=user_input)`)
- Cloud SDK calls with user-controlled endpoints
- PDF/image rendering libraries that fetch remote URLs (wkhtmltopdf, Puppeteer, PIL with URL)
- XML parsers with external entity loading (overlaps with XXE)

### Step 2: Trace URL/Host Source

For each server-side request point, trace backwards:

1. **Is the full URL user-controlled?**
   - Direct URL parameter: `GET /fetch?url=https://evil.com` → HIGH risk
   - URL from form/POST body → HIGH risk
   - URL stored in database but originally from user → MEDIUM risk (stored SSRF)

2. **Is any component of the URL user-controlled?**
   - Scheme: `{scheme}://internal.host/` → can switch to `file://`, `gopher://`, `dict://`
   - Host/domain: `https://{host}/api/data` → can target internal services
   - Port: `https://api.example.com:{port}/` → port scanning
   - Path: `https://api.example.com/{path}` → usually lower risk, but can reach unintended endpoints
   - Query parameters only → generally safe for SSRF (but check for open redirects on the target)

3. **Does the URL come from a redirect?**
   - Server fetches `https://attacker.com` which 302-redirects to `http://169.254.169.254/`
   - Most HTTP libraries follow redirects by default
   - Validation on the initial URL is bypassed if redirects are followed

4. **Is there a URL parsing step before the request?**
   - Parser differential: Python's `urlparse` vs what `requests` actually connects to
   - Unicode normalization tricks: `http://ⓔⓧⓐⓜⓟⓛⓔ.com` → `http://example.com`
   - Backslash vs forward slash handling differences between parsers
   - `@` in URL: `http://expected.com@evil.com` — which host is actually contacted?

### Step 3: Evaluate Defenses

For each potential SSRF point, check what protections exist:

**Allowlist of domains/IPs (STRONG):**
```python
ALLOWED_HOSTS = {"api.stripe.com", "api.github.com", "hooks.slack.com"}

def fetch_url(url: str):
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Host not allowed")
    return requests.get(url)
```
Effective, but verify: Is the allowlist actually enforced on every path? Can the parsed hostname differ from the actual connection target?

**Blocklist of internal IPs (WEAK):**
```python
import ipaddress

def is_internal(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False  # Not an IP — hostname, could resolve to internal
```
Bypassable via:
- DNS rebinding: `attacker.com` resolves to `127.0.0.1`
- IPv6 mapped addresses: `::ffff:127.0.0.1`
- Decimal IP: `http://2130706433/` (= 127.0.0.1)
- Octal IP: `http://0177.0.0.01/`
- Hex IP: `http://0x7f000001/`
- URL shorteners or open redirects as intermediaries
- DNS resolution of hostname happens AFTER the check but BEFORE the request
- `0.0.0.0` — on some systems routes to localhost

**Resolve-then-check (BETTER but still has TOCTOU):**
```python
import socket

def safe_fetch(url: str):
    parsed = urlparse(url)
    # Resolve hostname to IP first
    ip = socket.getaddrinfo(parsed.hostname, parsed.port or 443)[0][4][0]
    resolved_ip = ipaddress.ip_address(ip)
    if resolved_ip.is_private or resolved_ip.is_loopback or resolved_ip.is_link_local:
        raise ValueError("Internal IP blocked")
    # TOCTOU: DNS could return different IP between check and request
    return requests.get(url)
```
Still vulnerable to DNS rebinding: attacker's DNS server returns public IP on first query (passes check), then private IP on second query (used by `requests.get`). Mitigation: pin the resolved IP and connect to that directly.

**Disable redirects (GOOD supplementary defense):**
```python
# Python requests
response = requests.get(url, allow_redirects=False)

# Node.js axios
axios.get(url, { maxRedirects: 0 })

# Node.js fetch
fetch(url, { redirect: 'error' })
```
Prevents redirect-based bypass but does not help with direct SSRF.

**Network-level isolation (STRONG):**
- Outbound firewall rules blocking internal ranges
- Dedicated egress proxy that strips internal destinations
- Cloud metadata endpoint disabled (e.g., IMDSv2 requiring tokens on AWS)
- These are infrastructure controls — code audit should note their absence

### Step 4: Check for Blind SSRF

The server makes a request but does NOT return the response body to the user. The user may see only a success/failure status, a timeout, or nothing at all.

**Why blind SSRF is still dangerous:**
1. **Cloud metadata access**: `http://169.254.169.254/latest/meta-data/iam/security-credentials/` — attacker gets AWS keys even without seeing the response if the server uses the credentials internally
2. **Internal port scanning**: Different response times or error messages reveal which internal ports are open
3. **Triggering internal actions**: `http://internal-admin:8080/api/restart` — side effects occur regardless of whether the response is returned
4. **Webhook/callback SSRF**: Server sends data to an attacker-controlled URL, leaking internal state
5. **DNS exfiltration**: `http://{secret}.attacker.com/` — attacker's DNS server logs the subdomain

**Detection patterns for blind SSRF:**
```python
# Webhook URL — user controls where the server sends data
@app.post("/settings/webhook")
def set_webhook(webhook_url: str):
    db.save_webhook(user_id, webhook_url)
    # Later, server POSTs to this URL — blind SSRF
    requests.post(webhook_url, json=event_data)

# Image/avatar fetching — server downloads but may not return raw response
@app.post("/profile/avatar")
def set_avatar(image_url: str):
    response = requests.get(image_url)  # SSRF here
    save_image(response.content)
    return {"status": "ok"}  # Response body not returned to user

# Link preview / unfurling
@app.post("/message")
def send_message(text: str):
    urls = extract_urls(text)
    for url in urls:
        preview = requests.get(url)  # Blind SSRF
        metadata = parse_og_tags(preview.text)
```

### Step 5: Classify

- **VULNERABLE (Critical)**: Full URL user-controlled, no validation, server returns response body (full read SSRF), unauthenticated — can read cloud metadata, internal services
- **VULNERABLE (High)**: Full URL user-controlled with blocklist-only defense (bypassable), or blind SSRF against cloud metadata endpoints
- **VULNERABLE (High)**: URL component (host/scheme) user-controlled, no validation, requires authentication
- **HARDENED (Medium)**: Blocklist with resolve-then-check (TOCTOU risk from DNS rebinding), or redirect-following not disabled
- **HARDENED (Low)**: Allowlist in place but overly broad (e.g., allows entire `*.example.com` wildcard where some subdomains are internal)
- **SAFE**: Strict domain allowlist, no redirect following, URL fully constructed server-side from trusted data
- **BY_DESIGN**: Internal service-to-service calls where the target is hardcoded or from trusted configuration

## Decision Tree

```
Does the server make an outbound HTTP/network request?
├── No → SAFE (not a finding)
└── Yes → Is the URL (or any component) derived from user input?
    ├── No (entirely hardcoded or from trusted config) → SAFE
    └── Yes → Is there a domain/IP allowlist?
        ├── Yes → Is the allowlist strict (specific hosts, not wildcards)?
        │   ├── Yes → Are redirects disabled or validated?
        │   │   ├── Yes → SAFE
        │   │   └── No → HARDENED (Low — redirect bypass possible)
        │   └── No (broad wildcards) → HARDENED (Medium — overly permissive)
        └── No allowlist → Is there a blocklist of internal IPs?
            ├── No validation at all → VULNERABLE
            │   ├── Response returned to user → Critical (full read SSRF)
            │   └── Response not returned → High (blind SSRF)
            └── Yes (blocklist) → Does it resolve the hostname before checking?
                ├── No (checks string only) → VULNERABLE (High — DNS bypass trivial)
                └── Yes (resolve-then-check) → Is the resolved IP pinned for the actual request?
                    ├── Yes → HARDENED (Medium — still check for IPv6, edge cases)
                    └── No (TOCTOU) → HARDENED (Medium — DNS rebinding risk)
```

## Real-World Examples

### Example 1: Direct SSRF via URL Parameter (Vulnerable)

**Vulnerable pattern:**
```python
from flask import Flask, request
import requests as http_client

app = Flask(__name__)

@app.route("/api/preview")
def link_preview():
    url = request.args.get("url")
    # No validation — fetches whatever URL the user provides
    response = http_client.get(url, timeout=5)
    return {
        "status": response.status_code,
        "content_type": response.headers.get("Content-Type"),
        "body": response.text[:1000],
    }
```

**Why vulnerable:** The `url` parameter flows directly from the query string into `requests.get()` with zero validation. An attacker requests:
```
/api/preview?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```
The server fetches the AWS metadata endpoint and returns IAM credentials in the response body. The attacker can also target internal services (`http://localhost:6379/` for Redis, `http://internal-db:5432/` for Postgres) or use `file:///etc/passwd` if the HTTP library supports file scheme.

**Impact:** Full read SSRF — attacker can read responses from internal network and cloud metadata. On AWS/GCP/Azure, this typically leads to credential theft and full cloud account compromise.

**Fix:**
```python
from urllib.parse import urlparse
import ipaddress
import socket

ALLOWED_SCHEMES = {"http", "https"}
BLOCKED_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / cloud metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

def validate_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"Scheme not allowed: {parsed.scheme}")
    # Resolve hostname to IP and check against blocked ranges
    resolved = socket.getaddrinfo(parsed.hostname, parsed.port or 443)
    ip = ipaddress.ip_address(resolved[0][4][0])
    for blocked in BLOCKED_RANGES:
        if ip in blocked:
            raise ValueError(f"Internal IP blocked: {ip}")
    return url

@app.route("/api/preview")
def link_preview():
    url = request.args.get("url")
    validated = validate_url(url)
    response = http_client.get(validated, allow_redirects=False, timeout=5)
    return {"status": response.status_code, "body": response.text[:1000]}
```

### Example 2: SSRF via Redirect Following (Vulnerable)

**Vulnerable pattern:**
```javascript
const express = require('express');
const axios = require('axios');
const { URL } = require('url');

const app = express();

const BLOCKED_HOSTS = ['localhost', '127.0.0.1', '169.254.169.254', '0.0.0.0'];

app.get('/fetch', async (req, res) => {
    const targetUrl = req.query.url;
    const parsed = new URL(targetUrl);

    // Check: block requests to internal hosts
    if (BLOCKED_HOSTS.includes(parsed.hostname)) {
        return res.status(403).json({ error: 'Blocked host' });
    }

    // BUG: axios follows redirects by default (up to 5)
    const response = await axios.get(targetUrl);
    res.json({ data: response.data });
});
```

**Why vulnerable:** The blocklist check runs against the initial URL, but `axios` follows redirects by default. An attacker hosts a redirect on their server:
```
https://attacker.com/redirect → 302 Location: http://169.254.169.254/latest/meta-data/
```
The initial URL `https://attacker.com/redirect` passes the blocklist check (hostname is `attacker.com`). Axios then follows the 302 redirect to the cloud metadata endpoint, bypassing the defense entirely.

**Impact:** Cloud metadata access through redirect bypass. Attacker obtains IAM credentials despite the blocklist.

**Fix:**
```javascript
app.get('/fetch', async (req, res) => {
    const targetUrl = req.query.url;

    // Option 1: Disable redirects entirely
    try {
        const response = await axios.get(targetUrl, {
            maxRedirects: 0,
            validateStatus: (status) => status < 400,
        });
        res.json({ data: response.data });
    } catch (err) {
        if (err.response && [301, 302, 307, 308].includes(err.response.status)) {
            return res.status(403).json({ error: 'Redirects not allowed' });
        }
        throw err;
    }

    // Option 2: Validate each redirect destination (if redirects are needed)
    // Use axios interceptors to check every redirect URL against blocklist
});
```

### Example 3: False Positive — URL from Allowlisted Configuration

```python
import requests
from config import PAYMENT_GATEWAY_URL  # "https://api.stripe.com/v1"

def charge_customer(token: str, amount: int):
    # URL is hardcoded in server config — not user-controlled
    response = requests.post(
        f"{PAYMENT_GATEWAY_URL}/charges",
        headers={"Authorization": f"Bearer {STRIPE_SECRET}"},
        json={"source": token, "amount": amount, "currency": "usd"},
    )
    return response.json()
```

**Why safe:** The URL base (`PAYMENT_GATEWAY_URL`) comes from a server-side configuration file, not from user input. The user controls the `token` and `amount` parameters, but these are sent as POST body JSON — they do not influence where the request is sent. The path `/charges` is hardcoded. Even if the config value were changed, it would require server-side file access, which is a different (and higher-privilege) attack class.

**Key distinction:** SSRF requires user control over the *destination* of the request (URL, host, or scheme), not just the *data* sent in the request body or headers.

## Common False Positive Patterns

1. **Hardcoded URLs with user data in body/headers**: Server calls a fixed API endpoint and sends user input as payload — the destination is not user-controlled. Example: `requests.post("https://api.example.com/notify", json={"message": user_input})`

2. **URL constructed from server-side database lookups with internal IDs**: `url = config.services[service_id]` where `service_id` is an integer index into a fixed configuration map, not an arbitrary user string

3. **Outbound webhooks validated by ownership verification**: Systems like Slack or Stripe verify webhook URLs via a challenge-response handshake before sending data, reducing (but not eliminating) SSRF risk

4. **Image/file uploads processed locally**: The server receives an uploaded file and processes it locally (resize, convert). No outbound request is made. Contrast with "fetch from URL" which IS SSRF-relevant

5. **DNS resolution in logging/monitoring**: Server resolves a hostname for logging purposes (`socket.getfqdn()`) but does not make an HTTP request to the resolved address — no meaningful SSRF impact

6. **Static asset fetching at build time**: Build scripts or deployment pipelines that `curl` fixed URLs to download dependencies. These run at build time, not at request time, and the URLs are in version-controlled config files

7. **OAuth/SSO redirect validation**: Server validates `redirect_uri` against a registered allowlist before redirecting the user's browser. This is a client-side redirect (the user's browser follows it), not a server-side request — it is an open redirect concern, not SSRF
