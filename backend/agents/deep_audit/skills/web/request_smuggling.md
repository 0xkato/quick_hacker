# HTTP Request Smuggling Detection

## Methodology

### Step 1: Identify Proxy/Backend Architecture

Map the request processing chain to find desync opportunities:

**Reverse Proxies (Frontend):**
- Nginx: `proxy_pass`, `upstream` blocks
- HAProxy: `backend`, `server` directives
- AWS ALB/CLB, Cloudflare, Akamai, Fastly CDN edge servers
- Apache `mod_proxy`, Envoy, Traefik, Caddy

**Backend Servers:**
- Node.js (`http.createServer`, Express, Fastify) — historically permissive HTTP parsing
- Python (gunicorn, uvicorn, Werkzeug) — gunicorn handles chunked TE before WSGI
- Java (Tomcat, Jetty, Spring Boot embedded, WildFly/Undertow)
- Go (`net/http`) — strict by default but custom servers may differ

**Key questions:**
1. How many layers independently parse `Content-Length` (CL) and `Transfer-Encoding` (TE)?
2. Are persistent connections (keep-alive) enabled between layers?
3. Does HTTP/2 get downgraded to HTTP/1.1 anywhere in the chain?

### Step 2: Analyze CL.TE and TE.CL Desync

**CL.TE** — frontend uses Content-Length, backend uses Transfer-Encoding:
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

**TE.CL** — frontend uses Transfer-Encoding, backend uses Content-Length:
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

**Configuration checks:**
```nginx
# Nginx: uses CL by default for proxied requests
# If backend also processes TE → CL.TE possible
location / {
    proxy_pass http://backend:3000;
    proxy_http_version 1.1;         # Keep-alive enables smuggling
    proxy_set_header Connection ""; # Persistent connections
}
```

```
# AWS ALB processes TE: chunked, downgrades HTTP/2 to HTTP/1.1
# If backend ignores TE and uses CL → TE.CL desync
```

### Step 3: Analyze TE.TE Desync (Transfer-Encoding Obfuscation)

TE.TE occurs when both layers process TE but one can be tricked via obfuscation:

```http
Transfer-Encoding: chunked
Transfer-Encoding: x

Transfer-Encoding : chunked

Transfer-Encoding: chunked
Transfer-encoding: x

Transfer-Encoding:[tab]chunked

Transfer-Encoding
 : chunked
```

**Framework-specific quirks:**
- Node.js pre-18.x: very permissive, accepts whitespace variations, uses FIRST TE header
- gunicorn/Werkzeug: Werkzeug ignores TE for WSGI; gunicorn handles chunked before WSGI
- Tomcat 8.x/9.x: may accept obfuscated TE headers; 10+ is strict
- HAProxy pre-2.4: may forward both CL and TE without normalization

### Step 4: Check HTTP/2 Downgrade Vectors

```
Client --[HTTP/2]--> Proxy --[HTTP/1.1]--> Backend
```

**H2.CL smuggling** — Content-Length in HTTP/2 disagreeing with DATA frame length:
```
:method POST
:path /
:authority vulnerable.com
content-length: 0

SMUGGLED REQUEST HERE
```

**Check for:**
- Proxy terminates HTTP/2 and speaks HTTP/1.1 to backend
- Pseudo-headers not sanitized during downgrade
- Header injection via newline characters in HTTP/2 header values

### Step 5: Evaluate Connection Handling

Smuggling requires misinterpreted boundaries on a shared connection:

```nginx
# VULNERABLE: persistent connections
proxy_http_version 1.1;
proxy_set_header Connection "";

# MITIGATED: fresh connection per request
proxy_http_version 1.0;
# or: proxy_set_header Connection "close";
```

**Check:** keep-alive between tiers, connection pooling in load balancers, `Connection: close` being stripped.

### Step 6: Classify

- **VULNERABLE (Critical)**: Both CL and TE forwarded without normalization, persistent connections, HTTP/1.1 between tiers
- **VULNERABLE (High)**: TE obfuscation accepted by one layer, or HTTP/2 downgrade without header sanitization
- **HARDENED (Medium)**: Proxy normalizes but uses older version with known parser bugs
- **HARDENED (Low)**: Proxy strips duplicate headers but does not reject ambiguous requests
- **SAFE**: Proxy rejects both-CL-and-TE requests, HTTP/2 end-to-end, or no connection reuse
- **BY_DESIGN**: Single-tier architecture with no proxy

## Decision Tree

```
Is there a multi-tier HTTP architecture (proxy + backend)?
├── No (single server) → SAFE
└── Yes → Are persistent connections used between tiers?
    ├── No (Connection: close) → SAFE
    └── Yes → Does the proxy forward both CL and TE headers?
        ├── No (normalizes/strips) → Known parser bugs in proxy version?
        │   ├── Yes → HARDENED (Medium)
        │   └── No → HTTP/2 downgrade occurs?
        │       ├── Yes → Pseudo-headers sanitized?
        │       │   ├── Yes → SAFE
        │       │   └── No → VULNERABLE (High — H2 smuggling)
        │       └── No → SAFE
        └── Yes (both reach backend) → Do tiers agree on priority?
            ├── Yes → Can TE be obfuscated to cause disagreement?
            │   ├── Yes → VULNERABLE (High — TE.TE)
            │   └── No → SAFE
            └── No → VULNERABLE (Critical — CL.TE or TE.CL)
```

## Real-World Examples

### Example 1: CL.TE via Nginx to Node.js (Vulnerable)

```nginx
upstream backend { server node-app:3000; keepalive 64; }
server {
    listen 80;
    location / {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
}
```
```javascript
const app = express();
app.post('/login', (req, res) => res.json({ status: 'ok' }));
app.get('/admin', (req, res) => res.json({ users: getAllUsers() }));
app.listen(3000);
```

**Attack:**
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 45
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: vulnerable.com

```

**Why vulnerable:** Nginx uses CL (45 bytes) and forwards everything. Node.js sees TE chunked, reads `0\r\n\r\n` as end of first request, interprets `GET /admin` as the next request on the shared connection. This smuggled request executes in another user's authenticated context.

**Impact:** Request hijacking, access control bypass, session fixation. Attacker prepends requests that execute in another user's authenticated session.

**Fix:**
```nginx
proxy_set_header Transfer-Encoding "";  # Strip TE
# Or: proxy_http_version 1.0;          # Disable keep-alive
```

### Example 2: TE.TE Obfuscation on HAProxy to Gunicorn (Vulnerable)

```haproxy
# haproxy.cfg (version 2.0)
backend servers
    server app1 gunicorn-app:8000
    http-reuse always
```

**Attack:**
```http
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 4
Transfer-Encoding: chunked
Transfer-encoding: cow

5c
GPOST /admin HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

**Why vulnerable:** HAProxy sees `Transfer-encoding: cow` (lowercase), considers TE invalid, falls back to CL: 4. Gunicorn sees `Transfer-Encoding: chunked` (standard casing), processes chunked body including the smuggled `POST /admin`. The remainder poisons the next request on the shared connection.

**Impact:** Administrative action injection, WAF/auth bypass. All frontend security controls are circumvented.

**Fix:**
```haproxy
# Upgrade to HAProxy 2.4+ or reject ambiguous requests:
http-request deny if { req.hdr_cnt(transfer-encoding) gt 1 }
http-request deny if { req.hdr(transfer-encoding) -m sub -i chunked } { req.hdr_cnt(content-length) gt 0 }
```

### Example 3: False Positive — HTTP/2 End-to-End

```nginx
server {
    listen 443 ssl http2;
    location /api. {
        grpc_pass grpc://backend:50051;
    }
}
```

**Why safe:** HTTP/2 uses binary framing with explicit DATA frame lengths. Transfer-Encoding does not exist in HTTP/2. With HTTP/2 end-to-end (no downgrade to HTTP/1.1), there is no CL/TE ambiguity and no desync opportunity. Request smuggling fundamentally requires disagreement about request boundaries, which HTTP/2 framing eliminates.

## Common False Positive Patterns

1. **HTTP/2 end-to-end without downgrade**: Binary framing provides unambiguous message boundaries. Only flag if HTTP/1.1 downgrade occurs at any point in the chain.

2. **Connection: close on every response**: TCP connection torn down after each response. No shared connection for smuggled bytes to poison the next request.

3. **Single-tier architecture**: Application server handles client connections directly (no proxy/CDN/LB). One HTTP parser means no disagreement on boundaries.

4. **Modern proxy with strict RFC compliance**: HAProxy 2.6+, Nginx 1.21.1+ with default buffering, AWS ALB all normalize or reject conflicting CL/TE. Check the specific version.

5. **GET/HEAD only with no body forwarding**: No request body means no content to desync on. However, verify backends do not process bodies on GET requests.

6. **WebSocket upgrade connections**: After upgrade, the connection switches to WebSocket protocol. No subsequent HTTP requests to poison.

7. **API gateways that reconstruct requests**: Kong, AWS API Gateway, Apigee parse and rebuild requests. Backend sees the gateway's reconstruction, not raw client bytes, eliminating parser differential.
