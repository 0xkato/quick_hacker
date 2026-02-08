# TLS/SSL Configuration Analysis

## Methodology

### Step 1: Identify TLS Configuration Sites

Locate all code establishing TLS connections (client) or configuring TLS listeners (server):

| Language   | Libraries / Modules                                            |
|------------|----------------------------------------------------------------|
| Python     | `requests`, `urllib3`, `httpx`, `aiohttp`, `ssl`               |
| Node.js    | `https`, `tls`, `axios`, `node-fetch`, `got`                   |
| Java       | `HttpsURLConnection`, `SSLContext`, `OkHttp`, `Apache HttpClient` |
| Go         | `net/http`, `crypto/tls`, `tls.Config`                         |
| Rust       | `reqwest`, `hyper`, `rustls`, `native-tls`                     |

Also check web server configs: `nginx.conf`, `httpd.conf`, `haproxy.cfg`, `Caddyfile`.

### Step 2: Check Certificate Validation

Disabling cert verification enables trivial man-in-the-middle attacks:

```python
# VULNERABLE: Disables certificate verification
requests.get('https://api.example.com', verify=False)

# VULNERABLE: SSL context with no verification
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
```

```javascript
// VULNERABLE: Disables TLS verification for ALL connections in the process
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// VULNERABLE: Per-request disable
const agent = new https.Agent({ rejectUnauthorized: false });
```

```java
// VULNERABLE: Trust-all TrustManager — accepts any certificate
TrustManager[] trustAll = new TrustManager[] {
    new X509TrustManager() {
        public X509Certificate[] getAcceptedIssuers() { return null; }
        public void checkClientTrusted(X509Certificate[] c, String t) {}
        public void checkServerTrusted(X509Certificate[] c, String t) {}
    }
};
SSLContext sc = SSLContext.getInstance("TLS");
sc.init(null, trustAll, new SecureRandom());
```

```go
// VULNERABLE: Skip certificate verification
tr := &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}
```

### Step 3: Check Protocol Versions

| Protocol | Status | Vulnerabilities |
|----------|--------|-----------------|
| SSLv2/v3 | Broken | DROWN, POODLE |
| TLS 1.0  | Deprecated (RFC 8996) | BEAST, no AEAD |
| TLS 1.1  | Deprecated (RFC 8996) | No AEAD suites |
| TLS 1.2  | Acceptable | Secure with AEAD ciphers |
| TLS 1.3  | Recommended | Built-in forward secrecy, no legacy ciphers |

```python
# VULNERABLE: Allows TLS 1.0
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
ctx.minimum_version = ssl.TLSVersion.TLSv1  # Should be TLSv1_2
```

```go
// VULNERABLE: Allows TLS 1.0
tlsConfig := &tls.Config{MinVersion: tls.VersionTLS10}
```

```nginx
# VULNERABLE
ssl_protocols TLSv1 TLSv1.1 TLSv1.2;

# SAFE
ssl_protocols TLSv1.2 TLSv1.3;
```

### Step 4: Check Cipher Suites

| Cipher Category | Why Broken |
|-----------------|------------|
| RC4             | Keystream biases — practical plaintext recovery |
| DES / 3DES      | 64-bit block — Sweet32 birthday attack |
| Export ciphers   | 40/56-bit keys — trivially brute-forceable (FREAK, Logjam) |
| NULL ciphers     | No encryption at all |
| Anonymous DH     | No authentication — trivial MITM |

```nginx
# VULNERABLE: Includes weak ciphers
ssl_ciphers 'ALL:!aNULL';

# SAFE: AEAD-only ciphers with forward secrecy
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
```

```go
// VULNERABLE: Weak cipher suites
tlsConfig := &tls.Config{
    CipherSuites: []uint16{
        tls.TLS_RSA_WITH_RC4_128_SHA,
        tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
    },
}
```

### Step 5: Check HSTS Configuration

HSTS tells browsers to always use HTTPS, preventing protocol downgrade attacks:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

Common issues:
- HSTS missing entirely
- `max-age` too short (e.g., 3600 = 1 hour, easily bypassed)
- Missing `includeSubDomains` (subdomains still vulnerable)
- Not applied to all HTTPS responses (only some routes)

```nginx
# SAFE
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

### Step 6: Check for Mixed Content

HTTPS pages loading resources over HTTP:

```html
<!-- VULNERABLE: Active mixed content — script injection possible -->
<script src="http://cdn.example.com/lib.js"></script>

<!-- HARDENED: Passive mixed content — less severe -->
<img src="http://images.example.com/logo.png">
```

```javascript
// VULNERABLE: Auth token sent over plaintext HTTP from HTTPS page
fetch('http://api.example.com/data', {
    headers: { 'Authorization': `Bearer ${token}` }
});
```

### Step 7: Check Certificate Pinning

Pinning adds defense-in-depth but has risks: pinning without backup pins can brick the app on key rotation, pinning to leaf certs requires app updates on every renewal, SHA-1 pin hashes are deprecated, and HPKP header is deprecated (Chrome removed 2018). Always include at least one backup pin.

```java
// SAFE: Primary + backup pin
CertificatePinner pinner = new CertificatePinner.Builder()
    .add("api.example.com", "sha256/AAAA...")   // Primary
    .add("api.example.com", "sha256/BBBB...")   // Backup
    .build();
```

### Step 8: Check TLS Termination and Proxy Trust

When TLS terminates at a load balancer, verify:
- Backend does not blindly trust `X-Forwarded-Proto` from untrusted sources
- Internal service-to-service traffic is encrypted (not plaintext after termination)
- Proxy headers are set only by the trusted reverse proxy layer

```python
# VULNERABLE: Attacker can set X-Forwarded-Proto to bypass HTTPS enforcement
if request.headers.get('X-Forwarded-Proto') != 'https':
    return redirect(request.url.replace('http:', 'https:'))
```

### Step 9: Classify

- **VULNERABLE (Critical)**: Cert verification disabled in production; SSLv2/v3 enabled; NULL ciphers; hostname verification disabled
- **VULNERABLE (High)**: TLS 1.0/1.1 enabled; RC4/DES/3DES/export ciphers; active mixed content; self-signed cert trusted in production; `NODE_TLS_REJECT_UNAUTHORIZED=0`
- **HARDENED (Medium)**: HSTS missing or max-age < 1 year; CBC ciphers without AEAD alternatives; cert pinning without backup; X-Forwarded-Proto trusted without proxy validation
- **HARDENED (Low)**: TLS 1.2 without 1.3; passive mixed content; HSTS preload missing; cert pinning to leaf
- **SAFE**: TLS 1.2+ with AEAD ciphers; cert verification enabled; full HSTS; no mixed content
- **BY_DESIGN**: Cert verification disabled for dev/test with environment guards; self-signed in CI; TLS 1.0 for documented legacy compatibility

## Decision Tree

```
TLS configuration found?
├── No → Network communication without TLS? → VULNERABLE (High)
└── Yes → Certificate validation enabled?
    ├── Disabled (verify=False, InsecureSkipVerify, trust-all)
    │   ├── Production code → VULNERABLE (Critical)
    │   └── Test/dev with env guard → BY_DESIGN
    └── Enabled → Protocol versions?
        ├── SSLv2/v3 → VULNERABLE (Critical)
        ├── TLS 1.0/1.1 → VULNERABLE (High)
        └── TLS 1.2+ → Cipher suites?
            ├── RC4/DES/3DES/export/NULL → VULNERABLE (High)
            ├── CBC without AEAD alternatives → HARDENED (Medium)
            └── AEAD only → HSTS?
                ├── Missing → HARDENED (Medium)
                ├── max-age < 1yr or no includeSubDomains → HARDENED (Low)
                └── Full HSTS → Mixed content?
                    ├── Active (scripts/CSS over HTTP) → VULNERABLE (High)
                    ├── Passive (images) → HARDENED (Low)
                    └── None → SAFE
```

## Real-World Examples

### Example 1: Disabled Cert Verification in Python Microservice

**Vulnerable code:**
```python
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class PaymentClient:
    def __init__(self, base_url):
        self.session = requests.Session()
        self.session.verify = False  # Disables all cert verification

    def process_payment(self, order_id, amount, card_token):
        return self.session.post(f'{self.base_url}/v1/charges',
            json={'order_id': order_id, 'amount': amount, 'card_token': card_token},
            headers={'Authorization': f'Bearer {self.api_key}'}).json()
```

**Why vulnerable:** `verify=False` disables all certificate validation. Any network MITM attacker can present their own certificate and decrypt all traffic. `disable_warnings` hides the security warning. Payment card tokens and API keys are sent without server identity assurance.

**Impact:** Man-in-the-middle intercepts payment tokens, API keys, and customer data.

**Fix:** Use `self.session.verify = '/etc/ssl/certs/ca-certificates.crt'` or the default system CA bundle (`verify=True`).

### Example 2: NODE_TLS_REJECT_UNAUTHORIZED in Production Docker

**Vulnerable code:**
```dockerfile
FROM node:20-slim
WORKDIR /app
COPY . .
ENV NODE_TLS_REJECT_UNAUTHORIZED=0
CMD ["node", "server.js"]
```

**Why vulnerable:** Global process-level setting disabling cert verification for every outbound TLS connection: databases, external APIs, payment processors, auth providers. Cannot be scoped. Likely added for a dev self-signed cert and never removed.

**Impact:** Every outbound HTTPS connection from this service is vulnerable to MITM.

**Fix:** Remove the ENV line. For internal CAs: `ENV NODE_EXTRA_CA_CERTS=/app/certs/internal-ca.pem`.

### Example 3: Java Trust-All TrustManager Set as Global Default

**Vulnerable code:**
```java
public class HttpClientFactory {
    public static HttpsURLConnection create(String url) throws Exception {
        TrustManager[] trustAll = new TrustManager[] {
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] c, String t) {}
                public void checkServerTrusted(X509Certificate[] c, String t) {}
            }
        };
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, trustAll, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> true);
        return (HttpsURLConnection) new URL(url).openConnection();
    }
}
```

**Why vulnerable:** `setDefault*` methods install trust-all globally for the entire JVM. Every thread, library, and framework using `HttpsURLConnection` is affected. The vulnerability is hidden in a utility class that callers invoke without realizing they are disabling TLS for the whole application.

**Impact:** Global MITM vulnerability for every HTTPS connection in the JVM process.

**Fix:** Load specific CA into KeyStore, create TrustManagerFactory, and apply per-connection via `conn.setSSLSocketFactory()` instead of `setDefault`.

## Common False Positive Patterns

1. **Cert verification disabled in test code**: `verify=False` in tests connecting to local servers with self-signed certs. Verify the code path is unreachable in production.

2. **Development environment guards**: `if (NODE_ENV === 'development') { ... }` properly gating disabled verification. Verify the guard works (undefined defaults matter).

3. **Internal CA trust**: Loading a custom CA bundle (`verify='/path/to/internal-ca.pem'`, `tls.Config{RootCAs: pool}`) is proper cert management, not disabled verification.

4. **TLS 1.2 without 1.3**: Legacy or compliance environments requiring TLS 1.2 only. With AEAD ciphers, this is HARDENED (Low) at worst.

5. **HSTS missing on non-browser APIs**: Server-to-server REST APIs do not benefit from HSTS (browser-only mechanism). Verify no browser clients use the endpoint.

6. **Certificate pinning absent**: Pinning is defense-in-depth, not baseline. Absence is not a vulnerability if standard cert validation works correctly.

7. **Mixed content on localhost**: `http://localhost:3000` from HTTPS during development does not traverse a network. Verify not used in production.
