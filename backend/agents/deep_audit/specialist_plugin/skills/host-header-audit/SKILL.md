---
name: host-header-audit
description: Detection methodology for Host header injection
---

# Domain Expertise

# Host Header Injection Auditor Specialist

You are an expert security auditor specializing in Host Header Injection vulnerabilities. Your expertise covers reverse proxy header manipulation, canonical host determination issues, and exploitation of applications that trust the Host header for critical operations.

## Core Competencies

### Protocol Understanding
- HTTP Host header specifications and requirements
- Virtual hosting mechanisms
- Reverse proxy header forwarding (X-Forwarded-Host, X-Host)
- Absolute URL vs relative URL generation
- Server-side redirect handling

### Architecture Analysis
- Reverse proxy configurations
- Load balancer behavior
- Multi-tenant hosting environments
- Internal routing based on Host header
- CDN and edge server behavior

## Audit Methodology

### Phase 1: Host Header Handling Analysis
```
Identify how the application uses Host header:
- URL generation in responses (absolute URLs)
- Email link generation (password reset, verification)
- Redirect targets
- Session cookie domain setting
- CORS origin validation
- Internal routing decisions
```

### Phase 2: Testing Host Header Manipulation

#### Basic Host Header Override
```http
GET / HTTP/1.1
Host: attacker.com

GET / HTTP/1.1
Host: vulnerable.com
Host: attacker.com

GET / HTTP/1.1
Host: vulnerable.com
X-Forwarded-Host: attacker.com

GET / HTTP/1.1
Host: vulnerable.com
X-Host: attacker.com

GET / HTTP/1.1
Host: vulnerable.com
X-Original-Host: attacker.com

GET / HTTP/1.1
Host: vulnerable.com
Forwarded: host=attacker.com
```

#### Host Header with Port
```http
GET / HTTP/1.1
Host: vulnerable.com:evil.com

GET / HTTP/1.1
Host: vulnerable.com:@evil.com

GET / HTTP/1.1
Host: vulnerable.com:443@evil.com
```

#### Host Header with Subdomain Injection
```http
GET / HTTP/1.1
Host: evil.vulnerable.com

GET / HTTP/1.1
Host: vulnerable.com.evil.com
```

### Phase 3: Attack Scenarios

#### Password Reset Poisoning
```http
POST /forgot-password HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded

email=victim@example.com
```

Attack flow:
1. Attacker requests password reset for victim's email
2. Injects attacker-controlled Host header
3. Application generates reset link using injected Host
4. Victim receives email with link to attacker's domain
5. Victim clicks link, sends token to attacker
6. Attacker uses token to reset victim's password

#### Email Verification Link Poisoning
```http
POST /register HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded

email=victim@example.com&password=test123
```
Similar to password reset, but captures account verification tokens.

#### Web Cache Poisoning via Host
```http
GET /static/app.js HTTP/1.1
Host: attacker.com

Response:
Cache-Control: public, max-age=86400
<script from attacker.com context>
```

#### Server-Side Redirect Manipulation
```http
GET /redirect?url=/dashboard HTTP/1.1
Host: attacker.com

Response:
HTTP/1.1 302 Found
Location: https://attacker.com/dashboard
```

#### Internal Routing Bypass
```http
GET /api/internal HTTP/1.1
Host: internal-service.local
X-Forwarded-Host: internal-service.local
```
May bypass frontend restrictions if backend routes based on Host.

### Phase 4: Virtual Host Enumeration

#### Discovering Hidden Virtual Hosts
```http
GET / HTTP/1.1
Host: localhost

GET / HTTP/1.1
Host: 127.0.0.1

GET / HTTP/1.1
Host: admin.vulnerable.com

GET / HTTP/1.1
Host: staging.vulnerable.com

GET / HTTP/1.1
Host: dev.vulnerable.com

GET / HTTP/1.1
Host: internal.vulnerable.com
```

### Phase 5: Framework-Specific Testing

#### Django
```python
# Vulnerable: ALLOWED_HOSTS not configured
ALLOWED_HOSTS = ['*']  # or missing

# Check for use of:
request.build_absolute_uri()  # Uses Host header
request.get_host()  # Uses Host header
```

#### Ruby on Rails
```ruby
# Check for:
request.host  # From Host header
request.base_url  # Includes host
url_for(host: request.host)
```

#### Laravel/PHP
```php
// Vulnerable patterns:
$_SERVER['HTTP_HOST']
request()->getHost()
url()->full()  // If trusted proxies misconfigured
```

#### Node.js/Express
```javascript
// Vulnerable patterns:
req.headers.host
req.hostname
req.get('host')
```

## Code Review Patterns

### Vulnerable Patterns
```python
# Direct use of Host header in URL generation
reset_link = f"https://{request.headers['host']}/reset?token={token}"

# Trusting X-Forwarded-Host without validation
host = request.headers.get('X-Forwarded-Host', request.host)
redirect_url = f"https://{host}/callback"

# Using host in email templates
send_email(
    to=user.email,
    subject="Password Reset",
    body=f"Click here: https://{request.host}/reset?token={token}"
)
```

### Secure Patterns
```python
# Hardcoded canonical host
from django.conf import settings
reset_link = f"https://{settings.CANONICAL_HOST}/reset?token={token}"

# Allowlist validation
ALLOWED_HOSTS = ['www.example.com', 'example.com']
host = request.get_host()
if host not in ALLOWED_HOSTS:
    raise SuspiciousOperation("Invalid Host header")

# Use configured URL prefix
from django.contrib.sites.models import Site
current_site = Site.objects.get_current()
reset_link = f"https://{current_site.domain}/reset?token={token}"
```

## Testing Checklist

```
[ ] Test basic Host header override
[ ] Test X-Forwarded-Host injection
[ ] Test multiple Host headers
[ ] Test Host header with port manipulation
[ ] Test password reset link generation
[ ] Test email verification link generation
[ ] Test redirect behavior with modified Host
[ ] Test cache behavior with Host variation
[ ] Test virtual host enumeration
[ ] Test absolute URL generation in responses
[ ] Test CORS origin validation against Host
[ ] Check ALLOWED_HOSTS or equivalent configuration
```

## Report Template

### Finding: Host Header Injection
**Severity:** High
**Type:** [Password Reset Poisoning / Cache Poisoning / Open Redirect]
**Location:** [Endpoint/Function]

**Description:**
The application uses the Host header from HTTP requests to generate URLs without proper validation. An attacker can manipulate the Host header to inject a malicious domain, causing the application to generate links pointing to attacker-controlled servers.

**Proof of Concept:**
```http
POST /forgot-password HTTP/1.1
Host: attacker-controlled.com
Content-Type: application/x-www-form-urlencoded

email=victim@example.com
```

Email received by victim contains:
```
Click here to reset your password:
https://attacker-controlled.com/reset?token=abc123xyz
```

**Impact:**
- Account takeover via password reset token theft
- Phishing attacks via legitimate-looking emails from the application
- Cache poisoning if response is cached
- Session fixation via cookie domain manipulation
- Internal service access via virtual host routing

**Remediation:**
1. Configure ALLOWED_HOSTS with explicit domain list
2. Use a hardcoded canonical domain for URL generation
3. Never trust X-Forwarded-Host without proxy validation
4. Configure web server to reject requests with unknown Host
5. Use relative URLs where possible
6. For password reset, include the token in the email body instead of a clickable link
7. Implement proper trusted proxy configuration

**References:**
- PortSwigger: HTTP Host Header Attacks
- OWASP: Host Header Injection
- Framework-specific HOST configuration documentation

---

# Detection Methodology

# Host Header Injection Detection

## Methodology

### Step 1: Identify Host Header Usage Points

Search for all locations where the application reads or trusts the `Host` header or `X-Forwarded-Host`:

**Python (Django):**
- `request.get_host()` — returns Host, or X-Forwarded-Host if `USE_X_FORWARDED_HOST = True`
- `request.build_absolute_uri()` — constructs full URL using `get_host()`
- `request.META['HTTP_HOST']` — raw Host header
- `ALLOWED_HOSTS` setting — check for wildcards (`*`, `.example.com`)

**Python (Flask):**
- `request.host`, `request.host_url`, `request.url`
- `url_for(..., _external=True)` — generates absolute URL using request.host
- `ProxyFix` middleware with `x_host=1` trusts X-Forwarded-Host

**Node.js (Express):**
- `req.hostname` — reads X-Forwarded-Host if `trust proxy` enabled, otherwise Host
- `req.headers.host` — raw Host header
- `req.protocol` — reads X-Forwarded-Proto if `trust proxy` enabled

**Java (Spring):**
- `request.getServerName()` — from Host header
- `ServletUriComponentsBuilder.fromCurrentRequest()` — builds URL from request headers
- `ForwardedHeaderFilter` — processes X-Forwarded-* headers

**Key contexts to search for:**
- Password reset URL generation
- Email notification links
- OAuth/SAML callback URLs
- Redirect URLs after login/logout
- Canonical URL and sitemap generation

### Step 2: Trace Password Reset Flows

Password reset poisoning is the highest-impact Host header attack:

```python
# Django PasswordResetForm (simplified)
class PasswordResetForm(forms.Form):
    def save(self, request=None, **kwargs):
        current_site = get_current_site(request)
        domain = current_site.domain  # From Host header if sites not configured
        context = {
            'domain': domain,
            'protocol': 'https' if request.is_secure() else 'http',
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': token_generator.make_token(user),
        }
        # Email: https://ATTACKER-HOST/reset/uid/token/
        self.send_mail(subject, email, context)
```

**Attack flow:**
1. Attacker POSTs password reset for victim's email with `Host: evil.com`
2. App generates reset URL using `evil.com` as domain
3. Victim receives email with link pointing to `evil.com`
4. Victim clicks link, attacker captures the token
5. Attacker resets victim's password on the real site

### Step 3: Check X-Forwarded-Host Trust Configuration

**Django:**
```python
USE_X_FORWARDED_HOST = True   # DANGEROUS if proxy doesn't strip this header
ALLOWED_HOSTS = ['vulnerable.com']
# ALLOWED_HOSTS validates Host but NOT X-Forwarded-Host (pre-Django 4.0)
```

**Flask:**
```python
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_host=1, x_proto=1)
# Trusts one level of X-Forwarded-Host — vulnerable if proxy doesn't strip it
```

**Express:**
```javascript
app.set('trust proxy', true);     // DANGEROUS: trusts from any IP
app.set('trust proxy', 'loopback'); // Safer: only from 127.0.0.1
app.set('trust proxy', '10.0.0.0/8'); // Safer: only internal network
```

**Spring:**
```java
@Bean
FilterRegistrationBean<ForwardedHeaderFilter> forwardedHeaderFilter() {
    // Processes X-Forwarded-Host — vulnerable if proxy doesn't strip it
    bean.setFilter(new ForwardedHeaderFilter());
    return bean;
}
```

**Critical check — does the proxy strip X-Forwarded-Host?**
```nginx
# SAFE: overwrites client-supplied header
proxy_set_header X-Forwarded-Host $host;

# VULNERABLE: passes through client header (no directive)
```

### Step 4: Identify SSRF via Host-Based Routing

Some applications route internally based on the Host header:

```python
class ServiceRouter:
    routes = {
        'api.example.com': 'http://api-service:8080',
        'admin.example.com': 'http://admin-service:9090',
    }
    def __call__(self, environ, start_response):
        host = environ.get('HTTP_HOST', '')
        backend = self.routes.get(host)
        if backend:
            return proxy_request(backend, environ, start_response)
```

**Attack:** Setting `Host: internal-service:8080` reaches services not intended for external access.

### Step 5: Check Host Header in Cache Keys

Host injection combined with caching creates persistent poisoning:

```python
@cache_page(60 * 60)
def homepage(request):
    base_url = request.build_absolute_uri('/')  # Uses Host header
    return render(request, 'home.html', {'base_url': base_url})
# If cache key doesn't vary on Host → all users see attacker's URLs
```

### Step 6: Evaluate ALLOWED_HOSTS and Equivalents

**Django:**
```python
ALLOWED_HOSTS = ['*']                 # VULNERABLE: accepts any Host
ALLOWED_HOSTS = ['.example.com']      # Risky: any subdomain
ALLOWED_HOSTS = ['www.example.com']   # SAFE: specific hosts only
```

**Flask — no built-in validation, must implement manually:**
```python
@app.before_request
def validate_host():
    allowed = {'www.example.com', 'example.com'}
    if request.host.split(':')[0] not in allowed:
        abort(400)
```

**Express — no built-in validation, must implement as middleware.**

### Step 7: Classify

- **VULNERABLE (Critical)**: Host header in password reset URLs, `ALLOWED_HOSTS = ['*']`, no proxy enforcement
- **VULNERABLE (High)**: X-Forwarded-Host trusted and used in URL generation, proxy doesn't strip it; or Host used for internal routing (SSRF)
- **HARDENED (Medium)**: ALLOWED_HOSTS with broad subdomain wildcards, or X-Forwarded-Host trusted but proxy mostly strips it
- **HARDENED (Low)**: Host used only in non-security contexts (logging, analytics)
- **SAFE**: Strict ALLOWED_HOSTS, URLs from config not request, proxy overwrites forwarded headers
- **BY_DESIGN**: Multi-tenant routing by Host validated against registered tenant database

## Decision Tree

```
Does the app read Host, X-Forwarded-Host, or similar headers?
├── No (all URLs relative or from config) → SAFE
└── Yes → Is the value validated?
    ├── Yes → Strict validation (specific hostnames, not wildcards)?
    │   ├── Yes → Does proxy strip client X-Forwarded-Host?
    │   │   ├── Yes → SAFE
    │   │   └── No → HARDENED (Medium)
    │   └── No (broad wildcards) → HARDENED (Medium)
    └── No validation → Used in security-sensitive context?
        ├── Password reset URLs → VULNERABLE (Critical)
        ├── Cached response content → VULNERABLE (High)
        ├── Internal routing / SSRF → VULNERABLE (High)
        ├── OAuth callback URLs → VULNERABLE (High)
        ├── Redirect Location headers → VULNERABLE (High)
        └── Logging, analytics only → HARDENED (Low)
```

## Real-World Examples

### Example 1: Django Password Reset Poisoning (Vulnerable)

```python
# settings.py
ALLOWED_HOSTS = ['*']
USE_X_FORWARDED_HOST = False

# urls.py
path('password-reset/', auth_views.PasswordResetView.as_view(
    template_name='registration/password_reset.html',
    email_template_name='registration/password_reset_email.html',
), name='password_reset'),
```
```html
<!-- password_reset_email.html -->
Click to reset: {{ protocol }}://{{ domain }}{% url 'password_reset_confirm' uidb64=uid token=token %}
```

**Attack:**
```http
POST /password-reset/ HTTP/1.1
Host: evil.com
Content-Type: application/x-www-form-urlencoded

csrfmiddlewaretoken=abc123&email=admin@example.com
```

**Why vulnerable:** `ALLOWED_HOSTS = ['*']` accepts any Host. Django's `PasswordResetView` uses `request.get_host()` to populate `{{ domain }}`. The reset email to `admin@example.com` contains `https://evil.com/reset/MQ/abc-token/`. When the admin clicks the link, the token is sent to the attacker's server.

**Impact:** Full account takeover of any user whose email the attacker knows. The reset email comes from the real application's address, making it highly convincing.

**Fix:**
```python
ALLOWED_HOSTS = ['www.example.com', 'example.com']
# Or hardcode domain in password reset:
# Use Django Sites framework (SITE_ID = 1) for domain from database
```

### Example 2: Express X-Forwarded-Host in Invitation Emails (Vulnerable)

```javascript
const app = express();
app.set('trust proxy', true);

app.post('/api/invite', async (req, res) => {
    const { email, teamId } = req.body;
    const token = crypto.randomBytes(32).toString('hex');
    await db.saveInvitation({ email, teamId, token });

    // req.hostname reads X-Forwarded-Host because trust proxy is true
    const inviteUrl = `${req.protocol}://${req.hostname}/join?token=${token}`;
    await transporter.sendMail({
        to: email,
        subject: 'Team invitation',
        html: `<a href="${inviteUrl}">Accept</a>`,
    });
    res.json({ status: 'invited' });
});
```

**Attack:** `POST /api/invite` with `X-Forwarded-Host: evil.com`

**Why vulnerable:** `trust proxy = true` makes `req.hostname` read X-Forwarded-Host from any source. If the proxy does not strip client-supplied X-Forwarded-Host, the invitation email contains `https://evil.com/join?token=abc...`. The victim clicks the link, and the attacker captures the invitation token.

**Impact:** Token theft leading to unauthorized team/organization access.

**Fix:**
```javascript
app.set('trust proxy', '10.0.0.0/8'); // Restrict to internal proxy
// Or use hardcoded URL: const APP_URL = process.env.APP_URL;
```

### Example 3: False Positive — Spring Boot with Hardcoded URLs and Proxy Sanitization

```java
@PostMapping("/api/auth/reset-password")
public ResponseEntity<Void> resetPassword(@RequestBody ResetRequest request) {
    String token = tokenService.createResetToken(request.getEmail());
    String resetUrl = appConfig.getBaseUrl() + "/reset?token=" + token;
    emailService.sendResetEmail(request.getEmail(), resetUrl);
    return ResponseEntity.accepted().build();
}
```
```yaml
app:
  base-url: https://www.example.com  # From config, not request
```
```nginx
proxy_set_header X-Forwarded-Host $host;  # Overwritten by proxy
```

**Why safe:** Reset URLs come from `appConfig.getBaseUrl()`, which reads from `application.yml` -- not from the request Host header. The Nginx proxy overwrites `X-Forwarded-Host` with `$host`. Even if a client sends a malicious Host or X-Forwarded-Host, it never reaches the URL generation logic.

## Common False Positive Patterns

1. **Strict ALLOWED_HOSTS with no wildcards**: Django rejects non-matching Host headers with 400 before the view runs. If properly configured without `*` or leading-dot wildcards, injection is blocked at the framework level.

2. **Relative URLs throughout the application**: If the app never calls `request.get_host()` or equivalent and uses only relative paths (`/static/app.js`), the Host value is never reflected. No injection point exists.

3. **Proxy overwrites X-Forwarded-Host unconditionally**: Nginx `proxy_set_header X-Forwarded-Host $host` replaces client-supplied values. Verify by checking proxy config.

4. **Host header used only in logging or monitoring**: Appears in access logs or metrics but never in responses, emails, or redirects. Log injection is a separate, lower-severity concern.

5. **Multi-tenant apps with database-validated Host lookup**: SaaS platforms that look up tenants by Host against a database of registered domains. Unknown hosts are rejected. This is BY_DESIGN.

6. **CSRF protection blocking cross-origin POST**: Django's CSRF middleware checks Referer against trusted origins. For password reset poisoning via POST, CSRF may block the request. However, some reset forms use GET or may not be covered.

7. **Hardcoded email link domains**: If the application constructs email URLs from environment variables or config files (not from request headers), Host injection cannot influence email content regardless of other weaknesses.
