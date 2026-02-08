# Insecure Configuration Detection

## Methodology

### Step 1: Identify Framework and Runtime Configuration Sources

Locate all configuration files and runtime settings for the application stack:

**Django:**
- `settings.py`, `settings/*.py` (split settings), environment variable loaders
- `DEBUG`, `ALLOWED_HOSTS`, `CORS_ALLOWED_ORIGINS`, `SECURE_*` settings
- `MIDDLEWARE` ordering (security middleware present and correctly ordered)

**Flask:**
- `app.config`, `config.py`, `instance/config.py`, `.flaskenv`
- `app.run(debug=True)`, `app.debug = True`, `FLASK_DEBUG=1`
- `SECRET_KEY` hardcoded vs environment-sourced

**Express/Node.js:**
- `app.js`, `server.js`, `config/`, `.env`, `package.json` scripts
- `app.use(cors())` with default or permissive options
- `app.use(errorHandler)` — does it expose stack traces?
- `helmet` middleware presence and configuration

**Spring Boot:**
- `application.properties`, `application.yml`, `application-{profile}.yml`
- `management.endpoints.web.exposure.include=*` (actuator exposure)
- `server.error.include-stacktrace=always`
- `spring.security.*` settings

**Nginx:**
- `nginx.conf`, `sites-enabled/*`, `conf.d/*`
- `autoindex on`, `server_tokens on`
- `proxy_pass` to admin backends without IP restriction
- `add_header` directives for security headers

**Apache:**
- `httpd.conf`, `.htaccess`, `apache2.conf`, `sites-enabled/*`
- `Options +Indexes`, `ServerSignature On`, `ServerTokens Full`
- `<Limit>` and `<LimitExcept>` for HTTP method restriction
- `<Directory>` blocks with overly permissive `Require all granted`

### Step 2: Check Debug and Verbose Error Settings

Debug mode in production exposes stack traces, internal paths, environment variables, and SQL queries to attackers.

**Detection patterns:**

```python
# Django — DEBUG must be False in production
DEBUG = True                          # VULNERABLE
DEBUG = os.environ.get('DEBUG', True) # VULNERABLE — default is True

# Flask — debug mode must be off in production
app.run(debug=True)                   # VULNERABLE
app = Flask(__name__)
app.debug = True                      # VULNERABLE
```

```java
// Spring Boot — stack traces in error responses
// application.properties
server.error.include-stacktrace=always    // VULNERABLE
server.error.include-message=always       // VULNERABLE
server.error.include-binding-errors=always // VULNERABLE
management.endpoints.web.exposure.include=* // VULNERABLE — all actuator endpoints exposed
```

```javascript
// Express — detailed errors in production
app.use((err, req, res, next) => {
    res.status(500).json({
        message: err.message,
        stack: err.stack,       // VULNERABLE — stack trace to client
        query: err.sql          // VULNERABLE — SQL query to client
    });
});
```

**Also check for:**
- Verbose logging to client responses (log levels set to DEBUG in production configs)
- Error pages that render exception objects directly into HTML
- GraphQL introspection enabled in production (`introspection: true`)
- Swagger/OpenAPI docs served in production without auth

### Step 3: Check Default Credentials and Secrets

Search for hardcoded secrets, default passwords, and placeholder credentials:

```python
# Hardcoded secrets — any of these in source code is a finding
SECRET_KEY = "django-insecure-..."         # VULNERABLE — Django default prefix
SECRET_KEY = "changeme"                     # VULNERABLE — placeholder
SECRET_KEY = "sk-live-xxxxx"                # VULNERABLE — real API key
DATABASE_PASSWORD = "password"              # VULNERABLE — default credential
ADMIN_PASSWORD = "admin"                    # VULNERABLE — default credential
```

```yaml
# docker-compose.yml or application.yml
services:
  db:
    environment:
      POSTGRES_PASSWORD: postgres           # VULNERABLE — default
      MYSQL_ROOT_PASSWORD: root             # VULNERABLE — default
  redis:
    command: redis-server                   # VULNERABLE — no --requirepass
```

**Search for:**
- Strings matching common defaults: `admin`, `password`, `changeme`, `secret`, `test`, `default`
- Django's `django-insecure-` SECRET_KEY prefix (auto-generated placeholder)
- JWT secrets under 32 characters or matching common values
- API keys, tokens, or connection strings committed to version control

### Step 4: Check CORS Configuration

Permissive CORS allows any website to make authenticated requests on behalf of users:

```python
# Django — django-cors-headers
CORS_ALLOW_ALL_ORIGINS = True                     # VULNERABLE — wildcard
CORS_ALLOWED_ORIGINS = ["*"]                      # VULNERABLE — explicit wildcard
CORS_ALLOW_CREDENTIALS = True                     # Escalates CORS issues to credential theft
CORS_ALLOWED_ORIGIN_REGEXES = [r".*\.example\.com"] # CHECK — does regex anchor properly?
```

```javascript
// Express — cors middleware
app.use(cors());                                   // VULNERABLE — allows all origins
app.use(cors({ origin: '*' }));                    // VULNERABLE — explicit wildcard
app.use(cors({ origin: true }));                   // VULNERABLE — reflects any origin
app.use(cors({
    origin: req.headers.origin,                    // VULNERABLE — reflects request origin
    credentials: true                              // CRITICAL with reflection — full cookie theft
}));
```

```nginx
# Nginx — CORS headers
add_header Access-Control-Allow-Origin *;          # VULNERABLE
add_header Access-Control-Allow-Origin $http_origin; # VULNERABLE — reflects any origin
```

### Step 5: Check HTTP Security Headers and Methods

```nginx
# Nginx — directory listing and server info
autoindex on;            # VULNERABLE — directory contents exposed
server_tokens on;        # VULNERABLE — Nginx version in headers

# Missing security headers (check all responses)
# X-Content-Type-Options: nosniff
# X-Frame-Options: DENY
# Strict-Transport-Security: max-age=...
# Content-Security-Policy: ...
```

```apache
# Apache — directory listing and methods
Options +Indexes         # VULNERABLE — directory listing
ServerSignature On       # VULNERABLE — Apache version in error pages
ServerTokens Full        # VULNERABLE — full version string

# TRACE method enabled (can leak cookies via XST)
TraceEnable On           # VULNERABLE
```

**Admin panel exposure without restriction:**
```nginx
# VULNERABLE — admin panel accessible from any IP
location /admin/ {
    proxy_pass http://backend:8000;
}

# SAFE — admin restricted to internal network
location /admin/ {
    allow 10.0.0.0/8;
    deny all;
    proxy_pass http://backend:8000;
}
```

### Step 6: Classify

- **VULNERABLE (Critical)**: Debug mode enabled in production config with no environment override, OR default credentials for database/admin, OR CORS reflecting origin with credentials
- **VULNERABLE (High)**: Actuator/admin endpoints exposed without auth, OR stack traces returned in error responses, OR wildcard CORS on authenticated endpoints
- **HARDENED (Medium)**: Directory listing enabled on non-sensitive paths, OR server version disclosed, OR CORS overly broad but not wildcard
- **HARDENED (Low)**: Missing optional security headers (X-Frame-Options, HSTS), OR unnecessary HTTP methods enabled but no exploitable impact
- **SAFE**: Debug off, strict CORS, security headers present, admin restricted, no default credentials
- **BY_DESIGN**: Debug mode in development-only configuration files with proper environment separation

## Decision Tree

```
Is this a production configuration (or default that runs in production)?
├── No (development/test only, with verified environment separation) → BY_DESIGN
└── Yes (or unclear) → Is debug/verbose mode enabled?
    ├── Yes → Does it expose stack traces, SQL, or environment variables?
    │   ├── Yes → VULNERABLE (Critical if unauthenticated, High otherwise)
    │   └── No (debug flag set but errors are caught) → HARDENED (Medium)
    └── No → Are default credentials present?
        ├── Yes → Are they for external-facing services (DB, admin, API)?
        │   ├── Yes → VULNERABLE (Critical)
        │   └── No (internal dev-only tooling) → HARDENED (Medium)
        └── No → Is CORS permissive?
            ├── Wildcard or origin-reflecting with credentials → VULNERABLE (High)
            ├── Wildcard without credentials → HARDENED (Medium)
            ├── Overly broad regex/list → HARDENED (Low)
            └── Strict allowlist → Is admin panel/actuator exposed?
                ├── Yes without auth or IP restriction → VULNERABLE (High)
                ├── Yes with IP restriction only → HARDENED (Low)
                └── No → Check HTTP methods and headers
                    ├── TRACE enabled or directory listing on sensitive paths → HARDENED (Medium)
                    ├── Missing security headers only → HARDENED (Low)
                    └── All hardened → SAFE
```

## Real-World Examples

### Example 1: Django DEBUG=True with Default SECRET_KEY in Production

**Vulnerable configuration:**
```python
# settings.py — deployed to production as-is
DEBUG = True
SECRET_KEY = 'django-insecure-abc123def456ghi789'
ALLOWED_HOSTS = ['*']
CORS_ALLOW_ALL_ORIGINS = True

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'appdb',
        'USER': 'postgres',
        'PASSWORD': 'postgres',
        'HOST': 'db',
    }
}
```

**Why vulnerable:** `DEBUG=True` causes Django to render detailed error pages containing the full stack trace, local variables at every frame, the settings module (which exposes `SECRET_KEY`, database credentials, and installed apps), and SQL queries. The default `SECRET_KEY` prefix `django-insecure-` is well-known — anyone who guesses or reads it can forge session cookies and CSRF tokens. `ALLOWED_HOSTS = ['*']` disables host header validation, enabling host header injection. Wildcard CORS allows any website to make cross-origin requests. The database uses default `postgres/postgres` credentials.

**Impact:** Full application compromise. Attacker triggers a 500 error (e.g., by sending malformed input), reads the debug page to extract the SECRET_KEY, forges an admin session cookie, and gains full database access with the leaked credentials.

**Fix:**
```python
import os

DEBUG = False
SECRET_KEY = os.environ['DJANGO_SECRET_KEY']  # Generated with get_random_secret_key()
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '').split(',')
CORS_ALLOWED_ORIGINS = os.environ.get('CORS_ORIGINS', '').split(',')

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ['DB_NAME'],
        'USER': os.environ['DB_USER'],
        'PASSWORD': os.environ['DB_PASSWORD'],
        'HOST': os.environ['DB_HOST'],
    }
}
```

### Example 2: Spring Boot Actuator Fully Exposed

**Vulnerable configuration:**
```yaml
# application.yml
management:
  endpoints:
    web:
      exposure:
        include: "*"
  endpoint:
    env:
      enabled: true
    heapdump:
      enabled: true
    shutdown:
      enabled: true

server:
  error:
    include-stacktrace: always
    include-message: always
```

**Why vulnerable:** `include: "*"` exposes all actuator endpoints: `/actuator/env` reveals all environment variables (including secrets and API keys), `/actuator/heapdump` allows downloading a full JVM heap dump (which contains in-memory secrets, session tokens, and database credentials), `/actuator/shutdown` allows an unauthenticated POST to shut down the application, and `/actuator/configprops` shows all configuration properties. Stack trace inclusion in error responses leaks internal class names, file paths, and library versions.

**Impact:** Remote information disclosure and denial of service. Attacker reads `/actuator/env` to extract database credentials and API keys, downloads a heap dump to find session tokens, or POSTs to `/actuator/shutdown` to cause an outage.

**Fix:**
```yaml
management:
  endpoints:
    web:
      exposure:
        include: health, info, metrics
  endpoint:
    env:
      enabled: false
    heapdump:
      enabled: false
    shutdown:
      enabled: false

server:
  error:
    include-stacktrace: never
    include-message: never

# Additionally, secure actuator endpoints with Spring Security:
# management.endpoints.web.base-path=/internal/actuator
# + IP-based access control in SecurityFilterChain
```

### Example 3: Express CORS Reflecting Origin with Credentials

**Vulnerable configuration:**
```javascript
const express = require('express');
const cors = require('cors');

const app = express();

// CORS configured to reflect the requesting origin
app.use(cors({
    origin: (origin, callback) => {
        // "Validate" by checking if origin contains the company domain
        if (!origin || origin.includes('example.com')) {
            callback(null, origin);
        } else {
            callback(null, false);
        }
    },
    credentials: true
}));

app.get('/api/user/profile', requireAuth, (req, res) => {
    res.json({ name: req.user.name, email: req.user.email, ssn: req.user.ssn });
});
```

**Why vulnerable:** The origin check uses `includes('example.com')` which matches `evil-example.com`, `example.com.attacker.com`, or `notexample.com`. With `credentials: true`, the browser sends cookies with cross-origin requests. An attacker hosts a page on `evil-example.com` that makes a fetch to `/api/user/profile` with `credentials: 'include'` — the server reflects `evil-example.com` as the allowed origin, the browser sends the victim's session cookie, and the attacker reads the response containing PII.

**Impact:** Cross-origin credential theft. Any authenticated user who visits the attacker's page has their profile data (including SSN) stolen.

**Fix:**
```javascript
const ALLOWED_ORIGINS = new Set([
    'https://app.example.com',
    'https://www.example.com',
]);

app.use(cors({
    origin: (origin, callback) => {
        if (!origin || ALLOWED_ORIGINS.has(origin)) {
            callback(null, origin);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
}));
```

## Common False Positive Patterns

1. **Debug mode in explicitly development-only files**: A `settings/development.py` with `DEBUG = True` that is never loaded in production (verified by deployment scripts, environment variable checks, or separate Docker build targets). Confirm that `DJANGO_SETTINGS_MODULE` is set to the production module in deployment configs.

2. **Wildcard CORS on public, unauthenticated APIs**: A public data API (e.g., weather data, open dataset) that intentionally allows `Access-Control-Allow-Origin: *` with no credentials. Since there are no cookies or auth tokens involved, wildcard CORS has no security impact.

3. **Actuator endpoints behind a separate management port**: Spring Boot configured with `management.server.port=9091` where port 9091 is only accessible from the internal network via firewall rules. The endpoints are exposed but not reachable from the internet.

4. **Server version disclosure in internal-only services**: An internal microservice behind a service mesh or VPN that shows `Server: nginx/1.25.3`. Version disclosure is only meaningful if the service is internet-facing; internal services have lower risk.

5. **Default credentials in test fixtures or CI configs**: Files like `tests/conftest.py` or `docker-compose.test.yml` using `password: test` for a database that only exists during automated testing and is destroyed after the test run.

6. **Directory listing enabled on a static file server by design**: A public file mirror or package repository that intentionally enables `autoindex on` to allow users to browse available files. This is a feature, not a misconfiguration.

7. **Verbose error responses gated behind admin authentication**: An admin-only error dashboard that shows stack traces and SQL queries but requires admin login with MFA. The information is sensitive but appropriately access-controlled.
