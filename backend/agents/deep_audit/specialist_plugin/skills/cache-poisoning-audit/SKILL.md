---
name: cache-poisoning-audit
description: Detection methodology for web cache poisoning
---

# Domain Expertise

# Cache Poisoning/Deception Auditor Specialist

You are an expert security auditor specializing in Web Cache Poisoning and Cache Deception vulnerabilities. Your expertise covers cache key composition analysis, unkeyed header exploitation, and CDN-specific behaviors.

## Core Competencies

### Cache Mechanics Understanding
- Cache key composition and normalization
- Vary header behavior and implementation
- CDN-specific caching rules
- Cache-Control directive interpretation
- Edge caching vs origin caching
- Cache invalidation mechanisms

### Attack Vector Analysis
- Unkeyed inputs affecting responses
- Cache key manipulation techniques
- Web cache deception patterns
- Response splitting via caching
- Cache poisoning for DoS

## Audit Methodology

### Phase 1: Cache Fingerprinting
```
Identify caching infrastructure:
- Response headers (X-Cache, CF-Cache-Status, Age, X-Served-By)
- CDN vendor signatures (Cloudflare, Akamai, Fastly, Varnish)
- Cache-Control/Pragma headers
- Vary header presence and values
- Cache hit/miss behavior patterns
```

### Phase 2: Cache Key Analysis
```
Determine what's included in cache key:
- Host header (which host headers?)
- Request path (normalized how?)
- Query string (all parameters? specific ones?)
- Cookies (any? specific cookies?)
- Custom headers
```

### Phase 3: Unkeyed Input Discovery

#### Common Unkeyed Headers
```http
X-Forwarded-Host: attacker.com
X-Forwarded-Scheme: http
X-Forwarded-Proto: http
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Host: attacker.com
X-Forwarded-Server: attacker.com
X-HTTP-Method-Override: POST
X-Forwarded-Port: 443
```

#### Testing Methodology
```
1. Send request with potential unkeyed input
2. Check if input reflects in response
3. Verify response is cached
4. Request same URL without header
5. Check if poisoned response is served
```

### Phase 4: Cache Poisoning Attacks

#### X-Forwarded-Host Poisoning
```http
GET / HTTP/1.1
Host: vulnerable.com
X-Forwarded-Host: attacker.com

Response:
<script src="https://attacker.com/static/app.js"></script>
```
If cached, all users receive attacker-controlled JavaScript.

#### Unkeyed Port Poisoning
```http
GET / HTTP/1.1
Host: vulnerable.com
X-Forwarded-Port: 1234

Response contains:
<link href="https://vulnerable.com:1234/style.css">
```

#### Protocol Downgrade Poisoning
```http
GET / HTTP/1.1
Host: vulnerable.com
X-Forwarded-Proto: http

Response contains:
<script src="http://vulnerable.com/app.js"></script>
```
Mixed content issues, potential for MITM.

#### Query Parameter Pollution
```http
GET /?cb=1&utm_content=<script>alert(1)</script> HTTP/1.1
Host: vulnerable.com
```
If utm_content is unkeyed but reflected, cache poisoning possible.

#### Fat GET Requests
```http
GET /api/user HTTP/1.1
Host: vulnerable.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 14

admin=true
```
Some frameworks process body on GET; if response cached, privilege escalation.

### Phase 5: Web Cache Deception

#### Path Confusion Attacks
```
Target URL: /account/settings
Attack URL: /account/settings/nonexistent.css

If:
- Backend ignores /nonexistent.css, serves /account/settings
- Cache caches based on .css extension
Then:
- Attacker tricks victim into visiting malicious URL
- Victim's sensitive data cached
- Attacker retrieves cached response
```

#### Common Deception Patterns
```
/api/user/profile/logo.png
/my-account/x.css
/settings/..%2F..%2Fstatic/app.js
/user/data/anything.js
```

#### CDN-Specific Behaviors
```
Cloudflare:
- Caches by extension (.css, .js, .png, etc.)
- Check Page Rules configuration

Akamai:
- Complex caching rules
- Check cache key configuration

Fastly:
- VCL configuration determines caching
- Vary header support varies

Varnish:
- Default caches GET/HEAD only
- Custom VCL may expand caching
```

### Phase 6: Advanced Techniques

#### Cache Key Normalization Exploits
```
/api/endpoint vs /API/ENDPOINT
/api/endpoint vs /api//endpoint
/api/endpoint vs /api/endpoint/
/api/endpoint?a=1&b=2 vs /api/endpoint?b=2&a=1
```

#### Vary Header Manipulation
```http
GET /api/data HTTP/1.1
Host: vulnerable.com
Accept-Language: en-US,en;q=0.9,<script>alert(1)</script>
```
If Vary: Accept-Language and header is reflected unencoded.

#### Response Header Injection
```http
GET /page HTTP/1.1
Host: vulnerable.com
X-Injected-Header: value\r\nSet-Cookie: admin=true
```
Header injection leading to session fixation via cache.

## Code Review Patterns

### Vulnerable Patterns
```python
# Using unvalidated headers in response
host = request.headers.get('X-Forwarded-Host', request.host)
return f'<script src="https://{host}/app.js"></script>'

# Dynamic content on cached endpoints
@cache_page(3600)
def user_profile(request):
    return render(request, 'profile.html', {'user': request.user})
```

### Framework-Specific Issues
```ruby
# Rails - check cache key configuration
config.action_controller.page_cache_directory = ...

# Django - Vary header requirements
@vary_on_headers('Accept-Language', 'Cookie')
def my_view(request):
    ...
```

## Detection Checklist

```
[ ] Identify all caching layers (CDN, reverse proxy, application)
[ ] Map cache key composition for each layer
[ ] Test common unkeyed headers for reflection
[ ] Test query parameter keying behavior
[ ] Check for path normalization differences
[ ] Identify static extension caching rules
[ ] Test Vary header behavior
[ ] Check for cache deception on authenticated pages
[ ] Verify Cache-Control headers on sensitive responses
```

## Report Template

### Finding: Web Cache Poisoning
**Severity:** High/Critical
**Type:** [Unkeyed Header / Query Parameter / Cache Deception]
**Cache Layer:** [CDN/Reverse Proxy/Application]

**Description:**
The application's caching configuration allows attacker-controlled input to affect cached responses. The [specific unkeyed input] is not included in the cache key but influences the response content, enabling attackers to serve malicious content to all users.

**Proof of Concept:**
```http
GET /vulnerable-page HTTP/1.1
Host: vulnerable.com
X-Forwarded-Host: attacker.com

[Response with attacker-controlled content]
[Cache headers showing response was cached]
```

**Impact:**
- Stored XSS affecting all users of the cached page
- Phishing via modified page content
- Malware distribution via poisoned JavaScript
- Denial of service via cached error pages
- Session hijacking via cache deception

**Remediation:**
1. Include all inputs affecting response in cache key
2. Disable caching for pages with dynamic content based on headers
3. Add Cache-Control: private, no-store to sensitive pages
4. Validate and sanitize X-Forwarded-* headers
5. Configure CDN to not cache based on file extension alone
6. Implement Vary headers correctly for all varying inputs

**References:**
- PortSwigger Research: Practical Web Cache Poisoning
- Web Cache Deception Attack
- CDN-specific security documentation

---

# Detection Methodology

# Web Cache Poisoning Detection

## Methodology

### Step 1: Identify Caching Layers

Map all caching mechanisms in the request-response chain:

**CDN / Edge Caches:**
- Cloudflare: `CF-Cache-Status` header, Page Rules, Cache Rules
- Fastly (Varnish-based): `X-Cache`, `X-Cache-Hits`, VCL configuration
- Akamai: `X-Cache`, `X-Cache-Key`, Pragma headers
- AWS CloudFront: `X-Cache`, cache behaviors, origin request policies

**Reverse Proxy Caches:**
- Varnish: `vcl_hash`, `vcl_recv`, `beresp.ttl` in VCL config
- Nginx: `proxy_cache`, `proxy_cache_key`, `proxy_cache_valid`
- Apache `mod_cache`, Squid `refresh_pattern`

**Application-Level Caches:**
- Django: `@cache_page`, `cache_control`, `vary_on_headers`
- Rails: `caches_action`, `caches_page`, `fresh_when`
- Express: `apicache`, custom cache middleware
- Spring: `@Cacheable`, `CacheControl`

**Detection signals in responses:**
```http
X-Cache: HIT
CF-Cache-Status: HIT
Age: 3600
Cache-Control: public, max-age=86400
Vary: Accept-Encoding
```

### Step 2: Determine Cache Key Composition

The cache key determines which requests are "the same." Anything NOT in the key is an attack surface.

**Cloudflare default:** scheme + host + path + query string. Does NOT include headers or cookies unless configured.

**Varnish default:**
```vcl
sub vcl_hash {
    hash_data(req.url);       # Path + query
    hash_data(req.http.host); # Host header
    # Other headers NOT included
}
```

**Nginx default:**
```nginx
proxy_cache_key "$scheme$proxy_host$request_uri";
# Does NOT include arbitrary headers, cookies, or POST body
```

**Django `@cache_page`:** Uses request path + query string + `Vary` headers. If `Vary: Cookie` is missing, different users get the same cached response.

### Step 3: Find Unkeyed Inputs That Influence Responses

Search for headers/cookies NOT in the cache key that change response body or headers:

**X-Forwarded-Host:**
```python
# Django with USE_X_FORWARDED_HOST = True
# Template: <link href="https://{{ request.get_host() }}/static/style.css">
# Attacker sends X-Forwarded-Host: evil.com → cached response loads evil.com assets
```

```ruby
# Rails
config.action_controller.asset_host = proc { |source, request|
    request.headers['X-Forwarded-Host'] || request.host
}
# Asset URLs in cached pages point to attacker-controlled host
```

**X-Original-URL / X-Rewrite-URL:**
```http
GET / HTTP/1.1
Host: vulnerable.com
X-Original-URL: /admin/delete-user?id=1

# Cache key uses "/" but backend processes "/admin/delete-user?id=1"
```

**X-Forwarded-Proto:**
```python
# App redirects HTTP to HTTPS using X-Forwarded-Proto
if request.headers.get('X-Forwarded-Proto') == 'http':
    return redirect('https://' + request.host + request.path)
# Attacker poisons cache with a 302 redirect for all users
```

**Unkeyed cookies:**
```python
def homepage(request):
    language = request.COOKIES.get('lang', 'en')
    # Cached without Vary: Cookie → all users see attacker's language
```

### Step 4: Identify Parameter Cloaking and Fat GET Attacks

**Parameter cloaking** — cache and app parse query params differently:
```
GET /search?q=innocent;callback=evil_payload HTTP/1.1
# Varnish/Cloudflare: one param (q=innocent;callback=evil_payload)
# Rails: two params (q=innocent, callback=evil_payload) — ; is separator
# If callback is reflected → XSS via cache poisoning
```

**Fat GET** — some frameworks process request body on GET:
```javascript
app.use(express.json());
app.get('/api/config', (req, res) => {
    const theme = req.body.theme || 'default';
    res.json({ theme, config: getConfig() });
});
// Cache keys GET /api/config (no body in key)
// Attacker GETs with body: {"theme": "<script>alert(1)</script>"}
```

### Step 5: Detect Cache Key Normalization Differences

```
# Port: Host: vulnerable.com:443 vs Host: vulnerable.com
# Path: /./page vs /page vs /Page vs /page%2f
# Query: /page?b=2&a=1 vs /page?a=1&b=2 (sorted?)
# Trailing: /page? vs /page (with vs without trailing ?)
```

```nginx
# $request_uri = raw query; $uri = normalized, no query
# Mismatch in cache key vs what backend processes
proxy_cache_key "$scheme$host$uri$is_args$args";
```

### Step 6: Check for Web Cache Deception

Cache deception tricks the cache into storing private content:
```
# Attacker sends victim: https://vulnerable.com/account/settings/x.css
# CDN sees .css → caches response
# Backend ignores x.css → serves account page
# Attacker fetches cached URL → gets victim's account data
```

**Detection:** path-based cache rules + backend ignoring trailing segments + no `Cache-Control: private` on authenticated pages.

### Step 7: Classify

- **VULNERABLE (Critical)**: Unkeyed header reflected in cached HTML (stored XSS for all users)
- **VULNERABLE (High)**: Unkeyed input in response headers (redirect/session poisoning), or cache deception exposing auth data
- **HARDENED (Medium)**: Unkeyed input exists but sanitized, or cache TTL < 60 seconds
- **HARDENED (Low)**: Unkeyed input in non-security-relevant response parts only
- **SAFE**: All varying inputs are keyed, or responses carry `Cache-Control: private, no-store`
- **BY_DESIGN**: Static content cache with no dynamic elements

## Decision Tree

```
Is there a caching layer (CDN, proxy cache, framework cache)?
├── No → SAFE
└── Yes → Are there inputs NOT in cache key that influence the response?
    ├── No → SAFE
    └── Yes → Does the unkeyed input appear in the response body?
        ├── Yes → In executable context (HTML, JS)?
        │   ├── Yes → Sanitized/escaped?
        │   │   ├── Yes → HARDENED (Medium)
        │   │   └── No → VULNERABLE (Critical — stored XSS via cache)
        │   └── No → Security-sensitive content?
        │       ├── Yes → VULNERABLE (High)
        │       └── No → HARDENED (Low)
        └── No → Unkeyed input in response headers?
            ├── Yes → Location, Set-Cookie, or CSP?
            │   ├── Yes → VULNERABLE (High)
            │   └── No → HARDENED (Low)
            └── No → Cache deception possible?
                ├── Yes → VULNERABLE (High)
                └── No → SAFE
```

## Real-World Examples

### Example 1: X-Forwarded-Host in Django Cached Pages (Vulnerable)

```python
# settings.py
USE_X_FORWARDED_HOST = True
ALLOWED_HOSTS = ['vulnerable.com']

# views.py
@cache_page(60 * 15)
def homepage(request):
    return render(request, 'home.html')
```
```html
<link rel="stylesheet" href="https://{{ request.get_host }}/static/main.css">
<script src="https://{{ request.get_host }}/static/app.js"></script>
```

**Attack:** `GET / HTTP/1.1` with `X-Forwarded-Host: evil.com`

**Why vulnerable:** `USE_X_FORWARDED_HOST = True` makes `request.get_host()` return `evil.com`. `@cache_page` caches keyed on URL path only — `X-Forwarded-Host` is unkeyed. The response with `evil.com` URLs is cached for 15 minutes. Every visitor loads JavaScript from `evil.com`.

**Impact:** Mass stored XSS. Attacker serves malicious JavaScript to every user for the cache TTL duration. Session hijacking and credential theft at scale.

**Fix:**
```python
USE_X_FORWARDED_HOST = False  # Or add Vary header:
@vary_on_headers('X-Forwarded-Host')
@cache_page(60 * 15)
def homepage(request): ...
# Best: use relative URLs in templates
```

### Example 2: Parameter Cloaking in Rails Behind Cloudflare (Vulnerable)

```ruby
# Rails behind Cloudflare CDN
# routes.rb
get '/search', to: 'search#index'

# search_controller.rb
class SearchController < ApplicationController
    def index
        @query = params[:q]
        @callback = params[:callback]
    end
end
```
```erb
<h1>Results for: <%= @query %></h1>
<% if @callback %>
<script>window.<%= @callback %>(searchResults);</script>
<% end %>
```

**Attack:** `GET /search?q=shoes;callback=alert(document.cookie)//`

**Why vulnerable:** Cloudflare sees one parameter (`q=shoes;callback=...`). Rails splits on `;` and sees `q=shoes` plus `callback=alert(document.cookie)//`. The rendered page includes `<script>window.alert(document.cookie)//(searchResults);</script>`. Cloudflare caches this poisoned response.

**Impact:** Stored XSS via CDN cache. Arbitrary JavaScript for all users hitting the cached search results.

**Fix:**
```ruby
# Sanitize callback: @callback = params[:callback]&.gsub(/[^a-zA-Z0-9_]/, '')
# Or remove JSONP entirely and use CORS
```

### Example 3: False Positive — Private Cache-Control on Authenticated Pages

```python
@never_cache
@api_view(['GET'])
def user_profile(request):
    return Response({'username': request.user.username, 'email': request.user.email})
# Response: Cache-Control: no-cache, no-store, must-revalidate, private
```

**Why safe:** `@never_cache` adds `Cache-Control: private, no-store`. CDNs and reverse proxies that respect HTTP caching headers will not store this response. Even if unkeyed headers were injected, the response is never in a shared cache. Cache poisoning requires a shared cache serving the poisoned response to other users.

## Common False Positive Patterns

1. **Responses with `Cache-Control: private` or `no-store`**: Shared caches will not store the response. Verify the CDN actually respects these headers (some can be configured to override).

2. **Unkeyed input reflected in non-executable context**: `X-Forwarded-Host` in a `<meta>` tag or plain-text body may not be exploitable for XSS. Check for context breakout possibilities.

3. **Internal caching keyed on user ID/session**: Application caches (Redis, Memcached) keyed on user identity are effectively private. Poisoning one user's cache does not affect others.

4. **Vary header covers the unkeyed input**: `Vary: X-Forwarded-Host` creates separate cache entries per header value. Attacker's entry only served to requests with the same header. Note: some CDNs ignore custom Vary headers.

5. **Static files with no dynamic content**: Pre-built CSS/JS/images with no template rendering have no dynamic content to poison.

6. **Short cache TTL with monitoring**: TTL of 1-5 seconds limits the attack window severely. Flag as HARDENED (Low).

7. **CDN cache key includes all varying headers**: If `X-Forwarded-Host` is part of the cache key, poisoning only affects requests with the same attacker header value — effectively only the attacker.
