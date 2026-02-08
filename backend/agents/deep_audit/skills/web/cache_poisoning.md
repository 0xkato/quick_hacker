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
