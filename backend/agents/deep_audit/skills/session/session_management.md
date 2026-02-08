# Session Management Vulnerability Detection

## Methodology

### Step 1: Identify the Session Mechanism

Map how sessions work before hunting for flaws:

1. **Storage backend:** Server-side (Redis, DB, filesystem), client-side (signed cookies), or hybrid
2. **Session ID generation:** Framework default (CSPRNG) vs custom logic (high risk)
3. **Lifecycle events:** Creation, promotion (pre-auth → post-auth), destruction, rotation
4. **Transport:** Cookie flags (`HttpOnly`, `Secure`, `SameSite`), URL param, custom header

### Step 2: Hunt for Session Fixation

Session fixation occurs when a pre-auth session ID survives authentication, letting an attacker set a known ID and wait for the victim to log in.

**Flask — no rotation on login:**
```python
@app.route("/login", methods=["POST"])
def login():
    user = authenticate(request.form["username"], request.form["password"])
    if user:
        session["user_id"] = user.id  # Promotes existing session — no ID rotation!
        return redirect("/dashboard")
```

**Django — safe by default** (login() calls `session.cycle_key()`):
```python
from django.contrib.auth import login
def login_view(request):
    user = authenticate(request, username=username, password=password)
    if user:
        login(request, user)  # cycle_key() rotates session ID automatically
```

**Express — must call regenerate():**
```javascript
app.post('/login', (req, res) => {
    const user = authenticate(req.body.username, req.body.password);
    if (user) {
        req.session.regenerate((err) => {  // Without this → fixation
            req.session.userId = user.id;
            res.redirect('/dashboard');
        });
    }
});
```

**Java HttpSession:**
```java
// VULNERABLE: req.getSession() reuses existing session
request.getSession().setAttribute("user", user);
// FIX: invalidate old, create new
HttpSession old = request.getSession(false);
if (old != null) old.invalidate();
HttpSession fresh = request.getSession(true);
fresh.setAttribute("user", user);
```

### Step 3: Analyze Session ID Entropy

Predictable IDs let attackers guess valid sessions. Red flags: sequential integers, timestamps, `Math.random()`, Python `random` module.

```python
# VULNERABLE: non-cryptographic PRNG
import random, hashlib
def gen_id(username):
    return hashlib.md5(f"{username}{random.randint(0,9999)}".encode()).hexdigest()

# SAFE: CSPRNG
import secrets
def gen_id():
    return secrets.token_hex(32)
```

### Step 4: Check Session Invalidation on Security Events

Sessions must be destroyed on: logout, password change, role change, account lock.

```python
# VULNERABLE: partial cleanup on logout
@app.route("/logout")
def logout():
    session.pop("user_id", None)  # Session still exists, other keys persist
    return redirect("/login")

# FIX: full destruction
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")
```

Also check: does password change invalidate sessions on other devices?

### Step 5: Evaluate Session Lifetime

Check absolute timeout (max age), idle timeout (inactivity), and re-auth for sensitive actions.

```python
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=365)  # Way too long!
# Reasonable: timedelta(hours=8)
```

### Step 6: Detect Client-Side Session Tampering

When data lives in cookies, verify integrity protection:

```python
app.secret_key = "changeme"     # Weak — attacker can forge Flask sessions
app.secret_key = os.urandom(32) # Strong — 256-bit random
# Flask sessions are signed but NOT encrypted — never store secrets in them
```

```javascript
// VULNERABLE: unsigned client-side data
res.cookie('user', JSON.stringify({ id: 1, role: 'admin' }));
// Attacker modifies role directly
```

### Step 7: Classify

- **VULNERABLE (Critical)**: Session fixation — no ID rotation on login
- **VULNERABLE (Critical)**: Predictable session IDs (sequential, weak PRNG)
- **VULNERABLE (High)**: Session not invalidated on logout
- **VULNERABLE (High)**: Unsigned client-side session data
- **HARDENED (Medium)**: Session not invalidated on password change
- **HARDENED (Medium)**: Session lifetime >24h without re-auth for sensitive ops
- **HARDENED (Low)**: Missing idle timeout
- **SAFE**: Framework CSPRNG IDs, proper rotation, server-side storage, reasonable lifetime
- **BY_DESIGN**: Long-lived "remember me" with revocation and sensitive-action re-auth

## Decision Tree

```
Is the app using sessions (cookies, server-side store)?
├── No (stateless JWT/API key) → See jwt.md / auth_bypass.md
└── Yes → How are session IDs generated?
    ├── Custom logic without CSPRNG → VULNERABLE (Critical)
    └── Framework default / CSPRNG → Does session ID rotate on login?
        ├── No → VULNERABLE (Critical)
        └── Yes → Session destroyed on logout?
            ├── No → VULNERABLE (High)
            └── Yes → Invalidated on password change?
                ├── No → HARDENED (Medium)
                └── Yes → Check lifetime and storage
                    ├── >24h, no re-auth → HARDENED (Medium)
                    ├── Client-side without signing / weak key → VULNERABLE (High)
                    └── Server-side, reasonable lifetime → SAFE
```

## Real-World Examples

### Example 1: Flask Session Fixation with Weak Secret

```python
app = Flask(__name__)
app.secret_key = "development-key"

@app.route("/login", methods=["POST"])
def login():
    user = db.authenticate(request.form["username"], request.form["password"])
    if user:
        session["user_id"] = user.id
        session["role"] = user.role
        return redirect("/dashboard")
    return "Invalid credentials", 401

@app.route("/logout")
def logout():
    session.pop("authenticated", None)
    return redirect("/login")
```

**Why vulnerable:** No session rotation on login (fixation). Weak secret key (forgery). Logout removes one key, leaving `user_id` and `role` in the session.

**Impact:** Attacker sets a known session cookie, victim logs in, attacker gains authenticated access. Weak key also allows direct session forgery.

**Fix:** Use `os.urandom(32)` for secret, call `session.clear()` before setting post-auth data, and on logout.

### Example 2: Express Session Without Regeneration

```javascript
app.use(session({
    secret: 'keyboard-cat',
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 }  // 30 days
}));

app.post('/api/login', async (req, res) => {
    const user = await authenticate(req.body.email, req.body.password);
    if (user) {
        req.session.user = { id: user.id, email: user.email };
        return res.json({ success: true });
    }
    res.status(401).json({ error: 'Invalid credentials' });
});
```

**Why vulnerable:** `saveUninitialized: true` creates anonymous sessions. No `req.session.regenerate()` on login. Weak secret. 30-day lifetime without idle timeout.

**Impact:** Session fixation plus long-lived stolen session cookies grant persistent access.

**Fix:** Use `saveUninitialized: false`, call `req.session.regenerate()` on login, use crypto-random secret, set reasonable `maxAge` with `httpOnly`, `secure`, `sameSite` flags.

### Example 3: Java Servlet Session Fixation

```java
@WebServlet("/login")
public class LoginServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        User user = authService.authenticate(req.getParameter("username"), req.getParameter("password"));
        if (user != null) {
            req.getSession().setAttribute("user", user);
            req.getSession().setMaxInactiveInterval(604800);  // 7 days
            resp.sendRedirect("/dashboard");
        }
    }
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        req.getSession().removeAttribute("user");  // Logout — session not invalidated
        resp.sendRedirect("/login");
    }
}
```

**Why vulnerable:** `getSession()` reuses existing session (fixation). 7-day idle timeout is excessive. Logout removes attribute but does not call `invalidate()`.

**Impact:** Attacker injects JSESSIONID via subdomain cookie or URL rewriting, victim authenticates, attacker hijacks session.

**Fix:** Invalidate old session, create new one on login. Call `session.invalidate()` on logout. Use 30-minute idle timeout.

## Common False Positive Patterns

1. **Django's `login()` function** automatically calls `session.cycle_key()` for rotation. Do not flag standard Django login views.

2. **Pre-auth session data carryover** (shopping carts, UI preferences) is fine if the session ID itself is rotated on login.

3. **Token-based auth (JWT, API keys)** — session fixation/management findings do not apply when cookies are not used for authentication.

4. **"Remember me" with separate long-lived tokens** that require re-auth for sensitive actions and support revocation are acceptable by design.

5. **Session regeneration in middleware** rather than the login handler — check the full request lifecycle before concluding rotation is missing.

6. **Flask-Login's `login_user()`** combined with `SESSION_PROTECTION = "strong"` provides session rotation despite Flask not doing it natively.

7. **Load balancer sticky session IDs** are infrastructure routing identifiers, not application session tokens.
