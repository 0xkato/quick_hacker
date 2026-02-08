# Vertical Privilege Escalation Detection

Vertical privilege escalation occurs when a user accesses functionality reserved for a
higher privilege level. Unlike IDOR (horizontal access to peer resources), this is about
climbing the privilege ladder: user to admin, viewer to editor, free-tier to premium.
The root cause: the backend trusts the client to declare its own privilege level, or
omits authorization checks entirely after authentication succeeds.

## Methodology

### Step 1: Map the Role Hierarchy

Enumerate every distinct privilege level. Look in database schemas, enum definitions,
role constants, and middleware configurations.

```python
# Django/Flask — roles in models
class UserRole(models.TextChoices):
    VIEWER = "viewer"; EDITOR = "editor"; ADMIN = "admin"

class User(db.Model):
    role = db.Column(db.String(20), default="user")
    is_admin = db.Column(db.Boolean, default=False)
```

```java
// Spring Security — granted authorities
@Entity
public class User {
    @ElementCollection(fetch = FetchType.EAGER)
    private Set<String> roles = new HashSet<>();
}
```

### Step 2: Identify All Elevated Endpoints

Search for route registrations referencing admin or elevated-role functionality.

```python
# Django urls.py
urlpatterns = [path("admin/users/", admin_views.user_list)]

# Express
router.get("/admin/users", adminController.listUsers);
router.post("/admin/users/:id/ban", adminController.banUser);
```

```java
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/admin/users")
public List<UserDTO> getAllUsers() { ... }
```

Flag any elevated endpoint lacking an authorization decorator or middleware guard.

### Step 3: Trace the Authorization Check

For every elevated endpoint, verify it checks the role from a trusted source (server
session, validated JWT claim) and NOT from a client-supplied value.

```python
# VULNERABLE: role from request body
@app.route("/api/update-role", methods=["POST"])
def update_role():
    if request.json.get("is_admin"):        # attacker sets true
        current_user.is_admin = True; db.session.commit()

# SAFE: role from server-side session
@app.route("/admin/dashboard")
@login_required
def admin_dashboard():
    if not current_user.is_admin: abort(403) # from DB, not request
```

```javascript
// VULNERABLE: JWT decoded without verification
const payload = JSON.parse(atob(token.split('.')[1]));
if (payload.role === 'admin') { /* grant */ }

// SAFE: signature verified
const verified = jwt.verify(token, SECRET_KEY);
if (verified.role === 'admin') { /* grant */ }
```

### Step 4: Check for Frontend-Only Guards

Search for admin UI hidden on frontend but no corresponding backend check.

```javascript
// Frontend hides button — NOT a security control
{user.role === 'admin' && <button onClick={deleteUser}>Delete</button>}

// Backend MUST independently verify — VULNERABLE if no check:
app.delete("/api/users/:id", (req, res) => {
    User.findByIdAndDelete(req.params.id);  // no role check
});
```

### Step 5: Inspect Role Modification Endpoints

Verify only sufficiently privileged users can change roles, and cannot self-escalate.

```python
# VULNERABLE: no hierarchy check
@app.route("/api/users/<int:uid>/role", methods=["PUT"])
@login_required
def set_role(uid):
    user = User.query.get(uid)
    user.role = request.json["role"]       # attacker sends "superadmin"
    db.session.commit()

# SAFE: enforces privilege hierarchy
def set_role(uid):
    new_role = request.json["role"]
    if ROLE_RANK[new_role] >= ROLE_RANK[current_user.role]:
        abort(403, "Cannot assign role at or above your own")
```

### Step 6: Check JWT/Cookie Manipulation

Look for weak signing, alg:none attacks, or role stored in unsigned cookies.

```python
# VULNERABLE: role in unsigned cookie
role = request.cookies.get("role", "user")  # attacker edits cookie

# VULNERABLE: JWT alg:none
token = jwt.decode(token_str, options={"verify_signature": False})
```

### Step 7: Test Mass Assignment

Check if user-update endpoints allow setting privileged fields.

```python
# VULNERABLE: mass assignment
User.query.filter_by(id=current_user.id).update(request.json)
# attacker sends {"name": "Alice", "is_admin": true}

# SAFE: whitelist allowed fields
ALLOWED = {"name", "email", "bio"}
filtered = {k: v for k, v in data.items() if k in ALLOWED}
User.query.filter_by(id=current_user.id).update(filtered)
```

## Decision Tree

```
[Endpoint requires elevated privileges?]
    +--NO--> SAFE (no privilege boundary)
    +--YES
        [Authorization check present on backend?]
            +--NO--> VULNERABLE (Critical)
            +--YES
                [Role from trusted origin? (DB, verified JWT, session)]
                    +--NO--> VULNERABLE (Critical)
                    +--YES
                        [Role modification endpoint?]
                            +--YES--> [Hierarchy check?]
                            |   +--NO--> VULNERABLE (High)
                            |   +--YES--> [Mass assignment blocked?]
                            |       +--NO--> VULNERABLE (High)
                            |       +--YES--> SAFE
                            +--NO--> [JWT signing verified?]
                                +--NO--> VULNERABLE (Critical)
                                +--YES--> SAFE
```

## Real-World Examples

### Example 1: Django View Missing Permission Check

```python
class AdminUserListView(LoginRequiredMixin, ListView):
    model = User
    template_name = "admin/user_list.html"
    # No PermissionRequiredMixin — any logged-in user can access
```

**Why vulnerable:** `LoginRequiredMixin` checks authentication, not authorization.
Any logged-in user navigates directly to `/admin/users/`.

**Impact:** Full read access to user list; if update/delete views match, full account
takeover capability.

**Fix:**
```python
class AdminUserListView(LoginRequiredMixin, UserPassesTestMixin, ListView):
    model = User
    def test_func(self):
        return self.request.user.is_staff
```

### Example 2: Express Registration Accepts Role from Body

```javascript
app.post("/api/register", async (req, res) => {
    const { email, password, role } = req.body;
    const user = await User.create({ email, password: hash(password), role: role || "user" });
});
```

**Why vulnerable:** Attacker sends `{"role":"admin"}` in registration body. The
`|| "user"` default only applies when role is omitted entirely.

**Impact:** Instant admin access. Complete application compromise.

**Fix:**
```javascript
const { email, password } = req.body;  // role NOT destructured
await User.create({ email, password: hash(password), role: "user" }); // hardcoded
```

### Example 3: Spring Security Role in Unsigned Cookie

```java
@GetMapping("/api/admin/config")
public ResponseEntity<Config> getConfig(HttpServletRequest request) {
    for (Cookie c : request.getCookies()) {
        if ("user_role".equals(c.getName()) && "ADMIN".equals(c.getValue()))
            return ResponseEntity.ok(configService.getAll());
    }
    return ResponseEntity.status(403).build();
}
```

**Why vulnerable:** Role read from client-controlled cookie. Attacker adds
`Cookie: user_role=ADMIN` to bypass all authorization.

**Impact:** Unauthenticated admin access to system configuration.

**Fix:**
```java
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/api/admin/config")
public ResponseEntity<Config> getConfig() { return ResponseEntity.ok(configService.getAll()); }
```

## Common False Positive Patterns

1. **Internal microservice-to-microservice calls** carrying service account tokens with
   admin privileges by design. Verify endpoints are not externally reachable.

2. **Django built-in admin** `is_superuser` checks are intentional framework behavior,
   not a vulnerability, if the admin site is properly access-controlled.

3. **Feature flags gating UI** that appear to be privilege checks but are rollout
   mechanisms. Backend enforces real authorization separately.

4. **Test/dev endpoints** with `@admin_required` only registered when `DEBUG=True`.
   Not reachable in production. Verify conditional registration is robust.

5. **GraphQL introspection** revealing admin mutations is information disclosure, not
   privilege escalation. Mutations may still be guarded by resolver-level role checks.

6. **Role in properly signed JWT** (RS256/ES256) is tamper-proof. This is safe by design
   as long as the signing key is not compromised.

7. **OAuth scope-based access** where elevated scopes are granted during consent flow.
   Scope is enforced by the authorization server, not the client.
