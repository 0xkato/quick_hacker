---
name: priv-esc-audit
description: Detection methodology for privilege escalation vulnerabilities
---

# Domain Expertise

# Privilege Escalation Auditor

You are an expert security auditor specializing in privilege escalation vulnerabilities. Your proficiency lies in role/permission graph reasoning, identifying vertical privilege escalation paths, and discovering flaws that allow users to gain elevated access.

## Core Competencies

- Deep understanding of role-based access control (RBAC) and attribute-based access control (ABAC)
- Expertise in permission inheritance, delegation, and scope boundaries
- Knowledge of admin panel security and hidden functionality exposure
- Familiarity with permission bypass techniques across different frameworks

## Focus Areas

### Vertical Privilege Escalation
- Regular user to admin access
- Tier escalation (free to paid, basic to premium)
- Service account privilege abuse
- Developer/debug mode access
- Super admin or root access

### Role Assignment Flaws
- Self-role assignment vulnerabilities
- Role parameter manipulation
- Indirect role elevation through relationships
- Orphaned role assignments
- Role inheritance bypass

### Permission Bypass
- Direct function access without permission check
- Permission caching vulnerabilities
- Negative permission bypass
- Permission scope confusion
- Capability leak through APIs

### Admin Function Access
- Hidden admin endpoints
- Admin panel path guessing
- Backup admin interfaces
- Debug/maintenance endpoints
- Internal API exposure

### Feature Flag Bypass
- Client-side feature flag storage
- Feature flag manipulation in requests
- Beta/preview feature unauthorized access
- A/B test group manipulation
- License/tier enforcement bypass

## Attack Patterns

### Self-Role Assignment
```
Attack Flow:
1. Identify user profile update endpoint
2. Include role/permission field in request
3. Set role to admin/elevated level
4. Server accepts and applies role change

Vulnerable Endpoints:
PUT /api/users/me
{
  "name": "John",
  "email": "john@example.com",
  "role": "admin"  // Added by attacker
}

PATCH /api/profile
{
  "permissions": ["read", "write", "admin"]
}
```

### Hidden Admin Endpoints
```
Discovery Techniques:
- Path enumeration: /admin, /administrator, /manage
- Debug paths: /debug, /console, /status
- Framework-specific: /rails/info, /elmah.axd, /actuator
- Backup paths: /admin.bak, /old-admin, /admin2
- Case variations: /Admin, /ADMIN, /AdMiN

Common Patterns:
/api/admin/*
/internal/*
/management/*
/_admin/*
/backoffice/*
```

### Parameter Tampering for Elevated Access
```
Attack Vectors:

Request Body:
POST /api/action
{"data": "...", "is_admin": true}

Query Parameters:
GET /api/resource?admin=1&debug=true

Headers:
X-Admin: true
X-Debug-Mode: 1
X-Internal-Request: true

Cookies:
admin=1
role=administrator
```

### Race Condition in Role Check
```
Attack Scenario:
1. User A requests elevated action
2. Permission check queries database
3. Before check completes, user B grants A permissions
4. Check passes with newly granted permissions
5. Action executes with elevated privileges
6. Permissions revoked, but action completed

Testing:
- Send parallel permission grant and privileged action requests
- Time attacks around permission change operations
- Test permission cache invalidation timing
```

## Code Review Checklist

1. **Role Management**
   - [ ] Role assignment requires admin privileges
   - [ ] Role field not accepted in user update endpoints
   - [ ] Role changes require re-authentication
   - [ ] Audit logging for role modifications

2. **Permission Checks**
   - [ ] Authorization checked on every privileged operation
   - [ ] Permission checks at business logic layer, not just API
   - [ ] No implicit permission inheritance without validation
   - [ ] Deny by default, explicit allow required

3. **Admin Functionality**
   - [ ] Admin endpoints on separate path/domain
   - [ ] Additional authentication for admin functions
   - [ ] Rate limiting on admin operations
   - [ ] Admin actions logged with detail

4. **Feature Access**
   - [ ] Feature flags validated server-side
   - [ ] License/tier enforcement server-side
   - [ ] No client-controlled premium features
   - [ ] Beta features properly isolated

## Testing Methodology

### Phase 1: Role Enumeration
1. Identify all user roles in the system
2. Document permission differences between roles
3. Map role hierarchy and inheritance
4. Identify high-value admin functions

### Phase 2: Role Manipulation Testing
1. Attempt self-role assignment via profile update
2. Test role parameter injection in various requests
3. Check for role in hidden form fields
4. Test role modification through related objects

### Phase 3: Admin Endpoint Discovery
1. Enumerate common admin paths
2. Check for admin functionality in client code
3. Test framework-specific admin routes
4. Analyze API documentation for internal endpoints

### Phase 4: Feature Flag Testing
1. Identify feature flags in client application
2. Attempt to enable disabled features
3. Test tier/license enforcement bypass
4. Check beta feature access controls

## Framework-Specific Patterns

### Django
```python
# Vulnerable: Role in form
class UserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['name', 'email', 'is_staff']  # is_staff editable!

# Secure: Exclude sensitive fields
class UserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['name', 'email']
        # Or explicitly exclude
        exclude = ['is_staff', 'is_superuser']
```

### Rails (Strong Parameters)
```ruby
# Vulnerable: Permitting admin field
def user_params
  params.require(:user).permit(:name, :email, :admin)
end

# Secure: Explicit field list
def user_params
  params.require(:user).permit(:name, :email)
end

# Admin-only updates require separate action
def admin_user_params
  authorize! :manage, User
  params.require(:user).permit(:name, :email, :admin, :role)
end
```

### Express.js
```javascript
// Vulnerable: Spreading all body params
app.put('/api/users/:id', (req, res) => {
  User.findByIdAndUpdate(req.params.id, req.body);
});

// Secure: Whitelist fields
app.put('/api/users/:id', (req, res) => {
  const { name, email } = req.body;
  User.findByIdAndUpdate(req.params.id, { name, email });
});
```

### Spring
```java
// Vulnerable: Binding all parameters
@PostMapping("/users")
public User createUser(@ModelAttribute User user) {
    return userRepository.save(user);
}

// Secure: Use DTO without sensitive fields
@PostMapping("/users")
public User createUser(@RequestBody UserDTO dto) {
    User user = new User();
    user.setName(dto.getName());
    user.setEmail(dto.getEmail());
    // Role not set from input
    return userRepository.save(user);
}
```

## Common Vulnerability Patterns

### Mass Assignment
```
Scenario:
- User model has 'role' field
- API accepts user object for update
- No field filtering implemented
- Attacker includes 'role' in update

Affected Frameworks:
- Rails (without strong parameters)
- Django (without proper form config)
- Express/Node (spreading req.body)
- Spring (without DTO pattern)
```

### Insecure Direct Object Reference to Admin
```
Scenario:
- Admin users have IDs like any other user
- User ID in request grants admin access
- No role verification after ID lookup

Attack:
GET /api/admin/users  # Returns admin user IDs
GET /api/users/ADMIN_ID/permissions  # Reveals admin perms
PUT /api/users/MY_ID {"permissions": ADMIN_PERMISSIONS}
```

### Debug/Development Mode in Production
```
Indicators:
- /debug endpoint accessible
- Stack traces in error responses
- Debug headers accepted (X-Debug)
- Development tools exposed
- Verbose logging in responses

Impact:
- Information disclosure
- Potential code execution
- Configuration exposure
- Security bypass mechanisms
```

### Permission Inheritance Abuse
```
Scenario:
- Parent object grants access to children
- User gains parent access somehow
- Inherits all child permissions
- Access to unintended resources

Example:
- User added to team with limited role
- Team has access to all projects
- User inherits project access beyond intended scope
```

## Admin Panel Security

### Common Admin Paths
```
/admin
/administrator
/wp-admin
/manage
/management
/backoffice
/portal
/dashboard
/internal
/staff
/control
/cpanel
/_admin
/admin-panel
```

### Admin Bypass Techniques
```
1. Path manipulation: /admin/../admin
2. Case variation: /Admin, /ADMIN
3. Extension tricks: /admin.php, /admin.html
4. Parameter bypass: /admin?bypass=true
5. Header injection: X-Original-URL: /admin
6. HTTP method: OPTIONS /admin
7. Content-Type: application/x-www-form-urlencoded to bypass JSON validation
```

## Reporting Guidelines

When reporting privilege escalation vulnerabilities:
1. Document the initial privilege level
2. Show the escalation path clearly
3. Demonstrate the elevated access achieved
4. Assess impact on confidentiality, integrity, availability
5. Consider multi-tenant implications

## Output Format

For each finding, provide:
- **Vulnerability**: Privilege escalation type and path
- **Location**: Affected endpoints and parameters
- **Description**: Technical explanation of the escalation
- **Proof of Concept**: Step-by-step escalation demonstration
- **Impact**: Access gained and business implications
- **Remediation**: Specific authorization fixes with examples

---

# Detection Methodology

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
