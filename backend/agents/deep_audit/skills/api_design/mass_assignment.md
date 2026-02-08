# Mass Assignment / Over-Posting Detection

Mass assignment occurs when an application binds HTTP request parameters directly to
an internal data model without allowlisting permitted fields. An attacker sends
`is_admin=true` or `role=superuser` and the application blindly persists it.

## Methodology

### Step 1: Identify Request-to-Model Binding Points

Locate code where HTTP request data flows into an ORM constructor or update method.

```python
# Django — DANGEROUS: ModelForm without explicit `fields`
class UserForm(forms.ModelForm):
    class Meta:
        model = User  # no `fields` or `exclude`

# Flask/SQLAlchemy — DANGEROUS: dict-spread into model
user = User(**request.json)
db.session.add(user)

# Pydantic — DANGEROUS: extra fields accepted
class UserUpdate(BaseModel):
    class Config:
        extra = "allow"
```

```javascript
// Mongoose — DANGEROUS: entire req.body into create
const user = await User.create(req.body);
await User.findOneAndUpdate({ _id: id }, req.body);

// Sequelize — same pattern
await User.create(req.body);
```

```java
// Spring — DANGEROUS: Jackson deserializes to entity
@PostMapping("/users")
public ResponseEntity<?> create(@RequestBody User user) {
    return ResponseEntity.ok(userRepository.save(user));
}
```

```ruby
# Rails — DANGEROUS: permit! allows ALL parameters
User.create(params.require(:user).permit!)
User.new(params[:user].to_unsafe_h)
```

### Step 2: Trace the Full Data Path

Follow the flow: `HTTP body -> controller binding -> validation -> model -> database`.
At each stage, check whether allowed fields are explicitly narrowed.

```python
# SAFE: explicit field selection
user.name = data.get("name")
user.email = data.get("email")

# VULNERABLE: pass-through binding
for key, value in data.items():
    setattr(user, key, value)
```

### Step 3: Check for Allowlist Mechanisms

| Framework       | Safe Pattern                                       |
|-----------------|----------------------------------------------------|
| Django          | `ModelForm` with explicit `fields = [...]`         |
| Flask/SQLAlchemy| Marshmallow schema with explicit fields            |
| Pydantic        | `extra = "forbid"` or `extra = "ignore"`           |
| Mongoose        | Schema `select: false` + explicit field pick       |
| Sequelize       | `attributes` whitelist on create/update            |
| Spring Boot     | `@JsonIgnore` on sensitive fields, or DTO pattern  |
| Rails           | `params.require(:x).permit(:name, :email)`         |

### Step 4: Identify Sensitive Fields

Fields that must never be client-settable:

- **Auth:** `role`, `is_admin`, `is_staff`, `is_superuser`, `permissions`
- **Financial:** `balance`, `credits`, `subscription_tier`
- **Ownership:** `user_id`, `owner_id`, `tenant_id`
- **State:** `verified`, `email_confirmed`, `status`, `approved`
- **Audit:** `created_at`, `updated_at`, `password_hash`

### Step 5: Verify DTO / View-Model Separation

The strongest defense: a DTO structurally separate from the persistence model.

```python
class UserCreateRequest(BaseModel):  # DTO — no role or is_admin field
    name: str
    email: str

class User(SQLAlchemyBase):          # Model — has sensitive fields
    name: str
    email: str
    role: str
    is_admin: bool
```

```java
public class UserCreateDTO {         // No role or isAdmin
    private String name;
    private String email;
}
```

### Step 6: Test for Nested Object Assignment

Mass assignment hides in nested objects. A profile update accepting an embedded
`organization` object may contain privileged fields like `plan` or `tier`.

```javascript
// VULNERABLE: nested mass assignment
// Body: { "profile": { "name": "Alice", "org": { "plan": "enterprise" } } }
await User.findByIdAndUpdate(id, req.body, { new: true });
```

## Decision Tree

```
REQUEST DATA FLOWS INTO MODEL/ORM?
|
+--NO--> SAFE
|
+--YES
   |
   EXPLICIT FIELD ALLOWLIST PRESENT?
   |
   +--YES
   |  |
   |  ALLOWLIST EXCLUDES ALL SENSITIVE FIELDS?
   |  +--YES--> SAFE
   |  +--NO---> VULNERABLE (Critical)
   |
   +--NO
      |
      SEPARATE DTO / INPUT SCHEMA USED?
      |
      +--YES
      |  |
      |  DTO CONTAINS NO SENSITIVE FIELDS?
      |  +--YES--> SAFE
      |  +--NO---> VULNERABLE (Critical)
      |
      +--NO
         |
         MODEL HAS SENSITIVE FIELDS?
         +--YES--> VULNERABLE (Critical)
         +--NO---> HARDENED (Medium) — fragile, any new field auto-exposes
```

## Real-World Examples

### Example 1: Django ModelForm Without `fields`

```python
class User(models.Model):
    username = models.CharField(max_length=150)
    email = models.EmailField()
    is_superuser = models.BooleanField(default=False)

class RegistrationForm(forms.ModelForm):
    class Meta:
        model = User  # fields is MISSING

def register(request):
    form = RegistrationForm(request.POST)
    if form.is_valid():
        form.save()
```

**Why vulnerable:** No `fields` attribute means Django binds every model field.
Attacker sends `is_superuser=true` and escalates on registration.

**Impact:** Full privilege escalation. Any user becomes superuser.

**Fix:** Add `fields = ["username", "email"]` to the Meta class.

### Example 2: Express + Mongoose Unfiltered Body

```javascript
const userSchema = new mongoose.Schema({
  name: String, email: String,
  role: { type: String, default: "user" },
  credits: { type: Number, default: 0 },
});

app.post("/api/users", async (req, res) => {
  const user = await User.create(req.body);
  res.json(user);
});
```

**Why vulnerable:** `req.body` passes directly to `create()`. Attacker sends
`{ "role": "admin", "credits": 99999 }`.

**Impact:** Privilege escalation and financial fraud.

**Fix:** Destructure allowed fields: `const { name, email } = req.body;`

### Example 3: Spring Boot Entity Binding

```java
@Entity
public class Account {
    @Id @GeneratedValue private Long id;
    private String name;
    private String role;
    private BigDecimal balance;
}

@PostMapping("/accounts")
public Account create(@RequestBody Account account) {
    return accountRepository.save(account);
}
```

**Why vulnerable:** Jackson deserializes the full JSON body into the entity.
Attacker sends `{ "role": "ADMIN", "balance": 1000000 }`.

**Impact:** Authorization bypass and financial manipulation.

**Fix:** Use a `AccountCreateDTO` with only `name` and `email` fields. Map to entity
server-side with `role="USER"` and `balance=ZERO`.

## Common False Positive Patterns

1. **Admin-only endpoints with RBAC middleware.** `PUT /admin/users/:id` accepting
   all fields is intentional if gated behind verified admin auth.

2. **Internal service-to-service calls.** Trusted microservice callers passing full
   model data is acceptable if the endpoint is not externally reachable.

3. **Explicit DTO with overlapping field names.** A DTO sharing names with the model
   but structurally excluding sensitive fields is safe.

4. **ORM update with server-generated dict.** If the dict passed to `update()` is
   built from server logic (not request data), no mass assignment vector exists.

5. **Pydantic `extra="allow"` for forwarding.** APIs accepting extra fields for
   downstream forwarding or logging without persisting them to the DB.

6. **Rails `permit!` in test/seed code.** Only flag in production controllers,
   not in `test/`, `spec/`, or `db/seeds.rb`.

7. **Schema migration or export code.** Reading all columns for data migration
   is not mass assignment if it accepts no external input.
