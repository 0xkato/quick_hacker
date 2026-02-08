# LDAP Injection Detection

## Methodology

### Step 1: Identify LDAP Libraries and Connection Points

Locate all LDAP client usage. Injection occurs in search filter construction and DN composition.

**Python (ldap3 / python-ldap):**
```python
conn.search('dc=example,dc=com', f'(uid={username})')    # DANGEROUS
l.search_s(base, ldap.SCOPE_SUBTREE, filterstr)          # Injection target
```

**Java (JNDI / UnboundID):**
```java
ctx.search(base, "(uid=" + username + ")", controls);     // DANGEROUS
Filter.create("(uid=" + username + ")");                  // DANGEROUS
```

**C# / .NET:**
```csharp
searcher.Filter = "(uid=" + username + ")";               // DANGEROUS
DirectoryEntry entry = new DirectoryEntry(
    "LDAP://dc=example,dc=com/" + userDn);                // DN injection
```

### Step 2: Identify LDAP Filter Metacharacters

| Character | Hex Escape | Effect |
|---|---|---|
| `*` | `\2a` | Wildcard match |
| `(` | `\28` | Opens filter clause |
| `)` | `\29` | Closes filter clause |
| `\` | `\5c` | Escape character |
| `NUL` | `\00` | Null byte truncation |

**Authentication bypass payload:**
```
# Filter: (&(uid=USERNAME)(userPassword=PASSWORD))
# Injected username: admin)(|(uid=*
# Result: (&(uid=admin)(|(uid=*))(userPassword=anything))
```

### Step 3: Trace User Input into Filter and DN Strings

```python
# VULNERABLE: direct string interpolation
search_filter = f'(&(uid={username})(userPassword={password}))'
conn.search('dc=example,dc=com', search_filter)
```

```python
# VULNERABLE: DN injection in bind
dn = f"uid={username},ou=users,dc=example,dc=com"
conn = Connection(server, user=dn, password=password)
```

### Step 4: Check for Proper Escaping and Parameterization

```python
# SAFE: ldap3 escaping
from ldap3.utils.conv import escape_filter_chars
username_safe = escape_filter_chars(username)
```

```java
// SAFE: JNDI parameterized filter
String filter = "(uid={0})";
ctx.search(base, filter, new Object[]{username}, controls);

// SAFE: UnboundID typed Filter API
Filter filter = Filter.createEqualityFilter("uid", username);
```

### Step 5: Check DN Construction for Injection

```python
from ldap3.utils.dn import escape_rdn
safe_username = escape_rdn(username)
dn = f"uid={safe_username},ou=users,dc=example,dc=com"
```

```java
String safeName = Rdn.escapeValue(username);
```

### Step 6: Check for Blind LDAP Injection

```
# Boolean-based: attacker infers data from response behavior
# (&(uid=admin)(password=a*))  -> 200 OK (character matches)
# (&(uid=admin)(password=b*))  -> 401 (no match)
```

## Decision Tree

```
User input reaches LDAP filter or DN construction?
|
+-- NO --> SAFE
|
+-- YES
    |
    +-- Filter injection path
    |   |
    |   Parameterized filter (JNDI {0}, UnboundID Filter API)?
    |   +-- YES --> SAFE
    |   +-- NO
    |       |
    |       escape_filter_chars() or equivalent?
    |       +-- YES (all metacharacters) --> SAFE
    |       +-- Partial --> HARDENED (Medium)
    |       +-- NO --> VULNERABLE (Critical)
    |
    +-- DN injection path
        |
        DN escaping applied?
        +-- YES --> SAFE
        +-- NO --> VULNERABLE (High)
```

## Real-World Examples

### Example 1: Authentication Bypass via Filter Injection

```python
@app.route('/api/auth', methods=['POST'])
def authenticate():
    data = request.get_json()
    conn.search('dc=corp,dc=com',
        f'(&(sAMAccountName={data["username"]})(userPassword={data["password"]}))',
        attributes=['cn', 'mail', 'memberOf'])
    if conn.entries:
        return jsonify({"user": conn.entries[0].cn.value}), 200
    return jsonify({"error": "Invalid credentials"}), 401
```

**Why vulnerable:** Attacker sends `{"username": "admin)(&)", "password": "anything"}`. The `(&)` is an LDAP TRUE filter, bypassing password verification.

**Impact:** Complete authentication bypass for any known user.

**Fix:**
```python
from ldap3.utils.conv import escape_filter_chars

username = escape_filter_chars(data['username'])
conn.search('dc=corp,dc=com', f'(sAMAccountName={username})', attributes=['cn'])
if conn.entries:
    user_dn = conn.entries[0].entry_dn
    auth_conn = Connection(server, user=user_dn, password=data['password'])
    if auth_conn.bind():
        return jsonify({"user": conn.entries[0].cn.value}), 200
```

### Example 2: Directory Enumeration via JNDI Filter Injection

```java
@GetMapping("/api/users/search")
public List<UserDTO> searchUsers(@RequestParam String department) {
    String filter = "(department=" + department + ")";
    NamingEnumeration<?> results = ctx.search("ou=users,dc=corp,dc=com", filter, controls);
    // ... process results
}
```

**Why vulnerable:** Injecting `Engineering)(|(objectClass=*` matches every directory object, dumping the entire user directory.

**Impact:** Full directory enumeration exposing emails, phone numbers, group memberships.

**Fix:**
```java
String filter = "(department={0})";
Object[] filterArgs = { department };
ctx.search("ou=users,dc=corp,dc=com", filter, filterArgs, controls);
```

### Example 3: DN Injection in .NET Password Reset

```csharp
public bool ResetPassword(string username, string newPassword) {
    string userDn = "CN=" + username + ",OU=Users,DC=corp,DC=com";
    DirectoryEntry user = new DirectoryEntry("LDAP://" + server + "/" + userDn);
    user.Invoke("SetPassword", new object[] { newPassword });
    user.CommitChanges();
    return true;
}
```

**Why vulnerable:** Attacker submits `username=admin,OU=Admins,DC=corp,DC=com` to change the bind DN and reset a domain admin's password.

**Impact:** Privilege escalation via arbitrary account password reset.

**Fix:**
```csharp
// Search for user by sAMAccountName, then use their actual DN
DirectorySearcher searcher = new DirectorySearcher(rootEntry);
searcher.Filter = "(sAMAccountName=" + EscapeLdapFilter(username) + ")";
SearchResult result = searcher.FindOne();
if (result == null) return false;
DirectoryEntry user = result.GetDirectoryEntry();
user.Invoke("SetPassword", new object[] { newPassword });
```

## Common False Positive Patterns

1. **JNDI parameterized filters with {0}** -- Auto-escapes metacharacters. Safe by design.

2. **UnboundID typed Filter API** -- `Filter.createEqualityFilter("uid", input)` constructs properly escaped filters.

3. **Hardcoded LDAP filters in configuration** -- Filters like `(objectClass=person)` with no user input.

4. **Spring LDAP `LdapQueryBuilder`** -- `query().where("uid").is(username)` handles escaping internally.

5. **LDAP queries with input from internal services** -- Parameters from authenticated internal APIs, not user HTTP input.

6. **Read-only lookups by session-stored DN** -- DN was validated at authentication time.

7. **LDAP connection pool configuration** -- Bind DNs in property files not influenced by runtime user input.
