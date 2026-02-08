# XPath Injection Detection

## Methodology

### Step 1: Identify XPath Evaluation Entry Points

Locate all code evaluating XPath expressions against XML documents.

**Python (lxml / xml.etree):**
```python
tree = etree.parse('data.xml')
result = tree.xpath(f"//user[@name='{name}']")           # DANGEROUS
result = tree.findall(f".//user[@name='{name}']")        # DANGEROUS
```

**Java (javax.xml.xpath):**
```java
XPath xpath = XPathFactory.newInstance().newXPath();
xpath.evaluate("//user[@name='" + username + "']", doc); // DANGEROUS
```

**C# / .NET:**
```csharp
doc.SelectNodes("//user[@name='" + username + "']");     // DANGEROUS
nav.Select("//user[@name='" + username + "']");          // DANGEROUS
```

**Node.js (xpath / xmldom):**
```javascript
xpath.select("//user[@name='" + name + "']", doc);       // DANGEROUS
```

### Step 2: Understand XPath Injection Payloads

**Authentication bypass (tautology):**
```
Original:  //user[@name='USERNAME' and @password='PASSWORD']
Payload:   username = admin' or '1'='1
Result:    //user[@name='admin' or '1'='1' and @password='x' or '1'='1']
```

**Data extraction via union:** `admin']/email | //user/password | //x[@a='`

**Blind XPath (character extraction):**
```
//user[substring(password,1,1)='a' and @name='admin']
//user[string-length(password)>5 and @name='admin']
```

### Step 3: Trace User Input to XPath Expressions

```python
# VULNERABLE: direct interpolation
@app.route('/api/user')
def get_user():
    username = request.args.get('username', '')
    xpath_query = f"//users/user[@name='{username}']/profile"
    results = tree.xpath(xpath_query)
```

### Step 4: Check for XPath-Specific Defenses

XPath has limited parameterization support. Defenses rely on validation or escaping.

**Input validation:**
```python
if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
    return 'Invalid username', 400
```

**Quote escaping with concat():**
```python
def escape_xpath(value):
    if "'" not in value: return f"'{value}'"
    elif '"' not in value: return f'"{value}"'
    else:
        parts = value.split("'")
        return "concat(" + ",\"'\",".join(f"'{p}'" for p in parts) + ")"
```

**Java XPathVariableResolver (parameterized):**
```java
xpath.setXPathVariableResolver(name ->
    "username".equals(name.getLocalPart()) ? sanitizedUsername : null);
xpath.evaluate("//users/user[@name=$username]/profile", document);
```

### Step 5: Assess XML Data Sensitivity

Impact depends on the XML content. Authentication data, API keys, and PII in XML files make XPath injection critical. Public catalog data is lower risk.

### Step 6: Check for XPath 2.0+ Extended Features

XPath 2.0 adds `doc()` for reading other files (`doc('/etc/passwd')`) and `string-join()` for bulk extraction.

## Decision Tree

```
User input reaches XPath expression evaluation?
|
+-- NO --> SAFE
|
+-- YES
    |
    XPath variable resolver / parameterization used?
    +-- YES --> SAFE
    +-- NO
        |
        Strict whitelist validation (alphanumeric only)?
        +-- YES --> SAFE
        +-- NO
            |
            Quote escaping (concat() method, both quote types)?
            +-- YES --> HARDENED (Low)
            +-- Partial --> HARDENED (Medium)
            +-- NO
                |
                Sensitive data or auth decisions?
                +-- YES --> VULNERABLE (Critical)
                +-- NO  --> VULNERABLE (High)
```

## Real-World Examples

### Example 1: XML-Based Authentication Bypass

```python
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    tree = etree.parse('users.xml')
    query = f"//user[@username='{username}' and @password='{password}']"
    user = tree.xpath(query)
    if user:
        session['user'] = user[0].get('username')
        return redirect('/dashboard')
```

**Why vulnerable:** Attacker submits `username=admin' or '1'='1`. The tautology bypasses password verification due to XPath operator precedence.

**Impact:** Complete authentication bypass.

**Fix:**
```python
if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
    return render_template('login.html', error='Invalid username')
# Find by username, verify password in Python
user = tree.xpath(f"//user[@username='{username}']")
if user and hmac.compare_digest(user[0].get('password'), hash_password(password)):
    session['user'] = user[0].get('username')
```

### Example 2: Blind XPath Injection in Java Config API

```java
@GetMapping("/api/config")
public ResponseEntity<String> getConfig(@RequestParam String key) {
    String expression = "//config/setting[@key='" + key + "']/@value";
    String value = xpath.evaluate(expression, configDocument);
    return value.isEmpty() ? ResponseEntity.notFound().build() : ResponseEntity.ok(value);
}
```

**Why vulnerable:** Blind injection extracts data character-by-character: `key=x' or substring(//config/setting[@key='secret']/@value,1,1)='a`.

**Impact:** Exposure of all configuration values including database credentials and API keys.

**Fix:**
```java
Set<String> allowedKeys = Set.of("app.name", "app.version", "feature.flags");
if (!allowedKeys.contains(key)) return ResponseEntity.badRequest().body("Invalid key");
xpath.setXPathVariableResolver(name ->
    "key".equals(name.getLocalPart()) ? key : null);
xpath.evaluate("//config/setting[@key=$key]/@value", configDocument);
```

### Example 3: XPath Injection in .NET Product Search

```csharp
[HttpGet("api/products/search")]
public IActionResult SearchProducts(string category, string maxPrice) {
    string xpath = "//product[@category='" + category + "' and @price<=" + maxPrice + "]";
    XmlNodeList results = doc.SelectNodes(xpath);
    // ... process results
}
```

**Why vulnerable:** Both parameters are injectable. `category='] | //* | //x[@a='` dumps all XML nodes. `maxPrice=999] | //*[1=1` bypasses via numeric injection.

**Impact:** Full XML document exfiltration.

**Fix:**
```csharp
var validCategories = new HashSet<string> { "electronics", "books", "clothing" };
if (!validCategories.Contains(category.ToLower())) return BadRequest("Invalid category");
// Use XPathVariableResolver equivalent or validate maxPrice as decimal
```

## Common False Positive Patterns

1. **Hardcoded XPath expressions** -- `doc.SelectNodes("//config/database/host")` with no user input.

2. **ElementTree findall with static paths** -- `tree.findall('.//item')` with no dynamic components.

3. **XPath in XSLT stylesheets** -- Developer-authored expressions in `.xsl` files not generated from user input.

4. **XPath variable resolvers** -- Java `XPathVariableResolver` binding input as typed variables (`$username`).

5. **XPath in XML schema validation** -- `xs:selector` and `xs:field` are schema-level, not runtime-injectable.

6. **Read-only XPath on public data** -- Queries against non-sensitive data. Classify HARDENED (Low) since injection mechanism exists.

7. **Test code and XML fixtures** -- XPath in test suites operating on test fixtures, not reachable in production.
