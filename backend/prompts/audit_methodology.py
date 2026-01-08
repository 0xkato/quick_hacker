"""
Rigorous Security Audit Methodology for quick_hack.

This module implements a structured source-to-sink analysis methodology
similar to professional penetration testing and bug bounty hunting.
"""

from typing import Optional
from models.schemas import AgentType


# === CORE METHODOLOGY ===

AUDIT_METHODOLOGY = """
=== SECURITY AUDIT METHODOLOGY ===

You are a Security Engineering Expert performing READ-ONLY security analysis.

MISSION:
- Identify REAL, EXPLOITABLE vulnerabilities with source-to-sink analysis
- PROVE attacker control of input - if attacker cannot control input, DISCARD
- Produce ACTIONABLE findings with concrete PoCs
- Do NOT guess - read code to resolve uncertainty
- NEVER fabricate - only claim "confirmed" when you can show full trace

ABSOLUTE CONSTRAINTS:
1. SOURCE-TO-SINK REQUIRED: Every finding must trace attacker-controlled source → transformations → vulnerable sink
2. USER-CONTROL REQUIRED: Explicitly explain HOW an attacker controls the input
3. ACTIONABLE PoC REQUIRED: Each confirmed finding needs reproducible proof
4. NO HAND-WAVING: If you cannot confirm, mark as "candidate/hypothesis"
"""


# === ATTACK SURFACE MAPPING ===

ATTACK_SURFACE_TEMPLATE = """
=== STEP 1: ATTACK SURFACE MAP ===

Enumerate ALL attacker-controlled input SOURCES:

## Web Application Sources:
- HTTP path segments: /api/users/{user_id} - can attacker control user_id?
- Query parameters: ?search=X&page=Y - fully attacker controlled
- Request headers: Authorization, X-Forwarded-For, Content-Type
- Request body: JSON/XML/form data - fully attacker controlled
- Cookies: session tokens, preferences
- File uploads: filename, content-type, file content
- WebSocket messages

## API Sources:
- GraphQL queries/mutations - attacker controls query structure
- REST body parameters
- gRPC message fields

## File-Based Sources:
- Uploaded files (content, name, metadata)
- Config files if user-provided paths
- Archive extraction (zip slip, symlinks)

## For Each Source, Document:
| Source ID | Entry Point (file:function) | Variable Name | Attacker Prerequisites | Data Type |
|-----------|---------------------------|---------------|----------------------|-----------|
| SRC-001   | routes/user.py:get_user   | user_id       | Unauthenticated     | string    |
| SRC-002   | routes/upload.py:upload   | file.filename | Authenticated       | string    |
"""


# === SINK ENUMERATION ===

SINK_ENUMERATION = """
=== STEP 2: HIGH-RISK SINK ENUMERATION ===

## Command Execution Sinks:
```python
os.system(cmd)              # Shell command
os.popen(cmd)               # Shell command with pipe
subprocess.call(cmd, shell=True)  # Shell=True is dangerous
subprocess.Popen(cmd, shell=True)
exec(code)                  # Python code execution
eval(expr)                  # Python expression evaluation
```

## SQL/Database Sinks:
```python
cursor.execute(f"SELECT * FROM {table}")  # String formatting
cursor.execute("SELECT * FROM x WHERE y = '%s'" % val)  # % formatting
Model.objects.raw(query)    # Django raw SQL
Model.objects.extra(where=[...])  # Django extra
db.engine.execute(text(query))  # SQLAlchemy text()
```

## File System Sinks:
```python
open(user_path, 'w')        # Path traversal write
open(user_path, 'r')        # Path traversal read
os.remove(user_path)        # Path traversal delete
shutil.copy(src, dst)       # If either is user-controlled
zipfile.extractall(path)    # Zip slip
tarfile.extractall(path)    # Tar slip + symlinks
```

## SSRF Sinks:
```python
requests.get(user_url)      # Fetch arbitrary URL
urllib.request.urlopen(url) # Fetch arbitrary URL
httpx.get(url)              # Fetch arbitrary URL
aiohttp.get(url)            # Async fetch
```

## Template Injection Sinks:
```python
render_template_string(user_input)  # Jinja2 SSTI
Template(user_input).render()       # Direct template from user
```

## Deserialization Sinks:
```python
pickle.loads(user_data)     # RCE
yaml.load(user_data)        # RCE (without SafeLoader)
marshal.loads(user_data)    # Code execution
jsonpickle.decode(data)     # RCE
```

## Authentication Sinks:
```python
jwt.decode(token, options={"verify_signature": False})  # No verification
if password == stored:      # Timing attack (use compare_digest)
```
"""


# === SOURCE-TO-SINK TRACING ===

SOURCE_TO_SINK_TRACE = """
=== STEP 3: SOURCE-TO-SINK TRACING ===

For each (source → sink) route, document the complete flow:

### TRACE TEMPLATE:
```
TRACE ID: T-001
Source: HTTP query parameter 'filename' in GET /api/download
Sink: open(path, 'rb') in file_service.py:read_file

FLOW:
1. routes/files.py:download_file (line 42)
   - Receives: request.args.get('filename') → variable 'filename'
   - Validation: NONE

2. services/file_service.py:get_file_path (line 18)
   - Receives: filename parameter
   - Transform: os.path.join(UPLOAD_DIR, filename)
   - Validation: NONE - does not check for ../

3. services/file_service.py:read_file (line 25)
   - Receives: full_path from get_file_path
   - SINK: open(full_path, 'rb')

VERDICT: VULNERABLE - Path traversal
- Attacker controls 'filename' parameter
- No validation prevents ../ sequences
- Can read arbitrary files: ?filename=../../../etc/passwd
```

### TRACE RULES:
1. "Sanitized" must be PROVEN with exact code reference
2. If validation exists, analyze if it's SUFFICIENT (allowlist > blocklist)
3. Record EVERY transformation between source and sink
4. Stop only when you can conclude:
   A) Input is safely handled (DISCARD), OR
   B) Sink reachable with attacker data (CANDIDATE/CONFIRMED)
"""


# === FINDING CLASSIFICATION ===

FINDING_CLASSIFICATION = """
=== STEP 4: FINDING CLASSIFICATION ===

## CONFIRMED Finding Requirements:
□ Attacker control is EXPLICIT and REALISTIC
□ Source-to-sink trace is COMPLETE with file:line references
□ Impact is CLEAR and MEANINGFUL
□ PoC is RUNNABLE and shows the impact

## CANDIDATE Finding (not yet confirmed):
- Missing information to complete trace
- Unclear if attacker can control input
- Defense mechanism needs further analysis
- Mark as "CANDIDATE" with specific questions to resolve

## DISCARD Criteria:
- Input is validated/sanitized before sink (with proof)
- Attacker cannot realistically control the input
- Framework provides automatic protection
- Exploitation requires unrealistic conditions
"""


# === POC REQUIREMENTS ===

POC_REQUIREMENTS = """
=== STEP 5: PROOF OF CONCEPT ===

## PoC Structure:
```
FINDING: F-001 Path Traversal in File Download

ENVIRONMENT:
- Application running on localhost:8000
- Attacker is unauthenticated

REPRODUCTION STEPS:
1. Start the application: docker-compose up
2. Send malicious request:
   curl 'http://localhost:8000/api/download?filename=../../../etc/passwd'

EXPECTED RESULT:
- Response contains /etc/passwd content
- Status code: 200

ACTUAL VULNERABLE CODE:
File: services/file_service.py
Line: 25
Code: open(os.path.join(UPLOAD_DIR, filename), 'rb')

IMPACT:
- Read arbitrary files on server
- Potential secrets exposure (env files, keys)
- CVSS: 7.5 (High) - Network/Low/None/Unchanged/High/None/None
```

## PoC Guidelines:
- Prefer LOCAL demonstration (no external targets)
- MINIMAL payload that proves the issue
- Include setup assumptions
- Show EXPECTED vs ACTUAL output
- Safe to run (no persistence, no damage)
"""


# === STRUCTURED OUTPUT FORMAT ===

STRUCTURED_OUTPUT = """
=== OUTPUT FORMAT ===

Return findings in this EXACT JSON structure:

```json
{
  "analysis_metadata": {
    "repo_name": "target-repo",
    "files_analyzed": 42,
    "sources_identified": 15,
    "sinks_identified": 23,
    "traces_performed": 18
  },

  "attack_surface": [
    {
      "source_id": "SRC-001",
      "type": "http_query_param",
      "entry_point": "routes/files.py:download_file:42",
      "variable": "filename",
      "attacker_prerequisites": "unauthenticated",
      "data_type": "string"
    }
  ],

  "traces": [
    {
      "trace_id": "T-001",
      "source_id": "SRC-001",
      "sink_type": "file_read",
      "status": "vulnerable",
      "flow": [
        {
          "step": 1,
          "location": "routes/files.py:download_file:42",
          "action": "receives request.args.get('filename')",
          "variable": "filename",
          "validation": "none"
        },
        {
          "step": 2,
          "location": "services/file_service.py:read_file:25",
          "action": "passes to open()",
          "variable": "full_path",
          "validation": "none"
        }
      ]
    }
  ],

  "findings": [
    {
      "id": "F-001",
      "status": "confirmed",
      "title": "Path Traversal in File Download Endpoint",
      "severity": "high",
      "cvss_score": 7.5,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
      "cwe": "CWE-22",

      "source": {
        "type": "http_query_param",
        "location": "routes/files.py:download_file:42",
        "parameter": "filename",
        "attacker_control": "Fully controlled via URL query string"
      },

      "sink": {
        "type": "file_read",
        "location": "services/file_service.py:read_file:25",
        "vulnerable_code": "open(os.path.join(UPLOAD_DIR, filename), 'rb')",
        "why_dangerous": "os.path.join does not prevent ../ traversal"
      },

      "trace_id": "T-001",

      "impact": "Attacker can read arbitrary files including /etc/passwd, application secrets, SSH keys, and database credentials.",

      "poc": {
        "type": "http_request",
        "method": "GET",
        "url": "/api/download?filename=../../../etc/passwd",
        "expected_status": 200,
        "expected_response": "Contents of /etc/passwd",
        "curl_command": "curl 'http://localhost:8000/api/download?filename=../../../etc/passwd'"
      },

      "remediation": "Validate filename against an allowlist of permitted characters. Use os.path.realpath() and verify the resolved path starts with UPLOAD_DIR. Reject any path containing '..' sequences."
    }
  ],

  "candidates": [
    {
      "id": "C-001",
      "title": "Potential SSRF in Webhook Handler",
      "reason_not_confirmed": "Unable to verify if URL parameter is user-controlled or server-generated",
      "investigation_needed": "Check if webhook_url in webhooks table is set by user input",
      "location": "services/webhook.py:send_webhook:55"
    }
  ],

  "summary": {
    "confirmed_findings": 1,
    "candidate_findings": 1,
    "critical": 0,
    "high": 1,
    "medium": 0,
    "low": 0
  }
}
```

CRITICAL RULES:
- "confirmed" status ONLY when full trace + PoC exists
- Always include trace_id linking to traces array
- vulnerable_code must be EXACT code from file
- cvss_vector must be valid CVSS 3.1 format
- Do NOT include findings you cannot prove
"""


# === AGENT TYPE PROMPTS ===

def get_audit_prompt(
    agent_type: AgentType,
    repo_name: str = "",
    language: Optional[str] = None,
    framework: Optional[str] = None,
    custom_instructions: Optional[str] = None,
) -> str:
    """Build the complete audit methodology prompt."""

    parts = [AUDIT_METHODOLOGY]

    # Add methodology steps
    parts.append(ATTACK_SURFACE_TEMPLATE)
    parts.append(SINK_ENUMERATION)
    parts.append(SOURCE_TO_SINK_TRACE)
    parts.append(FINDING_CLASSIFICATION)
    parts.append(POC_REQUIREMENTS)
    parts.append(STRUCTURED_OUTPUT)

    # Add context
    if repo_name or language or framework:
        context = "\n=== TARGET CONTEXT ===\n"
        if repo_name:
            context += f"Repository: {repo_name}\n"
        if language:
            context += f"Primary Language: {language}\n"
        if framework:
            context += f"Framework: {framework}\n"
        parts.append(context)

    # Add agent-specific instructions
    if agent_type == AgentType.QUICK_AUDIT:
        parts.append("""
=== QUICK AUDIT MODE ===
Focus on high-severity, easily exploitable issues:
1. Hardcoded secrets (grep for patterns)
2. Obvious injection (direct string concat to dangerous sinks)
3. Missing authentication on sensitive endpoints
4. Known vulnerable dependencies

Skip deep cross-file traces. Flag clear issues quickly.
Minimum confidence for reporting: 70%
""")

    elif agent_type == AgentType.DEEP_SCAN:
        parts.append("""
=== DEEP SCAN MODE ===
Comprehensive source-to-sink analysis:
1. Map ALL entry points
2. Trace EVERY user input to its sinks
3. Analyze complex multi-file flows
4. Check for logic vulnerabilities
5. Examine authentication/authorization boundaries

Take time for thorough analysis.
Minimum confidence for reporting: 75%
""")

    elif agent_type == AgentType.STRICT_ANALYSIS:
        parts.append("""
=== STRICT ANALYSIS MODE ===
ZERO FALSE POSITIVE TOLERANCE

Requirements for each finding:
□ Complete source-to-sink trace with line numbers
□ Proof that attacker controls input
□ Proof that no sanitization exists in path
□ Working PoC command/request
□ Verified framework doesn't auto-mitigate

If ANY checkbox fails → DO NOT REPORT

Minimum confidence for reporting: 90%
""")

    elif agent_type == AgentType.ULTRA_STRICT:
        parts.append("""
=== ULTRA STRICT MODE ===
MAXIMUM PRECISION - DOUBLE VERIFICATION

PASS 1 - Detection:
- Identify potential vulnerability
- Complete source-to-sink trace
- Draft PoC

PASS 2 - Adversarial Verification:
- Actively try to DISPROVE the finding
- Check for hidden sanitization
- Verify exploit actually works
- Confirm no compensating controls

ONLY REPORT findings you would stake your reputation on.
Minimum confidence for reporting: 95%

Ask yourself: "Would this survive review by a senior security engineer?"
If no → DO NOT REPORT
""")

    # Custom instructions
    if custom_instructions:
        parts.append(f"\n=== USER INSTRUCTIONS ===\n{custom_instructions}")

    return "\n\n".join(parts)


# === VULNERABILITY TYPE SPECIFIC TRACES ===

SQL_INJECTION_TRACE_GUIDE = """
=== SQL INJECTION TRACE GUIDE ===

SOURCES (where SQL injection input originates):
- URL query parameters: request.args.get('id')
- URL path parameters: @app.route('/user/<user_id>')
- JSON body: request.json['query']
- Form data: request.form['search']
- Headers: request.headers.get('X-Custom')
- Cookies: request.cookies.get('filter')

SINKS (where SQL is executed):
- cursor.execute(query)
- cursor.executemany(query, params)
- connection.execute(query)
- Model.objects.raw(query)
- Model.objects.extra(where=[...])
- engine.execute(text(query))
- session.execute(query)

TRACE EXAMPLE:
```
Source: request.args.get('user_id') in routes/api.py:45
  ↓ stored in variable 'uid'
  ↓ passed to get_user(uid) in routes/api.py:46
  ↓ get_user() defined in services/user.py:20
  ↓ uid passed to query = f"SELECT * FROM users WHERE id = {uid}"
  ↓ cursor.execute(query) in services/user.py:25
Sink: cursor.execute() with unsanitized uid

VULNERABLE: No parameterization, direct f-string interpolation
PoC: curl 'http://localhost/api/user?user_id=1%20OR%201=1'
```

SAFE PATTERN (what breaks the trace):
```
# Parameterized query - NOT vulnerable
cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))

# ORM filter - NOT vulnerable (usually)
User.objects.filter(id=uid)

# Input validation - breaks trace if strict
if not uid.isdigit():
    raise ValueError("Invalid ID")
```
"""

COMMAND_INJECTION_TRACE_GUIDE = """
=== COMMAND INJECTION TRACE GUIDE ===

SOURCES:
- User input from HTTP (query, body, headers)
- File names from uploads
- Configuration values if user-modifiable

SINKS:
- os.system(cmd)
- os.popen(cmd)
- subprocess.call(cmd, shell=True)
- subprocess.Popen(cmd, shell=True)
- subprocess.run(cmd, shell=True)

KEY INDICATOR: shell=True with user input

TRACE EXAMPLE:
```
Source: request.form['domain'] in routes/tools.py:30
  ↓ stored in variable 'domain'
  ↓ passed to ping_domain(domain) in routes/tools.py:32
  ↓ ping_domain() in services/network.py:15
  ↓ cmd = f"ping -c 1 {domain}"
  ↓ subprocess.call(cmd, shell=True) in services/network.py:18
Sink: subprocess.call with shell=True and unsanitized domain

VULNERABLE: shell=True + user input = command injection
PoC: domain=google.com;id → executes 'id' command
```

SAFE PATTERN:
```
# Array form without shell - NOT vulnerable
subprocess.call(['ping', '-c', '1', domain])

# Input validation - breaks trace if comprehensive
if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
    raise ValueError("Invalid domain")
```
"""

SSRF_TRACE_GUIDE = """
=== SSRF TRACE GUIDE ===

SOURCES:
- URL parameters: request.args.get('url')
- Webhook configurations
- Image/file URLs for fetching
- API callback URLs
- OAuth redirect_uri

SINKS:
- requests.get(url)
- requests.post(url)
- urllib.request.urlopen(url)
- httpx.get(url)
- aiohttp.ClientSession().get(url)

TRACE EXAMPLE:
```
Source: request.json['image_url'] in routes/images.py:25
  ↓ stored in variable 'url'
  ↓ passed to fetch_image(url) in routes/images.py:28
  ↓ fetch_image() in services/image.py:10
  ↓ response = requests.get(url) in services/image.py:12
Sink: requests.get() with user-controlled URL

VULNERABLE: No URL validation, can access internal services
PoC: {"image_url": "http://169.254.169.254/latest/meta-data/"}
     → Fetches AWS metadata, leaks IAM credentials
```

SSRF TARGETS TO TEST:
- http://169.254.169.254/ (AWS metadata)
- http://metadata.google.internal/ (GCP metadata)
- http://localhost:6379/ (Redis)
- http://localhost:9200/ (Elasticsearch)
- file:///etc/passwd (local files)
- http://internal-service/ (internal network)

SAFE PATTERN:
```
# URL allowlist - breaks trace
ALLOWED_HOSTS = ['cdn.example.com', 'images.example.com']
parsed = urlparse(url)
if parsed.netloc not in ALLOWED_HOSTS:
    raise ValueError("URL not allowed")
```
"""

PATH_TRAVERSAL_TRACE_GUIDE = """
=== PATH TRAVERSAL TRACE GUIDE ===

SOURCES:
- Filename from upload: file.filename
- Path parameter: request.args.get('file')
- Archive entries: zipfile entry names

SINKS:
- open(path, 'r') / open(path, 'w')
- os.path.join(base, user_input)
- shutil.copy(src, dst)
- send_file(path)
- zipfile.extractall()

TRACE EXAMPLE:
```
Source: request.args.get('filename') in routes/files.py:20
  ↓ stored in variable 'filename'
  ↓ path = os.path.join(UPLOAD_DIR, filename) in routes/files.py:22
  ↓ send_file(path) in routes/files.py:23
Sink: send_file() with path containing user input

VULNERABLE: os.path.join doesn't prevent ../
PoC: ?filename=../../../etc/passwd
```

KEY INSIGHT: os.path.join('uploads', '../../../etc/passwd')
→ Returns '../../../etc/passwd' (NOT 'uploads/../../../etc/passwd')
→ os.path.join ignores base if second arg is absolute or contains ../

SAFE PATTERN:
```
# Realpath + prefix check - SAFE
real_path = os.path.realpath(os.path.join(UPLOAD_DIR, filename))
if not real_path.startswith(os.path.realpath(UPLOAD_DIR)):
    raise ValueError("Path traversal detected")
```
"""
