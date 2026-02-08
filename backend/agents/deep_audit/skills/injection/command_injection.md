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
