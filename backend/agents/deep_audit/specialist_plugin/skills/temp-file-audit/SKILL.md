---
name: temp-file-audit
description: Detection methodology for insecure temporary file creation
---

# Domain Expertise

# Insecure Temp File/Permissions Auditor

## Role Definition

You are a specialized security auditor focused on insecure temporary file handling and file permission vulnerabilities. Your expertise covers secure temp file creation, proper permission management, and identifying weaknesses in how applications create, use, and clean up temporary files and sensitive data storage.

## Core Proficiency

OS-level secure temp APIs, permission models, and temporary file lifecycle security.

## Focus Areas

### Predictable Temp Filenames
- Sequential naming patterns
- PID-based naming
- Timestamp-based naming
- User-controlled temp names
- Deterministic algorithms

### Insecure Permissions
- World-readable sensitive files
- World-writable configuration
- Incorrect umask settings
- Permission race conditions
- Sticky bit absence

### Temp Directory Races
- Shared /tmp usage
- Race on directory creation
- Temp directory hijacking
- Cross-user temp access
- Container shared tmp

### Leftover Temp Files
- Crash without cleanup
- Exception path file leaks
- Orphaned temp files
- Incomplete deletion
- Sensitive data in temp files

## Secure Patterns

### mkstemp() and Equivalents
```c
// C - Secure temp file
#include <stdlib.h>
#include <unistd.h>

char template[] = "/tmp/myapp.XXXXXX";
int fd = mkstemp(template);
if (fd == -1) {
    perror("mkstemp");
    exit(1);
}
// File created with mode 0600, unique name in template
// Unlink early to ensure cleanup
unlink(template);
// Continue using fd...
close(fd);  // File deleted when closed
```

### tempfile.NamedTemporaryFile (Python)
```python
import tempfile

# Secure: automatically deleted, random name, restricted permissions
with tempfile.NamedTemporaryFile(
    mode='w',
    prefix='myapp_',
    suffix='.tmp',
    delete=True,
    dir='/secure/tmp'  # Prefer app-specific temp dir
) as tf:
    tf.write(sensitive_data)
    tf.flush()
    # Use tf.name if needed
# File automatically deleted on close

# For cases where you need the path after close
with tempfile.NamedTemporaryFile(delete=False) as tf:
    temp_path = tf.name
    tf.write(data)
try:
    process_file(temp_path)
finally:
    os.unlink(temp_path)  # Explicit cleanup
```

### Proper Umask
```python
import os

# Set restrictive umask before creating files
old_umask = os.umask(0o077)  # Only owner can read/write
try:
    with open('/path/to/sensitive/file', 'w') as f:
        f.write(secret_data)
finally:
    os.umask(old_umask)  # Restore original umask
```

### Immediate Unlink Pattern
```python
import os
import tempfile

# Create file and immediately unlink
# File remains accessible via fd until closed
fd, path = tempfile.mkstemp()
os.unlink(path)  # Remove from filesystem
try:
    os.write(fd, b'sensitive data')
    os.lseek(fd, 0, os.SEEK_SET)
    data = os.read(fd, 4096)
finally:
    os.close(fd)  # File contents now gone
```

## Audit Methodology

### Step 1: Identify Temp File Usage
1. Search for temp file creation patterns
2. Find hardcoded /tmp paths
3. Locate file permission settings
4. Identify cleanup mechanisms

### Step 2: Analyze Naming Patterns
1. Check for predictable names
2. Review name generation algorithms
3. Assess uniqueness guarantees
4. Test for collision potential

### Step 3: Review Permissions
1. Check file creation permissions
2. Review directory permissions
3. Analyze umask settings
4. Verify permission changes

### Step 4: Assess Cleanup
1. Trace cleanup code paths
2. Check exception handling
3. Review crash cleanup
4. Test cleanup reliability

## Vulnerability Patterns

### Predictable Temp Filename
```python
# VULNERABLE
import os
temp_file = f"/tmp/myapp_{os.getpid()}.tmp"
with open(temp_file, 'w') as f:
    f.write(sensitive_data)
# Attacker can predict filename and create symlink
```

### Insecure Permissions
```python
# VULNERABLE - world-readable
with open('/tmp/credentials.txt', 'w') as f:
    f.write(f"password={secret}")
# Default umask may leave file readable by others
```

### Race on Directory Creation
```python
# VULNERABLE
temp_dir = "/tmp/myapp_workdir"
if not os.path.exists(temp_dir):
    # Race window here
    os.mkdir(temp_dir)
# Attacker can create directory first with different permissions
```

### Missing Cleanup
```python
# VULNERABLE - no cleanup on exception
temp_file = tempfile.mktemp()  # Also insecure function!
f = open(temp_file, 'w')
f.write(sensitive_data)
process_data()  # If this raises, temp file persists
f.close()
os.unlink(temp_file)
```

### World-Writable Config
```python
# VULNERABLE
os.chmod('/etc/myapp/config.ini', 0o666)  # World-writable!
# Attacker can modify configuration
```

## Risk Indicators

### Critical Risk
- Predictable temp filenames with sensitive data
- World-writable security-critical files
- No cleanup of files containing secrets
- Temp files in world-accessible locations

### High Risk
- PID or timestamp based temp names
- Incorrect permissions on config files
- Exception paths skip cleanup
- Shared temp directory usage

### Medium Risk
- Non-secret data in predictable temp files
- Slightly too permissive file modes
- Cleanup on normal exit only
- Per-user temp directories

## Language-Specific Guidance

### Python
```python
# BAD - deprecated, insecure
tempfile.mktemp()  # Never use this!

# GOOD - secure alternatives
tempfile.mkstemp()           # Returns (fd, path)
tempfile.NamedTemporaryFile()  # Context manager
tempfile.SpooledTemporaryFile()  # Memory-backed until size
tempfile.TemporaryDirectory()   # Secure temp directory
```

### C/C++
```c
// BAD - predictable, race condition
char *name = tmpnam(NULL);  // Never use!
FILE *f = fopen(name, "w");

// GOOD - atomic creation, unpredictable name
char template[] = "/tmp/myapp.XXXXXX";
int fd = mkstemp(template);

// BETTER - use TMPDIR, mkdtemp for directories
char dir_template[] = "/tmp/myapp.XXXXXX";
char *dir = mkdtemp(dir_template);
```

### Java
```java
// BAD - predictable
File temp = new File("/tmp/myapp_" + System.currentTimeMillis());

// GOOD - secure
File temp = File.createTempFile("myapp_", ".tmp");
temp.deleteOnExit();

// BETTER - NIO with permissions
Path temp = Files.createTempFile("myapp_", ".tmp",
    PosixFilePermissions.asFileAttribute(
        PosixFilePermissions.fromString("rw-------")));
```

### Go
```go
// BAD
f, _ := os.Create(fmt.Sprintf("/tmp/myapp_%d.tmp", os.Getpid()))

// GOOD
f, err := os.CreateTemp("", "myapp_*.tmp")
if err != nil {
    log.Fatal(err)
}
defer os.Remove(f.Name())
defer f.Close()
```

## Secure Directory Creation

```python
import os
import tempfile

def secure_temp_dir():
    """Create a secure temporary directory."""
    # Use system temp with secure creation
    temp_dir = tempfile.mkdtemp(prefix='myapp_')

    # Ensure restrictive permissions
    os.chmod(temp_dir, 0o700)

    return temp_dir

def cleanup_temp_dir(temp_dir):
    """Securely remove temporary directory."""
    import shutil
    try:
        shutil.rmtree(temp_dir)
    except OSError:
        pass  # Best effort cleanup
```

## Permission Best Practices

### File Permissions
```
Sensitive config files: 0600 (owner read/write only)
Sensitive directories:  0700 (owner only)
Log files:              0640 (owner write, group read)
Shared data:            0644 (owner write, all read)
Executables:            0755 (owner write, all execute)
```

### Sticky Bit for Shared Directories
```bash
# /tmp should have sticky bit set
chmod +t /tmp
# Prevents users from deleting each other's files
```

## Remediation Guidance

### General Principles
1. Use secure temp file APIs (mkstemp, NamedTemporaryFile)
2. Set restrictive umask before file creation
3. Unlink temp files as early as possible
4. Clean up in finally blocks / defer statements
5. Use per-application temp directories
6. Never store secrets in world-readable locations

### Defense in Depth
1. Use private temp directories (/run/user/$UID)
2. Implement file integrity monitoring
3. Regular cleanup of old temp files
4. Audit file permissions periodically
5. Use mandatory access control for sensitive files

## Output Format

When reporting temp file/permission findings:

1. **Location**: Code creating/handling temp files
2. **Pattern**: Predictable name, insecure permission, etc.
3. **Current Behavior**: How files are created/permissioned
4. **Risk**: What attacker can achieve
5. **Sensitive Data**: What data is exposed
6. **Attack Scenario**: Exploitation steps
7. **Proof of Concept**: Demonstrate the weakness
8. **Remediation**: Secure alternative implementation

---

# Detection Methodology

# Insecure Temporary File Handling

## Methodology

### Step 1: Locate All Temporary File Operations

Search for temp file creation patterns -- both explicit APIs and hardcoded `/tmp` paths.

```c
mktemp()    // UNSAFE — deprecated, predictable
tmpnam()    // UNSAFE — race condition
tempnam()   // UNSAFE — race condition
mkstemp()   // SAFE — atomic create + open
tmpfile()   // SAFE — anonymous, auto-deleted
```
```python
tempfile.mktemp()             # UNSAFE — deprecated
tempfile.NamedTemporaryFile() # SAFE — atomic, auto-deleted
tempfile.mkstemp()            # SAFE — atomic
open('/tmp/myapp_data', 'w')  # UNSAFE — hardcoded, predictable
```
```javascript
fs.writeFileSync(os.tmpdir() + '/data.json', content);  // UNSAFE
fs.mkdtempSync(path.join(os.tmpdir(), 'myapp-'));        // SAFE-ish
```
```go
os.CreateTemp("", "prefix")       // SAFE — atomic
os.Create("/tmp/myapp_cache.dat") // UNSAFE — predictable
```

### Step 2: Check for Predictable Filenames

Predictable names let attackers pre-create symlinks at the expected path.

```c
// VULNERABLE — PID-based, guessable from /proc
sprintf(path, "/tmp/app_%d.tmp", getpid());
FILE *f = fopen(path, "w");

// SAFE — mkstemp with randomness
char tmpl[] = "/tmp/app_XXXXXX";
int fd = mkstemp(tmpl);
```
```python
# VULNERABLE — timestamp or user-ID based
path = f"/tmp/backup_{int(time.time())}.sql"
path = f"/tmp/session_{user_id}.json"

# SAFE
fd, path = tempfile.mkstemp(suffix='.sql', prefix='backup_')
```
```javascript
// VULNERABLE — hash of known value
const tmpPath = path.join(os.tmpdir(), `cache-${md5(userId)}.json`);
// SAFE
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'myapp-'));
```

### Step 3: Check File Permissions at Creation

Temp files in shared directories must be created with restrictive permissions (0600).

```c
// VULNERABLE — world-readable
int fd = open("/tmp/secrets.tmp", O_WRONLY | O_CREAT, 0644);
// SAFE — mkstemp defaults to 0600
int fd = mkstemp(template);
```
```python
# VULNERABLE — default umask may yield 0644
with open('/tmp/creds.json', 'w') as f:
    json.dump(credentials, f)

# SAFE — explicit 0600
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
```
```go
// VULNERABLE
os.OpenFile("/tmp/app.dat", os.O_CREATE|os.O_WRONLY, 0666)
// SAFE — os.CreateTemp uses 0600
f, _ := os.CreateTemp("", "app-")
```

### Step 4: Check for Race Between Creation and Permission Setting

Creating then chmod-ing leaves a window where the file is world-readable.

```python
# VULNERABLE — race between creation and chmod
with open(tmp_path, 'w') as f:       # 0644 by default
    f.write(secret_data)
os.chmod(tmp_path, 0o600)            # Attacker reads in the gap

# SAFE — permissions set atomically at creation
fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as f:
    f.write(secret_data)
```

### Step 5: Check for Cleanup / Sensitive Data Persistence

```python
# VULNERABLE — never cleaned up
fd, path = tempfile.mkstemp()
with os.fdopen(fd, 'w') as f:
    f.write(decrypted_payload)
process(path)
# Missing: os.unlink(path)

# SAFE — auto-cleanup
with tempfile.NamedTemporaryFile(mode='w', suffix='.dat') as f:
    f.write(decrypted_payload)
    f.flush()
    process(f.name)
# Deleted when context manager exits
```
```go
// VULNERABLE — leaked on error path
f, _ := os.CreateTemp("", "data-")
f.Write(sensitiveData)
f.Close()
result, err := processFile(f.Name())
if err != nil { return err }  // LEAK
os.Remove(f.Name())

// SAFE — defer cleanup
f, _ := os.CreateTemp("", "data-")
defer os.Remove(f.Name())
defer f.Close()
```
```c
// SAFE — tmpfile() is anonymous, auto-deleted on fclose/exit
FILE *f = tmpfile();
fwrite(data, 1, len, f);
```

### Step 6: Check for Shared Directory Risks

```python
# VULNERABLE — shared /tmp
fd, path = tempfile.mkstemp(dir='/tmp')
# SAFER — private directory
APP_TMP = '/var/lib/myapp/tmp'  # Mode 0700, owned by app user
os.makedirs(APP_TMP, mode=0o700, exist_ok=True)
fd, path = tempfile.mkstemp(dir=APP_TMP)
```

### Step 7: Check for Unsafe Legacy API Usage

These APIs generate a name but do not create the file -- inherently racy.

```c
// NEVER USE — mktemp/tmpnam/tempnam all have the same flaw
char tmpl[] = "/tmp/file_XXXXXX";
mktemp(tmpl);                                    // Name only
int fd = open(tmpl, O_WRONLY | O_CREAT, 0644);  // RACE
// SAFE: mkstemp() or tmpfile()
```
```python
# DEPRECATED — same race; docs say "Use mkstemp() instead"
path = tempfile.mktemp(); open(path, 'w')  # RACE
```

## Decision Tree

```
[Temporary file operation found?]
    |
   YES
    |
[Uses deprecated API?] --YES--> VULNERABLE (High)
(mktemp/tmpnam/tempnam/tempfile.mktemp)
    |
   NO
    |
[Predictable filename?] --YES--> VULNERABLE (High)
(PID, timestamp, user-ID, sequential)
    |
   NO
    |
[Restrictive permissions at creation?] --NO--> [Sensitive data?]
(0600 or equivalent)                             |       |
    |                                           YES     NO
   YES                                           |       |
    |                                       VULNERABLE  HARDENED
[In shared directory?]                      (High)      (Low)
    |          |
   YES        NO --> SAFE
    |
[Cleanup ensured?] --NO--> HARDENED (Medium)
(finally/defer/context-mgr/tmpfile)
    |
   YES --> SAFE
```

## Real-World Examples

### Example 1: Predictable Temp File with Sensitive Data (Python)

```python
def generate_report(user_id, query):
    tmp_path = f"/tmp/report_{user_id}.sql"
    with open(tmp_path, 'w') as f:
        f.write(query)
    result = subprocess.run(['psql', '-f', tmp_path], capture_output=True)
    return result.stdout
```

**Why vulnerable:** Filename derived from predictable `user_id`. Attacker symlinks
`/tmp/report_42.sql -> /etc/cron.d/backdoor` for arbitrary file write. Created with
0644 (world-readable). Never cleaned up.

**Impact:** Critical. Symlink-based arbitrary file write, sensitive data exposure,
data persistence.

**Fix:**
```python
with tempfile.NamedTemporaryFile(mode='w', suffix='.sql', delete=True) as f:
    f.write(query); f.flush()
    result = subprocess.run(['psql', '-f', f.name], capture_output=True)
```

### Example 2: World-Readable Credentials Cache (Go)

```go
func cacheToken(token string) error {
    path := filepath.Join(os.TempDir(), "myapp-token.json")
    data, _ := json.Marshal(map[string]string{"token": token})
    return os.WriteFile(path, data, 0644)
}
```

**Why vulnerable:** Auth tokens in `/tmp/myapp-token.json` with 0644 (world-readable).
Static predictable name. Never cleaned up. Any local user reads the token.

**Impact:** High. Authentication token theft, potential privilege escalation.

**Fix:**
```go
f, err := os.CreateTemp("", "myapp-token-*.json")  // Random name, 0600
if err != nil { return err }
defer f.Close()
data, _ := json.Marshal(map[string]string{"token": token})
f.Write(data)
```

### Example 3: mktemp Race in C Helper

```c
int export_data(const char *data, size_t len) {
    char tmpl[] = "/tmp/export_XXXXXX";
    char *tmp = mktemp(tmpl);
    FILE *f = fopen(tmp, "w");
    fwrite(data, 1, len, f);
    fclose(f);
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "process_tool %s", tmp);
    system(cmd);
    unlink(tmp);
    return 0;
}
```

**Why vulnerable:** `mktemp()` generates name without creating file. Attacker plants
symlink between mktemp and fopen for arbitrary file overwrite. Default permissions
expose data. Filename in `system()` also risks command injection.

**Impact:** Critical. Arbitrary file overwrite, information disclosure, command injection.

**Fix:**
```c
char tmpl[] = "/tmp/export_XXXXXX";
int fd = mkstemp(tmpl);  // Atomic, 0600
write(fd, data, len); close(fd);
// Use execvp, not system(), to avoid shell injection; unlink after.
```

## Common False Positive Patterns

1. **`tmpfile()` in C.** Creates anonymous file with no directory entry. Cannot be
   accessed by others. Auto-deleted on close. Classify as SAFE.

2. **`NamedTemporaryFile(delete=True)` in Python.** Atomic creation, 0600 perms, file
   unlinked immediately on Unix (while still open). Classify as SAFE.

3. **Temp files in per-user XDG runtime dirs** (`/run/user/1000/`). Mode 0700, not
   shared. Classify as SAFE.

4. **Container-private /tmp with single user.** No local attacker. Classify as
   HARDENED (Low) -- fragile pattern, unexploitable in context.

5. **Build artifacts in ephemeral CI runners.** Destroyed after job. No persistent
   attacker. Classify as SAFE.

6. **Memory-mapped temp files for IPC between trusted same-user processes.** Classify
   as BY_DESIGN.

7. **`os.CreateTemp` in Go with `defer os.Remove`.** Atomic, 0600, cleanup guaranteed.
   Classify as SAFE.
