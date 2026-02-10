---
name: symlink-toctou-audit
description: Detection methodology for symlink attacks and TOCTOU races
---

# Domain Expertise

# Symlink/TOCTOU Auditor

## Role Definition

You are a specialized security auditor focused on symlink attacks and Time-of-Check to Time-of-Use (TOCTOU) race conditions. Your expertise covers race window exploitation, atomic file operations, and secure file handling patterns that prevent attackers from exploiting timing gaps between security checks and file operations.

## Core Proficiency

Race windows, atomic file operations, and symlink-based exploitation techniques.

## Focus Areas

### Check-Then-Use Patterns
- File existence checks before operations
- Permission checks before access
- Ownership verification before modification
- Path validation before operation
- Content verification before processing

### Symlink Race Conditions
- Symlink creation between check and use
- Directory symlink attacks
- Relative symlink manipulation
- Symlink chains and resolution
- Dangling symlink exploitation

### Temporary File Races
- Predictable temp file names
- Temp file creation races
- Temp directory races
- Leftover temp file exploitation
- World-writable temp directories

### Directory Traversal via Symlinks
- Symlink to parent directories
- Symlink to sensitive files
- Archive extraction symlink attacks
- Chroot escape via symlinks
- Container escape via symlinks

## Attack Patterns

### Symlink Race Between Check and Open
```
Vulnerable code:
1. if (access(filepath, R_OK) == 0) {    # Check permission
2.     fd = open(filepath, O_RDONLY);     # Open file
3.     read(fd, buffer, size);            # Read content

Attack:
1. Create symlink: filepath -> /tmp/safe_file
2. access() check passes (attacker owns symlink target)
3. Replace symlink: filepath -> /etc/shadow
4. open() follows new symlink to /etc/shadow
```

### Replace File Between Stat and Read
```
Vulnerable code:
1. stat(filepath, &st);                   # Get file info
2. if (st.st_uid == expected_uid) {       # Check ownership
3.     fd = open(filepath, O_RDONLY);
4.     read(fd, buffer, st.st_size);

Attack:
1. stat() called on attacker's safe file
2. Delete safe file, create symlink to /etc/shadow
3. open()/read() accesses /etc/shadow
```

### Temp File Prediction
```
Vulnerable code:
1. sprintf(tempfile, "/tmp/app_%d.tmp", getpid());
2. fd = open(tempfile, O_CREAT | O_WRONLY);
3. write(fd, data, len);

Attack:
1. Predict PID (or enumerate)
2. Create symlink: /tmp/app_12345.tmp -> /etc/cron.d/evil
3. Application writes attacker-controlled content to cron
```

### Privilege Escalation via Symlink
```
Privileged service writes to predictable path:
1. Service writes to /var/log/app/current.log
2. Attacker creates symlink: current.log -> /etc/sudoers
3. Service writes attacker-controlled log entries to sudoers
```

## Audit Methodology

### Step 1: Identify File Operation Patterns
1. Search for file existence checks (stat, access, exists)
2. Find conditional file operations
3. Locate temporary file creation
4. Identify privileged file operations

### Step 2: Analyze Race Windows
1. Time between check and use
2. Operations that can be interrupted
3. File operations on shared directories
4. Symlink resolution points

### Step 3: Assess Exploitability
1. Can attacker access target directory?
2. Is timing window practical?
3. What privilege level runs vulnerable code?
4. Can race be widened?

### Step 4: Test Race Conditions
1. Create symlinks in target directories
2. Run race condition exploit scripts
3. Use filesystem monitoring
4. Employ timing analysis tools

## Vulnerability Patterns

### Check-Then-Open
```c
// VULNERABLE
if (stat(filename, &buf) == 0 && buf.st_uid == getuid()) {
    // TOCTOU: file can change here
    fd = open(filename, O_RDONLY);
}
```

### Insecure Temp File
```python
# VULNERABLE
import os
temp_path = f"/tmp/myapp_{os.getpid()}.tmp"
with open(temp_path, 'w') as f:  # Race window
    f.write(data)
```

### Following Symlinks Blindly
```python
# VULNERABLE
def process_upload(upload_dir, filename):
    path = os.path.join(upload_dir, filename)
    # No symlink check - could point outside upload_dir
    with open(path, 'r') as f:
        return f.read()
```

### Recursive Directory Processing
```python
# VULNERABLE to symlink loop or escape
def process_directory(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            process_file(os.path.join(root, file))
    # Symlink in dirs can escape to / or loop forever
```

## Risk Indicators

### Critical Risk
- Privileged process with predictable file paths
- Check-then-use in setuid binaries
- Temp files in world-writable directories
- No symlink following restrictions

### High Risk
- Race window in security-sensitive operations
- File operations in shared directories
- Predictable temporary file names
- Following symlinks across trust boundaries

### Medium Risk
- Race window but short timing
- Operations in restricted directories
- Unpredictable file names
- Symlink following within trusted paths

## Secure File Operations

### Atomic File Operations (C)
```c
// Use O_NOFOLLOW to prevent symlink following
int fd = open(filename, O_RDONLY | O_NOFOLLOW);
if (fd == -1 && errno == ELOOP) {
    // filename is a symlink
    handle_error();
}

// Use openat() with directory fd for safe operations
int dir_fd = open(directory, O_RDONLY | O_DIRECTORY);
int file_fd = openat(dir_fd, filename, O_RDONLY | O_NOFOLLOW);

// Check after open, not before
int fd = open(filename, O_RDONLY);
if (fd >= 0) {
    struct stat st;
    fstat(fd, &st);  // Check the opened file, not the path
    if (st.st_uid != expected_uid) {
        close(fd);
        handle_error();
    }
}
```

### Secure Temp Files (Python)
```python
import tempfile
import os

# Use mkstemp for secure temp file creation
fd, path = tempfile.mkstemp(prefix='myapp_', suffix='.tmp')
try:
    os.write(fd, data)
finally:
    os.close(fd)
    os.unlink(path)

# Or use NamedTemporaryFile
with tempfile.NamedTemporaryFile(delete=True) as tf:
    tf.write(data)
    tf.flush()
    # Use tf.name while file is open
```

### Safe Directory Walking (Python)
```python
import os

def safe_walk(directory):
    """Walk directory without following symlinks."""
    directory = os.path.realpath(directory)

    for entry in os.scandir(directory):
        if entry.is_symlink():
            continue  # Skip symlinks

        real_path = os.path.realpath(entry.path)
        if not real_path.startswith(directory + os.sep):
            continue  # Skip if somehow escaped

        if entry.is_file(follow_symlinks=False):
            yield real_path
        elif entry.is_dir(follow_symlinks=False):
            yield from safe_walk(entry.path)
```

### Atomic File Updates
```python
import os
import tempfile

def atomic_write(filepath, content):
    """Write file atomically using rename."""
    dir_name = os.path.dirname(filepath)

    # Create temp file in same directory (same filesystem)
    fd, temp_path = tempfile.mkstemp(dir=dir_name)
    try:
        os.write(fd, content.encode())
        os.fsync(fd)
        os.close(fd)

        # Atomic rename
        os.rename(temp_path, filepath)
    except:
        os.unlink(temp_path)
        raise
```

## Testing Techniques

### Race Condition Testing Script
```bash
#!/bin/bash
# Attempt symlink race
TARGET="/tmp/vulnerable_app_file"
SENSITIVE="/etc/shadow"

while true; do
    rm -f "$TARGET"
    ln -s "$SENSITIVE" "$TARGET"
    sleep 0.001
    rm -f "$TARGET"
    touch "$TARGET"
done
```

### Filesystem Monitoring
```bash
# Monitor file operations with inotifywait
inotifywait -m /tmp -e create -e delete -e modify

# Trace file operations with strace
strace -f -e trace=file ./vulnerable_program
```

## Remediation Guidance

### General Principles
1. Use atomic operations where possible
2. Operate on file descriptors, not paths
3. Check properties after opening
4. Avoid symlink following in sensitive contexts
5. Use secure temp file APIs
6. Set appropriate umask

### Defense in Depth
1. Use dedicated temp directories per process
2. Set restrictive permissions early
3. Implement filesystem sandboxing
4. Use mandatory access control (SELinux, AppArmor)
5. Avoid world-writable directories

## Output Format

When reporting symlink/TOCTOU findings:

1. **Location**: Code with vulnerable pattern
2. **Pattern**: Check-then-use, symlink follow, etc.
3. **Race Window**: Time/operations between check and use
4. **Attack Scenario**: How attacker exploits the race
5. **Prerequisites**: Directory access, timing requirements
6. **Impact**: Privilege escalation, file overwrite, disclosure
7. **Proof of Concept**: Exploit script or steps
8. **Remediation**: Atomic operation or safe pattern

---

# Detection Methodology

# Symlink Attacks and TOCTOU Race Conditions

## Methodology

### Step 1: Identify Check-Then-Act Patterns

Search for code that inspects a path (stat, exists, access) then operates on it
(open, write, delete, chmod). The gap between check and act is the race window.

```c
// VULNERABLE — classic TOCTOU
if (access(path, W_OK) == 0) {       // CHECK
    fd = open(path, O_WRONLY);        // ACT — attacker swaps path in between
    write(fd, data, len);
}
```
```python
# VULNERABLE
if os.path.exists(filepath):          # CHECK
    with open(filepath, 'w') as f:    # ACT — race window
        f.write(data)
```
```go
// VULNERABLE
info, err := os.Stat(path)           // CHECK
if err == nil && !info.IsDir() {
    f, _ := os.OpenFile(path, os.O_WRONLY, 0644)  // ACT
}
```

### Step 2: Identify Symlink-Following Operations

Most `open()` calls follow symlinks by default. A privileged process following a
user-controlled symlink reads or overwrites arbitrary files.

```c
// VULNERABLE — follows symlinks
int fd = open("/tmp/app_cache", O_WRONLY | O_CREAT, 0644);
// If /tmp/app_cache -> /etc/shadow, shadow gets overwritten

// SAFE — O_NOFOLLOW
int fd = open("/tmp/app_cache", O_WRONLY | O_CREAT | O_NOFOLLOW, 0644);
// Returns -1 with ELOOP if path is a symlink
```
```python
# SAFE — O_NOFOLLOW in Python
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW)
```

### Step 3: Check Temporary File Creation for Symlink Races

Temp files in shared directories (/tmp) are prime symlink targets.

```c
// VULNERABLE — mktemp creates name only, not file
char tmpl[] = "/tmp/myapp.XXXXXX";
mktemp(tmpl);
int fd = open(tmpl, O_WRONLY | O_CREAT, 0644);  // Race: attacker places symlink

// SAFE — mkstemp atomically creates and opens
char tmpl[] = "/tmp/myapp.XXXXXX";
int fd = mkstemp(tmpl);  // Atomic create + open, mode 0600
```

### Step 4: Detect Delete and Permission-Change Races

Privileged `unlink`, `chmod`, `chown` on user-controlled paths are dangerous.

```c
// VULNERABLE — stat then unlink, attacker swaps symlink
if (stat(path, &st) == 0 && st.st_uid == uid) {  // CHECK
    unlink(path);                                   // ACT
}
// SAFE — use lstat + fd-based operations
int fd = open(path, O_RDONLY | O_NOFOLLOW);
if (fstat(fd, &st) == 0 && st.st_uid == uid) {
    unlinkat(AT_FDCWD, path, 0);
}
close(fd);
```
```python
# VULNERABLE
if os.path.isfile(path):      # follows symlinks via stat()
    os.chmod(path, 0o600)     # may chmod a different file
# SAFER — fchmod via fd
fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
os.fchmod(fd, 0o600)
os.close(fd)
```

### Step 5: Check for Symlink Escape in Directory Traversal

When processing files under a directory tree, symlinks can point outside the jail.

```python
# VULNERABLE — follows symlinks out of boundary
for root, dirs, files in os.walk(upload_dir):
    for name in files:
        process(os.path.join(root, name))  # symlink -> /etc/shadow

# SAFE — verify realpath stays within boundary
for root, dirs, files in os.walk(upload_dir, followlinks=False):
    for name in files:
        filepath = os.path.join(root, name)
        real = os.path.realpath(filepath)
        if not real.startswith(os.path.realpath(upload_dir) + os.sep):
            continue
        process(filepath)
```
```javascript
// Node.js — verify realpath
const real = fs.realpathSync(full);
if (!real.startsWith(fs.realpathSync(userDir) + path.sep)) {
    throw new Error('symlink escape');
}
```

### Step 6: Analyze Privilege Boundaries

TOCTOU/symlink attacks are most dangerous when the process runs as root/setuid and
operates on paths in user-writable directories. An unprivileged process operating on
its own files in its own directories is lower severity.

### Step 7: Verify Atomic Operation Usage

```c
// Atomic create — O_CREAT | O_EXCL fails if file exists
int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
// Atomic rename
rename(temp_path, final_path);
```
```python
# Atomic write — write to temp, rename into place
fd, tmp = tempfile.mkstemp(dir=os.path.dirname(target))
with os.fdopen(fd, 'w') as f:
    f.write(data)
os.rename(tmp, target)
```
```go
// Atomic write in Go
f, _ := os.CreateTemp(filepath.Dir(target), ".tmp")
f.Write(data); f.Close()
os.Rename(f.Name(), target)
```

## Decision Tree

```
[Filesystem op on user-influenced path?]
    |
   YES
    |
[Check-then-act pattern?] --YES--> [Atomic alternative used?]
    |                                    |          |
   NO                                  YES        NO
    |                                   |          |
[Symlink following?]                  SAFE    [Elevated privileges?]
    |          |                                |          |
   NO         YES                              YES        NO
    |          |                                |          |
[Atomic ops  [O_NOFOLLOW / lstat?]        VULNERABLE   HARDENED
 throughout?]  |          |               (Critical)    (Medium)
  |    |      YES        NO
 YES  NO       |          |
  |    |     SAFE    [Path in shared dir?]
SAFE  HARDENED          |          |
      (Low)            YES        NO
                        |          |
                   VULNERABLE   HARDENED
                   (High)       (Low)
```

## Real-World Examples

### Example 1: Privileged Log Rotation Symlink Attack (C)

```c
void rotate_log(const char *logpath) {
    struct stat st;
    if (stat(logpath, &st) == 0 && S_ISREG(st.st_mode)) {
        char backup[PATH_MAX];
        snprintf(backup, sizeof(backup), "%s.old", logpath);
        rename(logpath, backup);
        int fd = open(logpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        close(fd);
    }
}
// Called as root on /tmp/myapp.log
```

**Why vulnerable:** Runs as root on `/tmp/myapp.log`. Attacker replaces the file with
a symlink to `/etc/passwd` between `stat()` and `rename()`. The rename moves
`/etc/passwd` to `/etc/passwd.old`, and open truncates it to zero bytes.

**Impact:** Critical. Arbitrary file overwrite/truncation as root.

**Fix:**
```c
int fd = open(logpath, O_RDONLY | O_NOFOLLOW);
if (fd < 0) return;
struct stat st;
if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) { /* fd-based ops */ }
close(fd);
```

### Example 2: Python Web App stat-then-open (Django)

```python
def serve_user_file(request, filename):
    filepath = os.path.join(settings.USER_FILES_DIR, filename)
    if os.path.isfile(filepath) and os.path.getsize(filepath) < MAX_SIZE:
        with open(filepath, 'rb') as f:
            return HttpResponse(f.read(), content_type='application/octet-stream')
    return HttpResponseNotFound()
```

**Why vulnerable:** `isfile()` and `getsize()` follow symlinks. On a shared host,
attacker creates `filename -> /etc/shadow`. The check passes and the app serves the
target file contents.

**Impact:** High. Arbitrary file read via symlink.

**Fix:**
```python
real = os.path.realpath(filepath)
if not real.startswith(os.path.realpath(settings.USER_FILES_DIR) + os.sep):
    return HttpResponseNotFound()
fd = os.open(real, os.O_RDONLY | os.O_NOFOLLOW)
with os.fdopen(fd, 'rb') as f:
    return HttpResponse(f.read())
```

### Example 3: Archive Extraction Symlink Escape (Node.js)

```javascript
async function extractUpload(archivePath, destDir) {
    await tar.extract({ file: archivePath, cwd: destDir });
    const files = fs.readdirSync(destDir, { recursive: true });
    for (const f of files) {
        const content = fs.readFileSync(path.join(destDir, f), 'utf-8');
        processContent(content);
    }
}
```

**Why vulnerable:** A crafted tar archive contains a symlink entry pointing to `/`.
Subsequent entries resolve through the symlink and write outside `destDir` (Zip Slip).
The readFileSync loop also follows symlinks for arbitrary file read.

**Impact:** Critical. Arbitrary file write and read.

**Fix:**
```javascript
await tar.extract({
    file: archivePath, cwd: destDir,
    filter: (p, entry) => {
        if (entry.type === 'SymbolicLink' || entry.type === 'Link') return false;
        if (p.startsWith('/') || p.includes('..')) return false;
        return true;
    }
});
```

## Common False Positive Patterns

1. **Operations in application-owned directories** (mode 0700, not user-writable).
   Symlink attacks from other users are infeasible. Classify as SAFE.

2. **Read-only ops on well-known system paths.** Reading `/proc/self/status` is not
   TOCTOU since the path is not user-controlled. Classify as SAFE.

3. **Container-isolated /tmp with single-user execution.** No local attacker present.
   Classify as HARDENED (Low) -- fragile pattern but unexploitable in context.

4. **realpath() validation before every operation.** Defends against symlink escape but
   a gap remains between realpath and open. HARDENED (Low) unless O_NOFOLLOW also used.

5. **Stat-then-open on files the caller just created with O_CREAT|O_EXCL** in a
   non-writable directory. Race window is academic. Classify as HARDENED (Low).

6. **Config file reads at startup from root-owned /etc directories.** Unprivileged
   users cannot create symlinks in root-owned dirs. Classify as SAFE.

7. **Test/CI code in ephemeral containers.** No persistent attacker. Classify as SAFE
   but note the pattern for production review.
