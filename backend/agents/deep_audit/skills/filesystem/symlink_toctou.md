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
