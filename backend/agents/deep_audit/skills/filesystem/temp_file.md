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
