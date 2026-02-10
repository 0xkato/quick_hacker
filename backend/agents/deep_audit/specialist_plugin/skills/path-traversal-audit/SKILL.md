---
name: path-traversal-audit
description: Detection methodology for directory traversal and LFI
---

# Domain Expertise

# Path Traversal Auditor

## Role Definition

You are a specialized security auditor focused on path traversal vulnerabilities. Your expertise covers directory traversal attacks, path normalization pitfalls, encoding tricks, and OS-specific path handling that allow attackers to access files outside intended directories.

## Core Proficiency

Normalization pitfalls, encoding tricks, and cross-platform path handling differences.

## Focus Areas

### `../` Sequences
- Basic traversal patterns
- Multiple traversal depth
- Traversal in different path positions
- Concatenation vulnerabilities
- Partial path injection

### URL Encoding
- `%2e%2e%2f` (../)
- `%2e%2e/` (../)
- `..%2f` (../)
- Mixed encoding patterns
- Double encoding

### Null Byte Injection
- `%00` truncation (legacy systems)
- Null byte in path components
- Extension bypass via null
- Language-specific null handling

### OS-Specific Paths
- Windows backslash (`\`)
- Windows absolute paths (`C:\`)
- UNC paths (`\\server\share`)
- Windows short names (8.3 format)
- Unix absolute paths

### Path Normalization Order
- Decode then normalize
- Normalize then decode
- Validate then normalize
- Multiple normalization passes

## Bypass Techniques

### Double Encoding
```
%252e%252e%252f  ->  (decode once) %2e%2e%2f  ->  (decode twice) ../
%252e%252e/      ->  (decode once) %2e%2e/    ->  (decode twice) ../
```

### Unicode Normalization
```
%c0%ae%c0%ae/    ->  (overlong UTF-8) ../
%e0%80%ae        ->  (overlong UTF-8) .
%c0%af           ->  (overlong UTF-8) /
..%c0%af         ->  ../
```

### Mixed Slashes
```
..\/             ->  (Windows) ..\
..\/ 			 ->  (mixed) may normalize to ../
....//           ->  (double traversal attempt)
....\\           ->  (Windows double traversal)
```

### Null Bytes (Legacy)
```
../../../etc/passwd%00.png    ->  /etc/passwd (null terminates)
../../../etc/passwd\x00.jpg   ->  /etc/passwd
```

### Case Variations (Windows)
```
..\..\WINDOWS\system32\config\SAM
..\..\windows\system32\config\sam
```

## Audit Methodology

### Step 1: Identify File Path Construction
1. Search for file operation functions
2. Locate path concatenation code
3. Find user input reaching file paths
4. Identify path parameter sources

### Step 2: Analyze Path Validation
1. Check for traversal sequence filtering
2. Review path normalization order
3. Assess encoding handling
4. Verify OS-specific considerations

### Step 3: Test Bypass Techniques
1. Try encoding variations
2. Test normalization bypasses
3. Check OS-specific paths
4. Attempt null byte injection

### Step 4: Assess Impact
1. What files are accessible?
2. Can sensitive files be read?
3. Is write access possible?
4. Are there path-based authorization checks?

## Vulnerability Patterns

### Direct Path Concatenation
```python
# VULNERABLE
file_path = base_dir + "/" + user_input
with open(file_path, 'r') as f:
    return f.read()
```

### Insufficient Filtering
```python
# VULNERABLE - simple replace can be bypassed
sanitized = user_input.replace("../", "")
# Attack: "....//etc/passwd" -> "../etc/passwd"
```

### Validation Before Decoding
```python
# VULNERABLE - check before decode
if "../" not in user_input:  # Check first
    decoded = urllib.parse.unquote(user_input)  # Then decode
    # Attack: "%2e%2e%2f" passes check
```

### Normalization After Validation
```python
# VULNERABLE
if user_path.startswith("/safe/dir/"):  # Validate first
    real_path = os.path.normpath(user_path)  # Then normalize
    # Attack: "/safe/dir/../../../etc/passwd"
```

## Risk Indicators

### Critical Risk
- User input directly in file paths
- No path validation
- Sensitive files in accessible directories
- Write access to executable paths

### High Risk
- Blacklist-only filtering
- Validation before normalization
- Single encoding decode
- Cross-platform path handling

### Medium Risk
- Path constrained to specific directory
- Whitelist file access
- Strong input validation
- Canonicalization before validation

## Secure Path Handling

### Python
```python
import os

def safe_file_read(base_dir, user_input):
    # Canonicalize base directory
    base_dir = os.path.realpath(base_dir)

    # Build and canonicalize target path
    target_path = os.path.realpath(os.path.join(base_dir, user_input))

    # Verify target is within base directory
    if not target_path.startswith(base_dir + os.sep):
        raise ValueError("Path traversal detected")

    # Additional check for base_dir itself
    if target_path == base_dir:
        raise ValueError("Cannot access base directory")

    with open(target_path, 'r') as f:
        return f.read()
```

### Java
```java
public String safeFileRead(String baseDir, String userInput) throws IOException {
    Path basePath = Paths.get(baseDir).toRealPath();
    Path targetPath = basePath.resolve(userInput).normalize().toRealPath();

    if (!targetPath.startsWith(basePath)) {
        throw new SecurityException("Path traversal detected");
    }

    return Files.readString(targetPath);
}
```

### Node.js
```javascript
const path = require('path');
const fs = require('fs');

function safeFileRead(baseDir, userInput) {
    const resolvedBase = path.resolve(baseDir);
    const targetPath = path.resolve(baseDir, userInput);

    if (!targetPath.startsWith(resolvedBase + path.sep)) {
        throw new Error('Path traversal detected');
    }

    return fs.readFileSync(targetPath, 'utf8');
}
```

### PHP
```php
function safeFileRead($baseDir, $userInput) {
    $baseDir = realpath($baseDir);
    $targetPath = realpath($baseDir . DIRECTORY_SEPARATOR . $userInput);

    if ($targetPath === false || strpos($targetPath, $baseDir . DIRECTORY_SEPARATOR) !== 0) {
        throw new Exception('Path traversal detected');
    }

    return file_get_contents($targetPath);
}
```

## Testing Payloads

### Basic Traversal
```
../
../../
../../../
..\..\
..\/
..\
```

### Encoded Traversal
```
%2e%2e%2f
%2e%2e/
..%2f
%2e%2e%5c
..%5c
..%255c
```

### Double Encoded
```
%252e%252e%252f
%252e%252e/
..%252f
%252e%252e%255c
```

### Unicode/Overlong
```
%c0%ae%c0%ae%c0%af
..%c0%af
%e0%80%ae%e0%80%ae/
```

### Null Byte
```
../../../etc/passwd%00.png
../../../etc/passwd%00
..%00/
```

### Mixed/Complex
```
....//....//etc/passwd
..///////..////..//////etc/passwd
/var/www/images/../../../etc/passwd
```

## Remediation Guidance

### General Principles
1. Never trust user input in file paths
2. Canonicalize paths before validation
3. Use allowlists when possible
4. Validate after all decoding/normalization
5. Use OS-provided safe path functions

### Defense in Depth
1. Restrict filesystem permissions
2. Use chroot or containers
3. Implement file access logging
4. Use indirect file references (IDs)
5. Apply WAF rules for common patterns

## Output Format

When reporting path traversal findings:

1. **Location**: Code location with vulnerable path handling
2. **Input Source**: How attacker input reaches the path
3. **Validation**: Current validation (if any)
4. **Bypass Technique**: Specific bypass that works
5. **Payload**: Working traversal payload
6. **Accessible Files**: What can be accessed
7. **Impact**: Sensitive data exposure, code execution
8. **Remediation**: Secure path handling code

---

# Detection Methodology

# Path Traversal Detection

## Methodology

### Step 1: Identify File System Access Points

All places where the server reads, writes, deletes, or lists files based on any input:

**File read:**
- Python: `open()`, `Path.read_text()`, `Path.read_bytes()`, `shutil.copy()`, `send_file()` (Flask), `FileResponse()` (FastAPI)
- Node.js: `fs.readFile()`, `fs.createReadStream()`, `fs.promises.readFile()`, `res.sendFile()`, `res.download()`

**File write:**
- Python: `open(path, 'w')`, `Path.write_text()`, `shutil.move()`, `file.save()` (Flask uploads)
- Node.js: `fs.writeFile()`, `fs.createWriteStream()`, `multer` disk storage with dynamic destination

**File delete:**
- Python: `os.remove()`, `os.unlink()`, `Path.unlink()`, `shutil.rmtree()`
- Node.js: `fs.unlink()`, `fs.rm()`, `fs.promises.rm()`

**Directory listing:**
- Python: `os.listdir()`, `os.scandir()`, `os.walk()`, `Path.glob()`, `glob.glob()`
- Node.js: `fs.readdir()`, `glob()` / `fast-glob()` with user-controlled patterns

**File path construction (the hidden entry point):**
- `os.path.join(base, user_input)` — does NOT prevent traversal
- `path.join(base, userInput)` — does NOT prevent traversal
- `Path(base) / user_input` — same problem
- f-strings / template literals: `f"/uploads/{filename}"`, `` `/uploads/${filename}` ``

**Archive extraction (Zip Slip — see Step 4):**
- Python: `zipfile.ZipFile.extractall()`, `tarfile.TarFile.extractall()`, `shutil.unpack_archive()`
- Node.js: `adm-zip` `extractAllTo()`, `unzipper`, `decompress`, `tar`, `yauzl`

**Template loading:**
- `get_template(user_input)`, `render(user_input)` — if template path is user-controlled

### Step 2: Trace Path Source

For each file system access point, determine how the path is constructed:

1. **Is the filename, path, or any component user-controlled?**
   - Direct: query parameter (`?file=report.pdf`), URL path segment (`/files/:name`), form field, multipart upload filename
   - Indirect: database-stored filename, S3 key derived from user input, cache key mapped to filesystem
   - Archive entry names (attacker controls filenames inside zip/tar)

2. **How many components are user-controlled?**
   - Just filename: `/uploads/{user_filename}` — traversal risk
   - Subdirectory + filename: `/data/{user_dir}/{user_file}` — higher risk
   - Entire path: `open(user_path)` — critical, arbitrary file access

3. **What is the data flow?**
   - Direct: `request.param -> file path -> open()` (easy to trace)
   - Indirect: `request.param -> database -> later read -> file path -> open()` (stored traversal)
   - Transformed: `request.param -> URL-decode -> file path -> open()` (double encoding bypass)

### Step 3: Evaluate Defenses

**Correct approach — resolve then check prefix:**
```python
BASE_DIR = "/var/app/uploads"

def safe_read(user_filename):
    full_path = os.path.realpath(os.path.join(BASE_DIR, user_filename))
    if not full_path.startswith(BASE_DIR + os.sep) and full_path != BASE_DIR:
        raise ValueError("Path traversal detected")
    return open(full_path, 'r').read()
```
```javascript
const BASE_DIR = '/var/app/uploads';
function safeRead(userFilename) {
    const fullPath = path.resolve(BASE_DIR, userFilename);
    if (!fullPath.startsWith(BASE_DIR + path.sep) && fullPath !== BASE_DIR) {
        throw new Error('Path traversal detected');
    }
    return fs.readFileSync(fullPath, 'utf8');
}
```

**Stripping `../` — BYPASSABLE:**
```python
# DANGEROUS — multiple bypass vectors
clean = filename.replace("../", "")
# Bypass 1: ....// -> after strip -> ../
# Bypass 2: ..%2F -> URL-decoded after strip
# Bypass 3: ..\\ -> backslash on Windows
# Bypass 4: ..%252F -> double URL encoding
# Bypass 5: %2e%2e%2f -> URL-encoded dots and slash
```

**`os.path.join()` / `path.join()` — NOT A DEFENSE:**
```python
os.path.join("/uploads", "/etc/passwd")          # Returns "/etc/passwd"
os.path.join("/uploads", "../../../etc/passwd")   # Returns "/uploads/../../../etc/passwd"
```
```javascript
path.join('/uploads', '../../../etc/passwd')      // Returns '/etc/passwd'
```

**Chroot / jail (STRONGEST):** Process-level filesystem isolation. Even `../../../etc/passwd` resolves within the jail. Rare in application code.

**Allowlist (STRONG):** Input checked against a fixed set of permitted filenames/paths.

**Basename extraction (PARTIAL):**
```python
safe_name = os.path.basename(user_filename)  # "../../etc/passwd" -> "passwd"
# Prevents directory traversal, but does not protect against accessing
# unintended files in the same directory (e.g., ".env")
```

### Step 4: Check for Zip Slip

Zip Slip occurs when archive extraction writes files outside the intended directory because entry names contain `../` path components.

**Vulnerable:**
```python
with zipfile.ZipFile(zip_path, 'r') as zf:
    zf.extractall(dest_dir)  # No validation of entry paths
```

**Safe extraction:**
```python
def safe_extract(zip_path, dest_dir):
    dest_dir = os.path.realpath(dest_dir)
    with zipfile.ZipFile(zip_path, 'r') as zf:
        for entry in zf.namelist():
            target = os.path.realpath(os.path.join(dest_dir, entry))
            if not target.startswith(dest_dir + os.sep) and target != dest_dir:
                raise ValueError(f"Zip slip detected: {entry}")
        zf.extractall(dest_dir)
```

**Note:** Python 3.12+ added `zipfile.Path` with built-in traversal checks, and `tarfile.extractall()` gained a `filter` parameter. Check the runtime version.

**Affected formats:** zip, tar, tar.gz, jar, war, rar, 7z — any archive where the creator controls entry names.

### Step 5: Classify

- **VULNERABLE (Critical)**: User input reaches file read/write/delete with no path validation, unauthenticated endpoint
- **VULNERABLE (High)**: Same but requires authentication, or Zip Slip with no entry name validation
- **HARDENED (Medium)**: Strip-based defense (`replace("../", "")`) or `basename()` only
- **HARDENED (Low)**: `realpath()` + prefix check with minor issues (TOCTOU race, symlink edge cases)
- **SAFE**: `realpath()`/`resolve()` + strict prefix check, or allowlist, or chroot
- **BY_DESIGN**: Admin-only file browser with authentication and audit logging (still note it)

## Decision Tree

```
Does any file system operation use external data in the file path?
+-- No -> SAFE
+-- Yes -> Is the external data user-controlled?
    +-- No (hardcoded, internal config) -> SAFE (note if config is editable)
    +-- Yes -> Is this an archive extraction?
        +-- Yes -> Are entry names validated against traversal?
        |   +-- Yes (realpath + prefix check on each entry) -> SAFE
        |   +-- No -> VULNERABLE (High -- Zip Slip)
        +-- No -> Is the resolved path checked to be within the allowed directory?
            +-- Yes -> How?
            |   +-- realpath()/resolve() THEN startswith(base) -> SAFE
            |   +-- basename() only -> HARDENED (Medium)
            |   +-- Strip ../ or regex filter -> HARDENED (Medium -- bypassable)
            |   +-- Allowlist of exact filenames -> SAFE (verify completeness)
            +-- No -> Is there any validation at all?
                +-- No -> VULNERABLE
                |   +-- Unauth + read -> Critical
                |   +-- Unauth + write -> Critical (arbitrary write / RCE)
                |   +-- Auth + read -> High
                |   +-- Auth + write/delete -> High
                +-- Extension check only (.pdf) -> VULNERABLE
                    +-- Bypass: ../../etc/passwd%00.pdf or ../../etc/passwd/.pdf
```

## Real-World Examples

### Example 1: Path Traversal via File Download Endpoint (Vulnerable)

```python
from flask import Flask, request, send_file
app = Flask(__name__)

@app.route('/download')
def download():
    filename = request.args.get('file')
    return send_file(f"/var/app/reports/{filename}")
```

**Why vulnerable:** `filename` comes directly from the query string. Attacker requests `?file=../../../etc/passwd` and the path resolves to `/etc/passwd`. Further exploitation: `../../../proc/self/environ` leaks env vars, `../../../home/deploy/.ssh/id_rsa` leaks SSH keys.

**Impact:** Arbitrary file read. Attacker reads source code, credentials, SSH keys — anything readable by the web server process.

**Fix:**
```python
REPORTS_DIR = os.path.realpath("/var/app/reports")

@app.route('/download')
def download():
    filename = request.args.get('file')
    if not filename:
        abort(400)
    filepath = os.path.realpath(os.path.join(REPORTS_DIR, filename))
    if not filepath.startswith(REPORTS_DIR + os.sep):
        abort(403)
    if not os.path.isfile(filepath):
        abort(404)
    return send_file(filepath)
```

### Example 2: Zip Slip During Archive Extraction (Vulnerable)

```javascript
const AdmZip = require('adm-zip');

app.post('/import', upload.single('archive'), (req, res) => {
    const zip = new AdmZip(req.file.path);
    const extractDir = path.join('/var/app/data/imports', req.user.id);
    zip.extractAllTo(extractDir, true);  // No entry name validation
    res.json({ message: 'Import complete' });
});
```

**Why vulnerable:** Attacker uploads a zip with entry `../../../../var/app/routes/admin.js`. Extraction writes outside `extractDir`, overwriting application code. On next restart (or hot-reload), the backdoor is live.

**Impact:** Arbitrary file write. Leads to RCE via overwriting app files, cron jobs, SSH authorized_keys, or startup scripts.

**Fix:**
```javascript
app.post('/import', upload.single('archive'), (req, res) => {
    const zip = new AdmZip(req.file.path);
    const extractDir = path.resolve('/var/app/data/imports', req.user.id);
    for (const entry of zip.getEntries()) {
        const target = path.resolve(extractDir, entry.entryName);
        if (!target.startsWith(extractDir + path.sep)) {
            return res.status(400).json({ error: 'Malicious archive entry' });
        }
    }
    zip.extractAllTo(extractDir, true);
    res.json({ message: 'Import complete' });
});
```

### Example 3: False Positive — Path Built from Allowlisted Components

```python
REPORT_TYPES = {"monthly", "quarterly", "annual"}
DEPARTMENTS = {"engineering", "sales", "marketing", "finance"}
FORMATS = {"pdf", "csv"}

@app.route('/reports/<report_type>/<department>.<fmt>')
def get_report(report_type, department, fmt):
    if report_type not in REPORT_TYPES:
        abort(404)
    if department not in DEPARTMENTS:
        abort(404)
    if fmt not in FORMATS:
        abort(404)
    return send_file(f"/var/app/reports/{report_type}/{department}.{fmt}")
```

**Why safe:** Every path component is validated against a strict allowlist. Only 24 possible paths exist (3 x 4 x 2), all known-safe. Scanners flag the f-string flowing into `send_file()`, but manual review confirms the allowlist makes traversal impossible.

## Common False Positive Patterns

1. **Allowlisted path components**: User input checked against a fixed set (enum, dict lookup, set membership) before use in path. Traversal is impossible if the allowlist is strict.

2. **Hardcoded paths with no user input**: `open("/var/log/app.log")` — no external data in the path. Scanners flag any file I/O call regardless.

3. **Integer/UUID-only filenames**: `f"/uploads/{int(user_id)}/{uuid.UUID(file_id)}.dat"` — type casting eliminates all traversal characters.

4. **Static file middleware with built-in protections**: `express.static()`, `whitenoise`, `send_from_directory()` — these include their own traversal prevention. Verify no known bypass CVEs for the version in use.

5. **Database-generated identifiers as filenames**: UUID generated server-side, stored in DB. User provides a record ID (integer), server looks up the UUID path. User never controls the filesystem path.

6. **Basename extraction before path construction**: `os.path.basename(user_input)` strips directory components. `../../etc/passwd` becomes `passwd`. Prevents traversal, but verify no secondary risk (overwriting known filenames in the directory).

7. **Build scripts and test fixtures**: Path construction in Dockerfiles, Makefiles, CI configs, test setup — not user-facing at runtime. Note if patterns might be copied to production code.
