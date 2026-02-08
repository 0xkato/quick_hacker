# Zip Slip / Archive Extraction Path Traversal

Zip Slip occurs when an application extracts files from an archive (ZIP, TAR, JAR, RAR)
without validating extracted paths stay within the destination directory. Malicious entries
with names like `../../etc/cron.d/job` write outside the extraction directory, overwriting
system files, application code, or configuration to achieve remote code execution.

## Methodology

### Step 1: Identify All Archive Extraction Code

```python
# Python
import zipfile
zf.extractall(dest)         # Validates in Python 3.12+ only
zf.extract(member, dest)    # No traversal check pre-3.12

import tarfile
tf.extractall(dest)         # Vulnerable pre-3.12 (no data_filter)

import shutil
shutil.unpack_archive(f, dest)  # Wraps zipfile/tarfile
```

```javascript
// Node.js
const AdmZip = require('adm-zip');       // No path validation
const tar = require('tar');               // node-tar 6.2.1+ patched
const yauzl = require('yauzl');           // No built-in validation
const unzipper = require('unzipper');
```

```java
// Java
ZipInputStream zis = new ZipInputStream(inputStream);
ZipEntry entry;
while ((entry = zis.getNextEntry()) != null) {
    File file = new File(destDir, entry.getName());  // No validation!
}
```

```go
import "archive/zip"
for _, f := range reader.File {
    path := filepath.Join(dest, f.Name)  // No validation!
}
```

### Step 2: Analyze the Extraction Loop

```python
# VULNERABLE
def extract_zip(archive_path, dest_dir):
    with zipfile.ZipFile(archive_path) as zf:
        for info in zf.infolist():
            output_path = os.path.join(dest_dir, info.filename)
            with open(output_path, 'wb') as f:  # "../../etc/crontab" escapes
                f.write(zf.read(info.filename))

# SECURE
def extract_zip_safe(archive_path, dest_dir):
    dest_dir = os.path.realpath(dest_dir)
    with zipfile.ZipFile(archive_path) as zf:
        for info in zf.infolist():
            target = os.path.realpath(os.path.join(dest_dir, info.filename))
            if not target.startswith(dest_dir + os.sep):
                raise ValueError(f"Path traversal: {info.filename}")
            with open(target, 'wb') as f:
                f.write(zf.read(info.filename))
```

### Step 3: Check for Python 3.12+ data_filter (tarfile)

```python
# Python 3.12+ SECURE
with tarfile.open(archive) as tf:
    tf.extractall(dest, filter='data')  # Blocks traversal, symlinks, etc.

# Python < 3.12 VULNERABLE
with tarfile.open(archive) as tf:
    tf.extractall(dest)  # No filter, any filename accepted
```

### Step 4: Check for Symlink-Based Traversal in TAR

TAR supports symlinks. Two-entry attack: symlink to `/`, then write through it.

```python
import tarfile, io
def create_malicious_tar():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w') as tf:
        info = tarfile.TarInfo(name="escape")
        info.type = tarfile.SYMTYPE
        info.linkname = "/"
        tf.addfile(info)
        # "escape/etc/crontab" appears safe but writes to /etc/crontab
        info2 = tarfile.TarInfo(name="escape/etc/crontab")
        info2.size = len(payload)
        tf.addfile(info2, io.BytesIO(payload))
```

### Step 5: Analyze Node.js Archive Handling

```javascript
// VULNERABLE: adm-zip
const zip = new AdmZip(req.file.buffer);
zip.extractAllTo('/tmp/uploads/' + userId, true);  // No validation

// SECURE: yauzl with path validation
yauzl.open(archivePath, (err, zipfile) => {
    zipfile.on('entry', (entry) => {
        const fullPath = path.resolve(destDir, entry.fileName);
        if (!fullPath.startsWith(path.resolve(destDir) + path.sep)) {
            throw new Error('Path traversal: ' + entry.fileName);
        }
    });
});
```

### Step 6: Analyze Java Archive Handling

```java
// VULNERABLE
while ((entry = zis.getNextEntry()) != null) {
    File destFile = new File(destDir, entry.getName());
    FileOutputStream fos = new FileOutputStream(destFile);  // No check
}

// SECURE
String canonicalDest = destDir.getCanonicalPath();
while ((entry = zis.getNextEntry()) != null) {
    File destFile = new File(destDir, entry.getName());
    if (!destFile.getCanonicalPath().startsWith(canonicalDest + File.separator))
        throw new SecurityException("Zip Slip: " + entry.getName());
}
```

### Step 7: Check for Incomplete Mitigations

```python
# BAD: string check for ".."
if ".." in entry.filename: raise ValueError()
# Bypassed by: "..%2f", encoded paths, symlink traversal

# BAD: lstrip only
filename = entry.filename.lstrip("/")  # "../etc/passwd" still works

# BAD: os.path.join without realpath
output = os.path.join(dest, entry.filename)
# os.path.join("/safe", "/etc/passwd") returns "/etc/passwd"!

# GOOD: realpath on both, then prefix check
dest_real = os.path.realpath(dest)
output_real = os.path.realpath(os.path.join(dest, entry.filename))
if not output_real.startswith(dest_real + os.sep):
    raise ValueError("Traversal detected")
```

## Decision Tree

```
Code extracts files from an archive?
|
+-- NO --> SAFE
|
+-- YES
    |
    Archive from untrusted input?
    +-- NO --> HARDENED (Low)
    +-- YES
        |
        Entry filename validated before writing?
        +-- NO --> VULNERABLE (Critical) — arbitrary file write
        +-- YES
            |
            Uses realpath/canonical path resolution?
            +-- NO (string check only) --> VULNERABLE (High) — bypassable
            +-- YES
                |
                Symlink entries handled? (TAR)
                +-- NO --> VULNERABLE (High) — symlink traversal
                +-- YES or N/A (ZIP) --> SAFE
```

## Real-World Examples

### Example 1: Zip Slip in Node.js File Upload Handler

```javascript
app.post('/upload', upload.single('archive'), (req, res) => {
    const zip = new AdmZip(req.file.path);
    const extractDir = path.join(__dirname, 'uploads', req.user.id);
    zip.extractAllTo(extractDir, true);  // No path validation
    res.json({ status: 'extracted' });
});
```

**Why vulnerable:** `adm-zip`'s `extractAllTo` does not validate entry filenames.
A ZIP containing `../../server.js` overwrites the application's main file.

**Impact:** Arbitrary file write leading to RCE. Overwrite app code, cron jobs,
SSH authorized_keys, or systemd units.

**Fix:**
```javascript
const entries = zip.getEntries();
const realDest = fs.realpathSync(extractDir);
entries.forEach(entry => {
    const entryPath = path.resolve(extractDir, entry.entryName);
    if (!entryPath.startsWith(realDest + path.sep))
        throw new Error('Zip Slip: ' + entry.entryName);
});
zip.extractAllTo(extractDir, true);
```

### Example 2: TAR Symlink Traversal in Python CI Pipeline

```python
def extract_build_artifact(tar_path, workspace):
    with tarfile.open(tar_path) as tf:
        tf.extractall(workspace)  # No filter, no validation
```

**Why vulnerable:** Malicious tar contains symlink `output -> /` then writes
`output/home/deploy/.ssh/authorized_keys` through it, planting an SSH key.

**Impact:** RCE on CI server, lateral movement via compromised deploy keys.

**Fix:**
```python
with tarfile.open(tar_path) as tf:
    tf.extractall(workspace, filter='data')  # Python 3.12+
```

### Example 3: Zip Slip in Java Plugin Loader

```java
public void installPlugin(InputStream pluginZip) throws IOException {
    File pluginDir = new File(PLUGINS_DIR);
    ZipInputStream zis = new ZipInputStream(pluginZip);
    ZipEntry entry;
    while ((entry = zis.getNextEntry()) != null) {
        File target = new File(pluginDir, entry.getName());
        target.getParentFile().mkdirs();
        try (FileOutputStream fos = new FileOutputStream(target)) {
            byte[] buf = new byte[4096]; int len;
            while ((len = zis.read(buf)) > 0) fos.write(buf, 0, len);
        }
    }
}
```

**Why vulnerable:** `new File(pluginDir, "../../webapps/ROOT/shell.jsp")` resolves
outside PLUGINS_DIR. No canonical path check.

**Impact:** Web shell in application server's webroot, full RCE.

**Fix:**
```java
String canonicalDest = pluginDir.getCanonicalPath();
while ((entry = zis.getNextEntry()) != null) {
    File target = new File(pluginDir, entry.getName());
    if (!target.getCanonicalPath().startsWith(canonicalDest + File.separator))
        throw new SecurityException("Zip Slip: " + entry.getName());
}
```

## Common False Positive Patterns

1. **Archives from trusted sources only** — Internally generated archives with no user
   influence over filenames are not exploitable. Verify no user-controlled components.

2. **Python 3.12+ extractall** — Default behavior raises on path traversal. Verify
   minimum Python version in runtime requirements.

3. **Library-level mitigation** — `node-tar` 6.2.1+ has built-in validation. Check
   installed version against the CVE fix version.

4. **Extraction in ephemeral containers** — Container with no persistent filesystem
   and no network limits traversal impact. Flag as HARDENED (Low).

5. **Java getCanonicalPath validation** — When both destination and target are resolved
   to canonical paths with prefix check, mitigation is correct.

6. **Single-file extraction by hardcoded name** — `zf.read("manifest.json")` with no
   iteration means no attacker-controlled filenames.

7. **Flat extraction via basename** — `os.path.basename(entry.filename)` strips all
   directory components, discarding traversal sequences.
