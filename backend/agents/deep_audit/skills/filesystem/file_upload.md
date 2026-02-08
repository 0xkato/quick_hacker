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
