# File Parser Vulnerabilities

File parsers convert raw bytes into structured data. When handling untrusted files they
become attack surfaces for command injection, DoS, information disclosure, and RCE.
Image processors shell out to system commands, PDF renderers execute JavaScript, office
documents embed macros, and font parsers operate on complex binary formats with memory
corruption history.

## Methodology

### Step 1: Identify All File Parsing Libraries

```python
# Image processing
from PIL import Image              # Pillow — decompression bombs
from wand.image import Image       # Wand/ImageMagick — command injection
import cairosvg                    # CairoSVG — XXE via SVG
subprocess.run(['convert', ...])   # Direct ImageMagick — delegate injection

# PDF processing
import fitz                        # PyMuPDF — JavaScript, link following
subprocess.run(['gs', ...])       # Ghostscript — notorious RCE history

# Office documents
import openpyxl                    # XLSX — XXE, formula injection
import python_docx                 # DOCX — embedded objects
import xlrd                        # XLS legacy — macros, OLE

# Font processing
from fontTools import ttLib        # fontTools — TrueType/OpenType
import freetype                    # freetype-py — C library, CVE history
```

```javascript
// Node.js
const sharp = require('sharp');      // libvips — safer than ImageMagick
const gm = require('gm');           // GraphicsMagick/ImageMagick wrapper
const ExcelJS = require('exceljs');  // XLSX parsing
```

```java
import javax.imageio.ImageIO;              // Java built-in
import org.apache.pdfbox.pdmodel.*;        // PDFBox
import org.apache.poi.xssf.usermodel.*;    // Apache POI — Office
import org.apache.batik.transcoder.*;      // Batik — SVG (SSRF, XXE)
```

### Step 2: Check ImageMagick / GraphicsMagick Usage

```python
# VULNERABLE: ImageMagick via subprocess
def resize_image(input_path, output_path, size):
    subprocess.run(['convert', input_path, '-resize', size, output_path])
# Delegates trigger: shell injection via SVG/MVG, SSRF via URL filenames,
# file read via label:@/etc/passwd, RCE via ephemeral:// or msl://

# VULNERABLE: Wand (ImageMagick Python binding)
with Image(blob=file_data) as img:  # Full ImageMagick attack surface
    img.resize(200, 200)
```

Defense: `/etc/ImageMagick-7/policy.xml` should set `rights="none"` for coders MVG, MSL,
TEXT, LABEL, URL, HTTPS, HTTP, EPHEMERAL and set resource limits for memory, width, height.

### Step 3: Check for Decompression Bombs

```python
from PIL import Image
Image.MAX_IMAGE_PIXELS = None  # VULNERABLE: disables bomb check!
# Default ~178M pixels is safe. A 100000x100000 PNG header triggers OOM.

# SECURE:
Image.MAX_IMAGE_PIXELS = 25_000_000  # 25 megapixels max
```

For ZIP-based documents (DOCX/XLSX), check compression ratio (reject > 100:1) and
total uncompressed size before extraction to detect zip bombs.

### Step 4: Check PDF Processing Security

```python
# VULNERABLE: Ghostscript without sandbox
subprocess.run(['gs', '-dBATCH', '-dNOPAUSE', '-sDEVICE=pdfwrite',
                '-sOutputFile=output.pdf', user_uploaded_pdf])
# -dSAFER restricts file ops but has been bypassed in multiple CVEs

# Defense: validate PDF structure before processing
def validate_pdf(file_path):
    with open(file_path, 'rb') as f:
        if f.read(5) != b'%PDF-':
            raise ValueError("Not a PDF")
        content = f.read()
        for p in [b'/JavaScript', b'/JS ', b'/Launch', b'/SubmitForm',
                  b'/RichMedia', b'/XFA', b'/GoToR', b'/GoToE']:
            if p in content:
                raise ValueError(f"Dangerous element: {p}")
```

### Step 5: Check Office Document Parsing

```python
# Formula injection — cell values starting with =, +, -, @
def sanitize_cell(value):
    if isinstance(value, str) and value and value[0] in ('=', '+', '-', '@'):
        return "'" + value  # Prevent formula execution in downstream CSV/Excel

# DOCX/PPTX macro and OLE detection
def check_office_macros(file_path):
    with zipfile.ZipFile(file_path) as zf:
        names = zf.namelist()
        if any('vbaProject' in n for n in names):
            raise ValueError("VBA macros detected")
        if any('activeX' in n for n in names):
            raise ValueError("ActiveX controls detected")
        if any('oleObject' in n for n in names):
            raise ValueError("OLE objects detected")
        for name in names:
            if name.endswith('.rels'):
                content = zf.read(name).decode('utf-8', errors='ignore')
                if 'External' in content or 'http' in content.lower():
                    raise ValueError("External resource references")
```

### Step 6: Validate Magic Bytes and File Type

```python
import magic  # python-magic

ALLOWED_TYPES = {
    'image/jpeg': [b'\xff\xd8\xff'],
    'image/png': [b'\x89PNG\r\n\x1a\n'],
    'image/gif': [b'GIF87a', b'GIF89a'],
    'application/pdf': [b'%PDF-'],
}

def validate_file_type(file_path, expected_type):
    with open(file_path, 'rb') as f:
        header = f.read(16)
    if not any(header.startswith(h) for h in ALLOWED_TYPES.get(expected_type, [])):
        raise ValueError("Content does not match declared type")
    detected = magic.from_file(file_path, mime=True)
    if detected != expected_type:
        raise ValueError(f"Detected {detected} != expected {expected_type}")
```

### Step 7: Verify Sandboxed Processing

```python
# Minimal safe Pillow processing
def safe_resize(file_data, max_w=1920, max_h=1080):
    Image.MAX_IMAGE_PIXELS = 25_000_000
    img = Image.open(io.BytesIO(file_data))
    if hasattr(img, 'n_frames') and img.n_frames > 1:
        raise ValueError("Animated images not supported")
    img = img.convert('RGB')  # Strip exotic color modes
    img.thumbnail((max_w, max_h), Image.LANCZOS)
    output = io.BytesIO()
    img.save(output, format='PNG')  # Re-encode strips metadata
    return output.getvalue()
```

For high-risk parsing (ImageMagick, Ghostscript), run in Docker with `--network=none`,
`--memory=512m`, `--read-only`, and a timeout to contain exploits.

## Decision Tree

```
Code processes uploaded/external files?
|
+-- NO --> SAFE
|
+-- YES
    |
    +-- Images
    |   |
    |   Uses ImageMagick/GraphicsMagick?
    |   +-- YES --> policy.xml restricts coders?
    |   |   +-- YES --> HARDENED (Medium) — bypasses exist historically
    |   |   +-- NO  --> VULNERABLE (Critical) — RCE via delegates
    |   +-- NO (Pillow, sharp) --> Decompression limits set?
    |       +-- YES --> HARDENED (Low)
    |       +-- NO (MAX_IMAGE_PIXELS=None) --> VULNERABLE (High) — DoS
    |
    +-- PDFs
    |   +-- Ghostscript? --> VULNERABLE (Critical)
    |   +-- Other --> JS/Launch actions blocked?
    |       +-- YES --> HARDENED (Medium)
    |       +-- NO  --> VULNERABLE (High)
    |
    +-- Office --> Macros/OLE/ActiveX blocked?
    |   +-- YES --> HARDENED (Medium) / NO --> VULNERABLE (High)
    |
    +-- Fonts --> Untrusted? YES --> VULNERABLE (High) / NO --> SAFE
```

## Real-World Examples

### Example 1: ImageMagick SSRF via SVG Upload

```python
@app.route('/avatar/upload', methods=['POST'])
def upload_avatar():
    file = request.files['avatar']
    file.save('/tmp/avatar_upload')
    with Image(filename='/tmp/avatar_upload') as img:
        img.resize(200, 200)
        img.save(filename=f'/static/avatars/{user_id}.png')
```

Attacker uploads SVG: `<image href="http://169.254.169.254/latest/api/token" />`

**Why vulnerable:** ImageMagick's SVG coder resolves external URLs. MVG format can
invoke arbitrary delegates.

**Impact:** SSRF to cloud metadata, internal APIs. Potentially full RCE.

**Fix:**
```python
from PIL import Image as PILImage
img = PILImage.open(io.BytesIO(file_data))
if img.format not in ('JPEG', 'PNG', 'WEBP'):
    raise ValueError("Only JPEG/PNG/WEBP allowed")
img = img.convert('RGB'); img.thumbnail((200, 200))
```

### Example 2: Pillow Decompression Bomb

```python
Image.MAX_IMAGE_PIXELS = None  # Disabled for "panorama support"
@app.route('/process', methods=['POST'])
def process_image():
    img = Image.open(request.files['image'].stream)
    img.load()  # 100000x100000 PNG → ~30 GB allocation → OOM
```

**Why vulnerable:** Disabling pixel limit allows crafted images claiming extreme
dimensions to exhaust server memory.

**Impact:** Single request crashes application and co-located services.

**Fix:**
```python
Image.MAX_IMAGE_PIXELS = 25_000_000
MAX_FILE_SIZE = 10 * 1024 * 1024
# Enforce file size BEFORE parsing, then pixel limit catches the rest
```

### Example 3: PDF JavaScript in Rendering Pipeline

```java
public BufferedImage renderPdf(InputStream input) throws IOException {
    PDDocument doc = PDDocument.load(input);
    PDFRenderer renderer = new PDFRenderer(doc);
    return renderer.renderImage(0);
}
// PDF may contain /GoToR, /JavaScript, /Launch actions
```

**Why vulnerable:** PDFs reaching a JS-capable renderer (browser, Electron) execute
embedded JavaScript. Parser itself handles complex binary structures with DoS risk.

**Impact:** Phishing, credential theft, SSRF. Parser-level DoS or memory corruption.

**Fix:**
```java
PDDocument doc = PDDocument.load(input);
doc.getDocumentCatalog().setActions(null);
doc.getDocumentCatalog().setOpenAction(null);
for (int i = 0; i < doc.getNumberOfPages(); i++)
    doc.getPage(i).setActions(null);  // Strip all actions
```

## Common False Positive Patterns

1. **Pillow with default MAX_IMAGE_PIXELS** — ~178M pixel limit is active unless
   explicitly set to None. Default is safe.

2. **Image re-encoding pipeline** — Decode then re-encode to clean format strips
   metadata and exotic features. Output is clean regardless of input.

3. **sharp (libvips)** — Significantly smaller attack surface than ImageMagick. No SVG
   rendering, no delegates, no exotic coders. Still verify version.

4. **File type allowlist with magic byte validation** — Rejecting unexpected formats
   before parsing reduces attack surface to specific allowed parsers.

5. **Processing in ephemeral containers** — Docker with no network, read-only FS,
   memory/CPU limits contains exploits. No persistence or lateral movement.

6. **Ghostscript -dSAFER on 10.x+** — Hardened sandbox, though not guaranteed.
   Verify current version and -dSAFER applied.

7. **Bundled fonts only** — Application parsing its own bundled fonts (not user uploads)
   limits risk to supply-chain compromise, a different threat model.
