# Path Traversal Proof Checklist

You are analyzing a potential path traversal vulnerability. Follow this evidence-gathering plan:

## 1. Identify the Sink (sink_present)

**Goal:** Prove that file system operations use paths that could be manipulated.

**Evidence Required:**
- Exact file path and line number of file operation
- Function name: `open()`, `read_file()`, `File.read()`, `fs.readFile()`, `include()`, `require()`, `sendFile()`, `serve_static()`

**Tool Call Example:**
```json
{
  "tool": "search_code",
  "arguments": {
    "pattern": "(\\bopen\\(|read_file\\(|readFile\\(|sendFile\\(|send_static_file\\(|send_from_directory\\(|File\\.read\\(|include\\(|require\\()",
    "file_pattern": "**/*.{py,js,ts,php,rb,java}",
    "max_results": 100
  }
}
```

**Checklist Update:**
- `sink_present = PROVEN_TRUE` if file operation found
- `sink_present = PROVEN_FALSE` if no file operations in codebase
- `sink_present = UNKNOWN` if files are missing or code is obfuscated

## 2. Identify the Source (source_controlled_input)

**Goal:** Prove user/attacker controls part of the file path.

**Evidence Required:**
- Input comes from: request parameters, URL path, headers, cookies, file names
- NOT from: hardcoded values, config files, admin-only inputs, database (non-user-controlled)

**Common Patterns:**
- Python Flask: `request.args.get('file')`, URL path parameters
- Python Django: `request.GET['filename']`, path parameters
- Node.js Express: `req.query.file`, `req.params.filename`
- PHP: `$_GET['file']`, `$_REQUEST['path']`

**Tool Call Example:**
```json
{
  "tool": "read_file",
  "arguments": {
    "path": "app/download.py",
    "start_line": 15,
    "end_line": 45
  }
}
```

**Checklist Update:**
- `source_controlled_input = PROVEN_TRUE` if input is from HTTP request/external source
- `source_controlled_input = PROVEN_FALSE` if path is hardcoded or from trusted source
- `source_controlled_input = UNKNOWN` if input origin is unclear

## 3. Trace Data Flow (dataflow_evidenced)

**Goal:** Prove user input flows to file path without proper sanitization.

**Evidence Required:**
- Step-by-step path from source to sink
- Cite each intermediate variable/function with file:line
- Prove that path validation/sanitization is absent or bypassable

**Safe Patterns (Proper Validation):**
If you see:
```python
# Allowlist validation (SAFE)
ALLOWED_FILES = ['report.pdf', 'data.csv', 'summary.txt']
if filename in ALLOWED_FILES:
    with open(f'/var/files/{filename}') as f:
        return f.read()
# SAFE - strict allowlist
```

```python
# Path.resolve() with validation (SAFER)
from pathlib import Path
base = Path('/var/uploads')
requested = base / user_filename
if requested.resolve().is_relative_to(base):
    with open(requested) as f:
        return f.read()
# SAFER - ensures path stays within base directory
```

**Unsafe Patterns (No Validation):**
If you see:
```python
# Direct concatenation (UNSAFE)
filename = request.args.get('file')
with open(f'/var/files/{filename}') as f:
    return f.read()
# UNSAFE - attacker can use ../../../etc/passwd
```

```javascript
// Path concatenation without validation (UNSAFE)
const file = req.query.file;
res.sendFile(`/uploads/${file}`);
// UNSAFE - directory traversal possible
```

```php
// Direct inclusion (UNSAFE)
$file = $_GET['page'];
include("/var/www/pages/$file.php");
// UNSAFE - attacker can traverse directories
```

**Traversal Techniques to Look For:**
- `../` - Parent directory traversal
- `..\\` - Windows parent directory
- `....//` - Double encoding bypass
- `%2e%2e%2f` - URL encoding
- Absolute paths: `/etc/passwd` if base path concatenation is weak

**Tool Call Example:**
```json
{
  "tool": "trace_data_flow",
  "arguments": {
    "source": "request.args.get('filename')",
    "file_path": "app/download.py",
    "sink_patterns": ["open(", "send_file("]
  }
}
```

**Checklist Update:**
- `dataflow_evidenced = PROVEN_TRUE` if unsanitized path reaches file operation
- `dataflow_evidenced = PROVEN_FALSE` if strict allowlist or path validation prevents traversal
- `dataflow_evidenced = UNKNOWN` if intermediate steps are missing

## 4. Verify Reachability (reachable)

**Goal:** Prove the vulnerable code path can actually execute.

**Evidence Required:**
- Function is called (not dead code)
- Route/API endpoint is registered
- No conditional guards that prevent execution

**Tool Call Example:**
```json
{
  "tool": "get_entry_points",
  "arguments": {
    "framework": "flask"
  }
}
```

**Checklist Update:**
- `reachable = PROVEN_TRUE` if function is called and route is accessible
- `reachable = PROVEN_FALSE` if dead code or feature-flagged off
- `reachable = UNKNOWN` if call graph is incomplete

## 5. Verify Boundary Crossing (boundary_crossed)

**Goal:** Prove external input reaches the file operation.

**Evidence Required:**
- Input comes from outside the system (HTTP, API, etc.)
- NOT an internal admin function or localhost-only endpoint

**Tool Call Example:**
```json
{
  "tool": "search_code",
  "arguments": {
    "pattern": "(@login_required|@admin_required|@require_auth)",
    "file_pattern": "**/*.py",
    "max_results": 50
  }
}
```

**Checklist Update:**
- `boundary_crossed = PROVEN_TRUE` if externally accessible (e.g., public download endpoint)
- `boundary_crossed = PROVEN_FALSE` if internal-only (e.g., admin file manager with strong auth)
- `boundary_crossed = UNKNOWN` if access controls are unclear

## 6. Rule Out Misconfiguration (not_only_misconfig)

**Goal:** Prove the vulnerability is in the code, not just a config issue.

**Evidence Required:**
- Vulnerability exists regardless of config settings
- NOT just "web server misconfigured to serve files outside document root"

**Checklist Update:**
- `not_only_misconfig = PROVEN_TRUE` if code is vulnerable by design
- `not_only_misconfig = PROVEN_FALSE` if only a web server config issue
- `not_only_misconfig = UNKNOWN` if unclear

## 7. StrictClassifier Alignment

**Expected Disposition:**
- If ALL 6 items are PROVEN_TRUE → `VALID_SECURITY_ISSUE`
- If sink_present or source_controlled_input is PROVEN_FALSE → `BY_DESIGN` or `SPECULATIVE`
- If dataflow_evidenced is PROVEN_FALSE (allowlist or path validation) → `BY_DESIGN` (safe by design)
- If not_only_misconfig is PROVEN_FALSE → `MISCONFIGURATION`
- If ANY is UNKNOWN → `SPECULATIVE` (unless preliminary_disposition fast-tracks)

**Disposition-Sensitive Downgrades:**
- If preliminary_disposition is already `BUG` or `VALID_SECURITY_ISSUE`, critic should fast-track to `READY_TO_REPORT` unless contradictions exist
- If preliminary_disposition is `MISCONFIGURATION`, critic should return `STOP_FILTERED` with disposition_hint='MISCONFIGURATION'

## Common False Positives to Avoid

**Trap 1: Hardcoded Paths**
```python
# No user input in path (SAFE)
with open('/var/log/app.log') as f:
    return f.read()
# source_controlled_input = PROVEN_FALSE
```

**Trap 2: Strict Allowlist**
```python
# Allowlist validation (SAFE)
ALLOWED = {'report': 'report.pdf', 'data': 'data.csv'}
file = ALLOWED.get(request.args['type'])
if file:
    with open(f'/var/files/{file}') as f:
        return f.read()
# dataflow_evidenced = PROVEN_FALSE
```

**Trap 3: Path Canonicalization with Validation**
```python
# Python pathlib with is_relative_to (SAFE in Python 3.9+)
from pathlib import Path
base = Path('/var/uploads').resolve()
requested = (base / user_file).resolve()
if requested.is_relative_to(base):
    with open(requested) as f:
        return f.read()
# SAFE - ensures path stays within base
# dataflow_evidenced = PROVEN_FALSE
```

**Trap 4: Framework Safe Defaults**
```python
# Flask send_from_directory (SAFE when used correctly)
return send_from_directory('/var/uploads', filename)
# Flask validates that filename doesn't escape directory
# dataflow_evidenced = PROVEN_FALSE
```

**Trap 5: Weak Filtering (False Sense of Security)**
```python
# Naive filtering (STILL UNSAFE)
filename = request.args['file'].replace('../', '')
with open(f'/var/files/{filename}') as f:
    return f.read()
# UNSAFE - can be bypassed with ....// or absolute paths
# dataflow_evidenced = PROVEN_TRUE (weak filtering is bypassable)
```

## Attack Scenarios

### Scenario 1: Reading Sensitive Files
```python
# Attacker requests: ?file=../../../etc/passwd
filename = request.args.get('file')
with open(f'/var/uploads/{filename}') as f:
    return f.read()
# Result: Reads /etc/passwd
```

### Scenario 2: Bypassing Weak Filters
```python
# Code tries to block traversal
filename = request.args['file'].replace('../', '')
# Attacker requests: ?file=....//....//etc/passwd
# After replace: ../../etc/passwd (bypass successful)
```

### Scenario 3: Absolute Paths
```python
# Code assumes relative paths
filename = request.args.get('file')
with open(f'/var/uploads/{filename}') as f:
    return f.read()
# Attacker requests: ?file=/etc/passwd
# Result: Opens /etc/passwd (absolute path overwrites base)
```

### Scenario 4: Windows Paths
```
# Windows path traversal
?file=..\..\..\windows\system32\config\sam
```

## Validation Techniques (for recognizing safe code)

**Safe Approaches:**
1. **Strict Allowlist** - Only allow specific filenames
2. **Path Canonicalization** - Resolve symlinks and validate result is within base
3. **Framework Helpers** - Use `send_from_directory()`, `Path.is_relative_to()`
4. **Input Rejection** - Reject any input containing `../`, `..\\`, or absolute paths

**Unsafe Approaches:**
1. **Naive String Replacement** - `replace('../', '')` is bypassable
2. **Blacklisting** - Trying to block all traversal sequences is error-prone
3. **No Validation** - Direct path concatenation

## Evidence Citation Format

Always cite evidence as:
- `file_path:line_start-line_end` for code snippets
- `artifact_id:finding_123` for previously collected evidence
- Never say "I believe" or "it appears" - use UNKNOWN if uncertain

## Key Insight

Path traversal requires:
1. **File operation sink** (open, sendFile, etc.)
2. **User-controlled path component**
3. **Insufficient path validation** (no allowlist, weak filtering, or bypassable canonicalization)
4. **External accessibility** (boundary crossed)

Safe code uses strict allowlists or proper path validation (e.g., `Path.is_relative_to()`).
