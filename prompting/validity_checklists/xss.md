# XSS (Cross-Site Scripting) Proof Checklist

You are analyzing a potential XSS vulnerability. Follow this evidence-gathering plan:

## 1. Identify the Sink (sink_present)

**Goal:** Prove that user data is rendered in an HTML/JavaScript context.

**Evidence Required:**
- Exact file path and line number of rendering operation
- Function name: `render()`, `render_template()`, `innerHTML`, `document.write()`, `Response()`, or template rendering

**Tool Call Example:**
```json
{
  "tool": "search_code",
  "arguments": {
    "pattern": "(render_template|render|innerHTML|document\\.write|dangerouslySetInnerHTML|Response\\()",
    "file_pattern": "**/*.{py,js,ts,jsx,tsx,html}",
    "max_results": 100
  }
}
```

**Checklist Update:**
- `sink_present = PROVEN_TRUE` if HTML/JS rendering found
- `sink_present = PROVEN_FALSE` if no rendering operations in codebase
- `sink_present = UNKNOWN` if files are missing or code is obfuscated

## 2. Identify the Source (source_controlled_input)

**Goal:** Prove user/attacker controls the rendered data.

**Evidence Required:**
- Input comes from: request parameters, body, headers, cookies, URL path, user-generated content
- NOT from: hardcoded values, config files, admin-only inputs

**Common Patterns:**
- Flask: `request.args.get()`, `request.form[]`, `request.json[]`
- Django: `request.GET[]`, `request.POST[]`, `request.body`
- FastAPI: Function parameters with `Query()`, `Body()`, `Path()`
- JavaScript: `document.location`, `window.location.search`, `URLSearchParams`
- React: Props from user input, state from API responses

**Tool Call Example:**
```json
{
  "tool": "read_file",
  "arguments": {
    "path": "app/templates/profile.html",
    "start_line": 10,
    "end_line": 40
  }
}
```

**Checklist Update:**
- `source_controlled_input = PROVEN_TRUE` if input is from HTTP request/external source
- `source_controlled_input = PROVEN_FALSE` if input is hardcoded or admin-only
- `source_controlled_input = UNKNOWN` if input origin is unclear

## 3. Trace Data Flow (dataflow_evidenced)

**Goal:** Prove user input flows to the rendering context without proper escaping.

**Evidence Required:**
- Step-by-step path from source to sink
- Cite each intermediate variable/function with file:line
- Prove that output encoding/escaping is absent or bypassable

**Safe Patterns (Auto-Escaping):**
If you see:
- React/Vue: `<div>{userName}</div>` (JSX auto-escapes by default)
- Jinja2: `{{ userName }}` with autoescaping enabled
- Django templates: `{{ userName }}` (auto-escapes by default)
- Rails ERB: `<%= h(userName) %>` or `<%= userName %>` with auto-escaping

These are SAFE - `dataflow_evidenced = PROVEN_FALSE`

**Unsafe Patterns (No Escaping):**
If you see:
- `innerHTML = userInput` (JavaScript DOM manipulation)
- `dangerouslySetInnerHTML={{__html: userInput}}` (React)
- Jinja2: `{{ userName|safe }}` or `{% autoescape false %}`
- Django: `{{ userName|safe }}` or template has autoescaping disabled
- `document.write(userInput)`, `eval(userInput)`

These are UNSAFE if userInput is attacker-controlled

**Tool Call Example:**
```json
{
  "tool": "trace_data_flow",
  "arguments": {
    "source": "request.args.get('name')",
    "file_path": "app/views.py",
    "sink_patterns": ["render_template(", "Response("]
  }
}
```

**Checklist Update:**
- `dataflow_evidenced = PROVEN_TRUE` if unsanitized flow exists
- `dataflow_evidenced = PROVEN_FALSE` if auto-escaped or properly sanitized
- `dataflow_evidenced = UNKNOWN` if intermediate steps are missing

## 4. Verify Reachability (reachable)

**Goal:** Prove the vulnerable code path can actually execute.

**Evidence Required:**
- Route/endpoint is registered
- Function is called (not dead code)
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

**Goal:** Prove external input reaches the rendering context.

**Evidence Required:**
- Input comes from outside the system (HTTP, WebSocket, URL parameters, etc.)
- NOT an internal admin function or localhost-only debug endpoint

**Tool Call Example:**
```json
{
  "tool": "search_code",
  "arguments": {
    "pattern": "(@login_required|@auth\\.required|@admin_required|@require_auth)",
    "file_pattern": "**/*.py",
    "max_results": 50
  }
}
```

**Checklist Update:**
- `boundary_crossed = PROVEN_TRUE` if externally accessible (e.g., public page, API)
- `boundary_crossed = PROVEN_FALSE` if internal-only (e.g., admin panel with strong auth)
- `boundary_crossed = UNKNOWN` if access controls are unclear

## 6. Rule Out Misconfiguration (not_only_misconfig)

**Goal:** Prove the vulnerability is in the code, not just a config issue.

**Evidence Required:**
- Vulnerability exists regardless of config settings
- NOT just "CSP disabled" or "X-XSS-Protection header missing"

**Checklist Update:**
- `not_only_misconfig = PROVEN_TRUE` if code is vulnerable by design
- `not_only_misconfig = PROVEN_FALSE` if only a config/header issue
- `not_only_misconfig = UNKNOWN` if unclear

## 7. Verify Security Controls Bypassed (security_control_bypassed)

**Goal:** Prove that output encoding/escaping is absent or insufficient.

**Evidence Required:**
- No context-appropriate encoding (HTML entity encoding, JavaScript escaping, URL encoding)
- OR encoding is present but bypassable (wrong context, incomplete escaping)

**XSS-Specific Requirement:**
This field is REQUIRED for XSS per blocking_gaps.py rules. You must prove escaping is bypassed.

**Examples:**
- **HTML Context**: `<div>{{user_input}}</div>` without HTML entity encoding
- **JavaScript Context**: `<script>var x = "{{user_input}}";</script>` without JS escaping
- **URL Context**: `<a href="{{user_input}}">` without URL validation/encoding
- **CSS Context**: `<style>{{user_input}}</style>` without CSS sanitization

**Tool Call Example:**
```json
{
  "tool": "read_file",
  "arguments": {
    "path": "app/templates/profile.html",
    "start_line": 50,
    "end_line": 80
  }
}
```

**Checklist Update:**
- `security_control_bypassed = PROVEN_TRUE` if no escaping or bypassable escaping
- `security_control_bypassed = PROVEN_FALSE` if proper context-aware escaping
- `security_control_bypassed = UNKNOWN` if escaping behavior is unclear

## 8. StrictClassifier Alignment

**Expected Disposition:**
- If ALL 7 items (including security_control_bypassed) are PROVEN_TRUE → `VALID_SECURITY_ISSUE`
- If sink_present or source_controlled_input is PROVEN_FALSE → `BY_DESIGN` or `SPECULATIVE`
- If dataflow_evidenced is PROVEN_FALSE (auto-escaped) → `BY_DESIGN` (safe by design)
- If security_control_bypassed is PROVEN_FALSE (properly escaped) → `BY_DESIGN`
- If not_only_misconfig is PROVEN_FALSE → `MISCONFIGURATION`
- If ANY is UNKNOWN → `SPECULATIVE` (unless preliminary_disposition fast-tracks)

**XSS-Specific Note:**
Per blocking_gaps.py, XSS requires proving that `security_control_bypassed = PROVEN_TRUE` in addition to the standard 6 fields. This means you must prove output is NOT escaped.

**Disposition-Sensitive Downgrades:**
- If preliminary_disposition is already `BUG` or `VALID_SECURITY_ISSUE`, critic should fast-track to `READY_TO_REPORT` unless contradictions exist
- If preliminary_disposition is `MISCONFIGURATION`, critic should return `STOP_FILTERED` with disposition_hint='MISCONFIGURATION'

## Common False Positives to Avoid

**Trap 1: Framework Auto-Escaping**
```jsx
// React auto-escapes JSX variables
<div>{userName}</div>  // SAFE - React escapes by default
// dataflow_evidenced = PROVEN_FALSE, security_control_bypassed = PROVEN_FALSE
```

**Trap 2: Template Auto-Escaping**
```jinja
{# Jinja2 with autoescaping #}
{{ userName }}  {# SAFE if autoescaping is on #}
{{ userName|safe }}  {# UNSAFE - escaping bypassed! #}
```

**Trap 3: JSON API Responses**
```python
# Data in JSON response is not XSS (unless rendered as HTML client-side)
return jsonify({"name": user_input})  # SAFE for JSON API
# But if frontend does: innerHTML = jsonData.name → UNSAFE
```

**Trap 4: CSP Mitigations**
```
Content-Security-Policy: default-src 'self'; script-src 'self'
# Strong CSP can block XSS exploitation
# But this is a HARDENING (defense-in-depth), not BY_DESIGN
# If code has XSS without CSP, it's still VALID_SECURITY_ISSUE
```

**Trap 5: DOM-Based XSS vs Reflected/Stored**
```javascript
// DOM-based XSS (client-side only)
document.getElementById('div').innerHTML = location.hash.slice(1);
// Still XSS, but source and sink are both client-side
```

## Evidence Citation Format

Always cite evidence as:
- `file_path:line_start-line_end` for code snippets
- `artifact_id:finding_123` for previously collected evidence
- Never say "I believe" or "it appears" - use UNKNOWN if uncertain
