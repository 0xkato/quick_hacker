# Code Injection Proof Checklist

You are analyzing a potential code injection vulnerability (eval/exec). Follow this evidence-gathering plan:

## 1. Identify the Sink (sink_present)

**Goal:** Prove that code is dynamically evaluated/executed.

**Evidence Required:**
- Exact file path and line number of eval/exec operation
- Function name: `eval()`, `exec()`, `compile()`, `Function()`, `setTimeout()` with string, `setInterval()` with string

**Tool Call Example:**
```json
{
  "tool": "search_code",
  "arguments": {
    "pattern": "(\\beval\\(|\\bexec\\(|\\bcompile\\(|new Function\\(|setTimeout\\(.*['\"]|setInterval\\(.*['\"])",
    "file_pattern": "**/*.{py,js,ts}",
    "max_results": 100
  }
}
```

**Checklist Update:**
- `sink_present = PROVEN_TRUE` if eval/exec operation found
- `sink_present = PROVEN_FALSE` if no code execution operations in codebase
- `sink_present = UNKNOWN` if files are missing or code is obfuscated

## 2. Identify the Source (source_controlled_input)

**Goal:** Prove user/attacker controls the code being evaluated.

**Evidence Required:**
- Input comes from: request parameters, body, headers, cookies, user files, database (user-controlled data)
- NOT from: hardcoded values, config files, admin-only inputs, trusted sources

**Common Patterns:**
- Python: `request.args.get()`, `request.form[]`, `request.json[]`
- JavaScript: `req.query`, `req.body`, `req.params`, `process.argv`
- Node.js: Reading from user-uploaded files

**Tool Call Example:**
```json
{
  "tool": "read_file",
  "arguments": {
    "path": "app/calculator.py",
    "start_line": 20,
    "end_line": 50
  }
}
```

**Checklist Update:**
- `source_controlled_input = PROVEN_TRUE` if input is from HTTP request/external source
- `source_controlled_input = PROVEN_FALSE` if input is hardcoded or admin-only
- `source_controlled_input = UNKNOWN` if input origin is unclear

## 3. Trace Data Flow (dataflow_evidenced)

**Goal:** Prove user input flows to eval/exec without sufficient validation.

**Evidence Required:**
- Step-by-step path from source to sink
- Cite each intermediate variable/function with file:line
- Note any allowlisting/validation attempts (but prove they're insufficient)

**Safe Patterns (Strong Allowlists):**
If you see:
```python
ALLOWED_OPS = {'+', '-', '*', '/', '(', ')'}
if all(c.isdigit() or c in ALLOWED_OPS for c in user_input):
    result = eval(user_input)  # SAFE - strict allowlist
```
This is SAFE - `dataflow_evidenced = PROVEN_FALSE`

**Unsafe Patterns (No Validation):**
If you see:
```python
result = eval(user_input)  # UNSAFE - no validation
code = compile(user_input, '<string>', 'exec')  # UNSAFE
exec(f"calculate({user_input})")  # UNSAFE - string interpolation
```
These are UNSAFE if user_input is attacker-controlled

**Tool Call Example:**
```json
{
  "tool": "trace_data_flow",
  "arguments": {
    "source": "request.args.get('expression')",
    "file_path": "app/calculator.py",
    "sink_patterns": ["eval(", "exec(", "compile("]
  }
}
```

**Checklist Update:**
- `dataflow_evidenced = PROVEN_TRUE` if unvalidated flow exists
- `dataflow_evidenced = PROVEN_FALSE` if strict allowlist or safe alternative used
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
- `reachable = PROVEN_TRUE` if function is called and route is registered
- `reachable = PROVEN_FALSE` if dead code or feature-flagged off
- `reachable = UNKNOWN` if call graph is incomplete

## 5. Verify Boundary Crossing (boundary_crossed) OR Security Control Bypassed (Rule 3b Exception)

**Goal:** Prove external input reaches the eval/exec OR prove security controls are bypassed.

**Rule 3b Exception for CODE_INJECTION:**
Per blocking_gaps.py, CODE_INJECTION can use `security_control_bypassed` instead of `boundary_crossed` if proven. This recognizes that even internal eval/exec with bypassed validation is dangerous.

**Evidence Required (Boundary Crossing):**
- Input comes from outside the system (HTTP, CLI, file upload, etc.)
- NOT an internal admin function or localhost-only debug endpoint

**Evidence Required (Security Control Bypassed):**
- Allowlist is present but bypassable (e.g., incomplete character filtering)
- OR validation exists but can be circumvented
- OR eval/exec is used in a way that bypasses intended restrictions

**Tool Call Example:**
```json
{
  "tool": "read_file",
  "arguments": {
    "path": "app/calculator.py",
    "start_line": 15,
    "end_line": 45
  }
}
```

**Checklist Update:**
- `boundary_crossed = PROVEN_TRUE` if externally accessible
- `boundary_crossed = PROVEN_FALSE` if internal-only (and security_control_bypassed not proven)
- `security_control_bypassed = PROVEN_TRUE` if validation is bypassable
- Use whichever is easier to prove (only need one per Rule 3b)

## 6. Rule Out Misconfiguration (not_only_misconfig)

**Goal:** Prove the vulnerability is in the code, not just a config issue.

**Evidence Required:**
- Vulnerability exists regardless of config settings
- NOT just "debug mode enabled" with eval

**Checklist Update:**
- `not_only_misconfig = PROVEN_TRUE` if code is vulnerable by design
- `not_only_misconfig = PROVEN_FALSE` if only a config issue
- `not_only_misconfig = UNKNOWN` if unclear

## 7. StrictClassifier Alignment

**Expected Disposition:**
- If standard 6 items (source/sink/dataflow/reachable/boundary/not_misconfig) are PROVEN_TRUE → `VALID_SECURITY_ISSUE`
- **Rule 3b Alternative**: If security_control_bypassed is PROVEN_TRUE, it can replace boundary_crossed
- If sink_present or source_controlled_input is PROVEN_FALSE → `BY_DESIGN` or `SPECULATIVE`
- If dataflow_evidenced is PROVEN_FALSE (strict allowlist) → `BY_DESIGN` (safe by design)
- If not_only_misconfig is PROVEN_FALSE → `MISCONFIGURATION`
- If ANY is UNKNOWN → `SPECULATIVE` (unless preliminary_disposition fast-tracks)

**Rule 3b for CODE_INJECTION:**
You can prove EITHER:
- Standard path: source + sink + dataflow + reachable + boundary + not_misconfig
- OR Alternative: source + sink + dataflow + reachable + security_control_bypassed + not_misconfig

**Disposition-Sensitive Downgrades:**
- If preliminary_disposition is already `BUG` or `VALID_SECURITY_ISSUE`, critic should fast-track to `READY_TO_REPORT` unless contradictions exist
- If preliminary_disposition is `MISCONFIGURATION`, critic should return `STOP_FILTERED` with disposition_hint='MISCONFIGURATION'

## Common False Positives to Avoid

**Trap 1: Hardcoded Eval**
```python
# User input doesn't reach eval
result = eval("2 + 2")  # SAFE - hardcoded
# source_controlled_input = PROVEN_FALSE
```

**Trap 2: Strong Allowlist**
```python
SAFE_CHARS = set('0123456789+-*/(). ')
if all(c in SAFE_CHARS for c in user_input):
    result = eval(user_input)  # SAFE - strict allowlist
# dataflow_evidenced = PROVEN_FALSE
```

**Trap 3: AST-Based Validation**
```python
import ast
tree = ast.parse(user_input, mode='eval')
allowed_nodes = (ast.Expression, ast.BinOp, ast.Num, ast.Add, ast.Sub)
if all(isinstance(node, allowed_nodes) for node in ast.walk(tree)):
    result = eval(user_input)  # SAFE - AST allowlist
# dataflow_evidenced = PROVEN_FALSE
```

**Trap 4: JSON.parse() is NOT eval()**
```javascript
// JSON.parse is SAFE - it parses JSON, doesn't execute code
const data = JSON.parse(userInput);  // SAFE
// sink_present = PROVEN_FALSE (JSON.parse is not code execution)
```

**Trap 5: Template Engines (Not eval)**
```python
# Template rendering is NOT code injection (unless template syntax is user-controlled)
template.render(user_input)  # SAFE - template engines escape by default
# This is XSS territory, not CODE_INJECTION
```

**Trap 6: Feature Intent - Calculator/REPL Tools**
```python
# If this is an intentional calculator/REPL feature with documentation
@app.route('/calculator')
def calculator():
    # Docs say: "Evaluate mathematical expressions"
    return eval(request.args['expr'])
# Check for 2+ strong signals of feature intent (path + docs)
# If BY_DESIGN, preliminary_disposition should reflect this
```

## Evidence Citation Format

Always cite evidence as:
- `file_path:line_start-line_end` for code snippets
- `artifact_id:finding_123` for previously collected evidence
- Never say "I believe" or "it appears" - use UNKNOWN if uncertain

## Rule 3b Reminder

For CODE_INJECTION, you can prove `security_control_bypassed` instead of `boundary_crossed`. This is useful when:
- Eval/exec is internal but has bypassable validation
- Allowlist exists but incomplete (e.g., allows `__import__`)
- Restricted namespace but escapable

If you can prove security controls are bypassed, that's sufficient even if boundary isn't crossed.
