# Command Injection Proof Checklist

You are analyzing a potential command injection vulnerability. Follow this evidence-gathering plan:

## 1. Identify the Sink (sink_present)

**Goal:** Prove that shell commands are executed with potential for injection.

**Evidence Required:**
- Exact file path and line number of command execution
- Function name: `os.system()`, `subprocess.call()` with `shell=True`, `popen()`, `exec()` (shell context), backticks, `child_process.exec()`

**Tool Call Example:**
```json
{
  "tool": "search_code",
  "arguments": {
    "pattern": "(os\\.system\\(|subprocess\\.call\\(|subprocess\\.run\\(.*shell=True|popen\\(|child_process\\.exec\\(|shell_exec\\(|\\`.*\\`)",
    "file_pattern": "**/*.{py,js,ts,php,rb}",
    "max_results": 100
  }
}
```

**Checklist Update:**
- `sink_present = PROVEN_TRUE` if shell command execution found
- `sink_present = PROVEN_FALSE` if no command execution operations in codebase
- `sink_present = UNKNOWN` if files are missing or code is obfuscated

## 2. Identify the Source (source_controlled_input)

**Goal:** Prove user/attacker controls part of the command.

**Evidence Required:**
- Input comes from: request parameters, body, headers, cookies, file names, user-uploaded files
- NOT from: hardcoded values, config files, admin-only inputs

**Common Patterns:**
- Python: `request.args.get()`, `request.form[]`, `request.json[]`, `request.files`
- Node.js: `req.query`, `req.body`, `req.params`, `req.file.filename`
- PHP: `$_GET`, `$_POST`, `$_FILES`

**Tool Call Example:**
```json
{
  "tool": "read_file",
  "arguments": {
    "path": "app/utils.py",
    "start_line": 30,
    "end_line": 60
  }
}
```

**Checklist Update:**
- `source_controlled_input = PROVEN_TRUE` if input is from HTTP request/external source
- `source_controlled_input = PROVEN_FALSE` if input is hardcoded or admin-only
- `source_controlled_input = UNKNOWN` if input origin is unclear

## 3. Trace Data Flow (dataflow_evidenced)

**Goal:** Prove user input flows to command execution without proper sanitization.

**Evidence Required:**
- Step-by-step path from source to sink
- Cite each intermediate variable/function with file:line
- Prove that shell metacharacter filtering is absent or insufficient

**Safe Patterns (No Shell Involvement):**
If you see:
```python
# subprocess with list arguments and shell=False (SAFE)
subprocess.run(['git', 'log', user_input], shell=False)
# No shell metacharacters interpreted
```
This is SAFE - `dataflow_evidenced = PROVEN_FALSE`

```python
# Strict allowlist for arguments
ALLOWED_FORMATS = ['png', 'jpg', 'gif']
if user_format in ALLOWED_FORMATS:
    subprocess.run(['convert', f'input.{user_format}', 'output.png'])
# SAFE - allowlist prevents command injection
```

**Unsafe Patterns (Shell Involvement):**
If you see:
```python
# Shell=True with user input (UNSAFE)
os.system(f"convert {user_file} output.png")
subprocess.run(f"git log {user_input}", shell=True)
```

```javascript
// child_process.exec uses shell (UNSAFE)
child_process.exec(`ls -la ${userDir}`);
```

These are UNSAFE if user input contains shell metacharacters: `;`, `|`, `&`, `$()`, backticks, `>`, `<`, `&&`, `||`

**Tool Call Example:**
```json
{
  "tool": "trace_data_flow",
  "arguments": {
    "source": "request.files['file'].filename",
    "file_path": "app/converter.py",
    "sink_patterns": ["os.system(", "subprocess.run("]
  }
}
```

**Checklist Update:**
- `dataflow_evidenced = PROVEN_TRUE` if unsanitized flow with shell involvement
- `dataflow_evidenced = PROVEN_FALSE` if argv arrays (no shell) or strict allowlist
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

**Goal:** Prove external input reaches the command execution OR prove security controls are bypassed.

**Rule 3b Exception for COMMAND_INJECTION:**
Per blocking_gaps.py, COMMAND_INJECTION can use `security_control_bypassed` instead of `boundary_crossed` if proven.

**Evidence Required (Boundary Crossing):**
- Input comes from outside the system (HTTP, file upload, network service, etc.)
- NOT an internal admin function or localhost-only debug endpoint

**Evidence Required (Security Control Bypassed):**
- Allowlist is present but bypassable
- OR shell escaping exists but can be circumvented
- OR command uses shell=True when shell=False would work

**Tool Call Example:**
```json
{
  "tool": "read_file",
  "arguments": {
    "path": "app/converter.py",
    "start_line": 20,
    "end_line": 50
  }
}
```

**Checklist Update:**
- `boundary_crossed = PROVEN_TRUE` if externally accessible
- `boundary_crossed = PROVEN_FALSE` if internal-only (and security_control_bypassed not proven)
- `security_control_bypassed = PROVEN_TRUE` if shell escaping is bypassable
- Use whichever is easier to prove (only need one per Rule 3b)

## 6. Rule Out Misconfiguration (not_only_misconfig)

**Goal:** Prove the vulnerability is in the code, not just a config issue.

**Evidence Required:**
- Vulnerability exists regardless of config settings
- NOT just "sudo configured incorrectly" or "file permissions wrong"

**Checklist Update:**
- `not_only_misconfig = PROVEN_TRUE` if code is vulnerable by design
- `not_only_misconfig = PROVEN_FALSE` if only a config issue
- `not_only_misconfig = UNKNOWN` if unclear

## 7. StrictClassifier Alignment

**Expected Disposition:**
- If standard 6 items (source/sink/dataflow/reachable/boundary/not_misconfig) are PROVEN_TRUE → `VALID_SECURITY_ISSUE`
- **Rule 3b Alternative**: If security_control_bypassed is PROVEN_TRUE, it can replace boundary_crossed
- If sink_present or source_controlled_input is PROVEN_FALSE → `BY_DESIGN` or `SPECULATIVE`
- If dataflow_evidenced is PROVEN_FALSE (argv arrays, no shell) → `BY_DESIGN` (safe by design)
- If not_only_misconfig is PROVEN_FALSE → `MISCONFIGURATION`
- If ANY is UNKNOWN → `SPECULATIVE` (unless preliminary_disposition fast-tracks)

**Rule 3b for COMMAND_INJECTION:**
You can prove EITHER:
- Standard path: source + sink + dataflow + reachable + boundary + not_misconfig
- OR Alternative: source + sink + dataflow + reachable + security_control_bypassed + not_misconfig

**Disposition-Sensitive Downgrades:**
- If preliminary_disposition is already `BUG` or `VALID_SECURITY_ISSUE`, critic should fast-track to `READY_TO_REPORT` unless contradictions exist
- If preliminary_disposition is `MISCONFIGURATION`, critic should return `STOP_FILTERED` with disposition_hint='MISCONFIGURATION'

## Common False Positives to Avoid

**Trap 1: Argv Arrays Without Shell**
```python
# subprocess with list arguments and shell=False (SAFE)
subprocess.run(['git', 'log', user_input], shell=False)
# No shell metacharacters interpreted
# dataflow_evidenced = PROVEN_FALSE
```

```python
# execve() family doesn't use shell (SAFE)
os.execve('/bin/ls', ['ls', user_input], env)
# sink_present = PROVEN_FALSE (no shell command injection possible)
```

**Trap 2: Fixed Subcommands with Allowlists**
```python
ALLOWED_FORMATS = ['png', 'jpg', 'gif']
if user_format in ALLOWED_FORMATS:
    os.system(f"convert input.{user_format} output.png")
# SAFE - strict allowlist
# dataflow_evidenced = PROVEN_FALSE
```

**Trap 3: Proper Escaping**
```python
import shlex
safe_arg = shlex.quote(user_input)
os.system(f"ls {safe_arg}")
# POTENTIALLY SAFE - but verify shlex.quote is used correctly
# Check if user_input goes through shlex.quote before reaching os.system
```

**Trap 4: Hardcoded Commands**
```python
# User input affects data passed to command, not command structure
tempfile = create_tempfile(user_data)
os.system(f"process_file < {tempfile}")
# If tempfile is system-generated, not user-controlled filename: SAFE
# source_controlled_input = PROVEN_FALSE (for command structure)
```

**Trap 5: Node.js execFile vs exec**
```javascript
// child_process.execFile does NOT use shell (SAFE)
child_process.execFile('git', ['log', userInput], callback);
// dataflow_evidenced = PROVEN_FALSE

// child_process.exec DOES use shell (UNSAFE)
child_process.exec(`git log ${userInput}`, callback);
// UNSAFE if userInput contains shell metacharacters
```

## Shell Metacharacters to Look For

Evidence that user input can inject shell commands:
- `;` - Command separator
- `|` - Pipe to another command
- `&` - Background execution
- `$()` or backticks - Command substitution
- `>`, `>>`, `<` - Redirection
- `&&`, `||` - Conditional execution
- Newline (`\n`) - Command separator

If any of these can reach the shell via user input, it's command injection.

## Evidence Citation Format

Always cite evidence as:
- `file_path:line_start-line_end` for code snippets
- `artifact_id:finding_123` for previously collected evidence
- Never say "I believe" or "it appears" - use UNKNOWN if uncertain

## Rule 3b Reminder

For COMMAND_INJECTION, you can prove `security_control_bypassed` instead of `boundary_crossed`. This is useful when:
- Command execution is internal but has bypassable shell escaping
- Allowlist exists but incomplete
- Uses shell=True when shell=False would work (unnecessary shell involvement)

If you can prove security controls are bypassed, that's sufficient even if boundary isn't crossed.
