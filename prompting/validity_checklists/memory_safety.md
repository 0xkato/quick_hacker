# Memory Safety Analysis Module

**CRITICAL: ANALYSIS ONLY - NO EXPLOITATION INSTRUCTIONS**

You are analyzing potential memory safety vulnerabilities in C, C++, or Rust code. This module is for DEFENSIVE SECURITY ANALYSIS only.

## Scope Limitations

**DO:**
- Identify buffer overflows, use-after-free, double-free, null pointer dereferences
- Analyze unsafe patterns and recommend fixes
- Provide remediation guidance (bounds checking, safe APIs, RAII)

**DO NOT:**
- Provide exploit development guidance
- Generate payloads or shellcode
- Explain how to weaponize vulnerabilities
- Describe ROP chains, heap spraying, or exploitation techniques

## 1. Identify the Sink (sink_present)

**Goal:** Prove a memory-unsafe operation occurs.

**Evidence Required:**
- Exact file path and line number
- Operation type: buffer write, pointer dereference, memory allocation/deallocation

**Common Unsafe Functions (C/C++):**
- `strcpy()`, `strcat()`, `sprintf()`, `gets()` (unbounded)
- `malloc()`/`free()` with manual management
- Raw pointer arithmetic without bounds checking

**Rust-Specific:**
- `unsafe { }` blocks
- `.get_unchecked()`
- Raw pointer dereferences: `*ptr`

**Tool Call Example:**
```json
{
  "tool": "search_code",
  "arguments": {
    "pattern": "(strcpy|strcat|sprintf|gets|malloc|free|unsafe|get_unchecked)\\(",
    "file_pattern": "**/*.{c,cpp,rs}",
    "max_results": 100
  }
}
```

**Checklist Update:**
- `sink_present = PROVEN_TRUE` if memory-unsafe operation found
- `sink_present = PROVEN_FALSE` if only safe APIs used
- `sink_present = UNKNOWN` if files are missing

## 2. Identify the Source (source_controlled_input)

**Goal:** Prove user/attacker controls the input that affects memory operation.

**Evidence Required:**
- Input comes from: network, file, user input, environment variables
- NOT from: hardcoded constants, internal state

**Common Patterns:**
- C: `read()`, `recv()`, `fgets()` from stdin/socket
- C++: `std::cin`, `getline()`, network input
- Rust: `std::io::stdin().read_line()`, network parsing

**Checklist Update:**
- `source_controlled_input = PROVEN_TRUE` if external input affects memory op
- `source_controlled_input = PROVEN_FALSE` if input is internal/constant
- `source_controlled_input = UNKNOWN` if input source is unclear

## 3. Trace Data Flow (dataflow_evidenced)

**Goal:** Prove user input affects the vulnerable memory operation without bounds checking.

**Safe Patterns:**
- `strncpy()` with correct bounds
- `snprintf()` with buffer size
- Rust: `.get()` instead of `.get_unchecked()`
- RAII patterns (C++ smart pointers, Rust ownership)

**Unsafe Patterns:**
- `strcpy(buffer, user_input)` (unbounded)
- `malloc(user_provided_size)` without validation
- `buffer[user_index]` without bounds check

**Tool Call Example:**
```json
{
  "tool": "read_file",
  "arguments": {
    "path": "src/parser.c",
    "start_line": 100,
    "end_line": 150
  }
}
```

**Checklist Update:**
- `dataflow_evidenced = PROVEN_TRUE` if unbounded flow exists
- `dataflow_evidenced = PROVEN_FALSE` if bounds checking present
- `dataflow_evidenced = UNKNOWN` if intermediate logic is unclear

## 4. Verify Reachability (reachable)

**Goal:** Prove the vulnerable code can execute.

**Evidence Required:**
- Function is called from entrypoint
- Not dead code or debug-only

**Tool Call Example:**
```json
{
  "tool": "find_usages",
  "arguments": {
    "name": "parse_packet",
    "max_results": 50
  }
}
```

**Checklist Update:**
- `reachable = PROVEN_TRUE` if called from entrypoint
- `reachable = PROVEN_FALSE` if dead code
- `reachable = UNKNOWN` if call graph is incomplete

## 5. Verify Boundary Crossing (boundary_crossed)

**Goal:** Prove external input reaches the memory operation.

**Evidence Required:**
- Input comes from network, IPC, file, user input
- NOT from internal testing functions

**Checklist Update:**
- `boundary_crossed = PROVEN_TRUE` if external input
- `boundary_crossed = PROVEN_FALSE` if internal-only
- `boundary_crossed = UNKNOWN` if unclear

## 6. Rule Out Misconfiguration (not_only_misconfig)

**Goal:** Prove the vulnerability is in the code, not just compiler flags.

**Checklist Update:**
- `not_only_misconfig = PROVEN_TRUE` if code is vulnerable by design
- `not_only_misconfig = PROVEN_FALSE` if only a compiler/config issue (e.g., stack canaries disabled)
- `not_only_misconfig = UNKNOWN` if unclear

## 7. StrictClassifier Alignment

**Expected Disposition:**
- If ALL 6 items are PROVEN_TRUE → `VALID_SECURITY_ISSUE`
- If dataflow_evidenced is PROVEN_FALSE (bounds checked) → `BY_DESIGN`
- If not_only_misconfig is PROVEN_FALSE → `MISCONFIGURATION`
- If ANY is UNKNOWN → `SPECULATIVE`

## Remediation Guidance (Defensive)

**For Buffer Overflows:**
- Replace `strcpy()` with `strncpy()` or `strlcpy()`
- Replace `sprintf()` with `snprintf()`
- Always validate buffer sizes before writes

**For Use-After-Free:**
- Set pointers to NULL after `free()`
- Use smart pointers (C++ `std::unique_ptr`, `std::shared_ptr`)
- Use Rust ownership system (borrow checker prevents UAF)

**For Integer Overflows:**
- Check for overflow before arithmetic operations
- Use safe integer libraries (SafeInt, checked arithmetic)

## Common False Positives - CRITICAL: REJECT THESE

**CRITICAL RULE: If bounds checking or length validation EXISTS, the finding is SPECULATIVE**

An attack scenario that says "if attacker bypasses the length check" or "if validation is circumvented"
is SPECULATIVE because the control EXISTS. You cannot assume controls can be bypassed.

**Trap 1: Bounded operations that look unbounded**
```c
char buffer[256];
strncpy(buffer, user_input, sizeof(buffer) - 1);  // Bounded, dataflow_evidenced = PROVEN_FALSE
buffer[255] = '\0';
```
→ REJECT: strncpy with size limit = NOT a buffer overflow

**Trap 2: Length validation before copy**
```c
#define MAX_SIZE 256
if (strlen(input) >= MAX_SIZE) {
    return -1;  // Rejects oversized input
}
strcpy(buffer, input);  // Safe because length is validated
```
→ REJECT: Length is checked before copy. Not exploitable.

**Trap 3: Size parameter from constant**
```c
#define CONFIG_SHELL_CMD_BUFF_SIZE 256
char cmd[CONFIG_SHELL_CMD_BUFF_SIZE];
strncpy(cmd, user_input, CONFIG_SHELL_CMD_BUFF_SIZE - 1);
```
→ REJECT: Size limit is enforced by constant. "If attacker bypasses length" is SPECULATIVE.

**Trap 4: Rust safe abstractions**
```rust
let value = vec.get(user_index);  // Returns Option, safe
// vs.
let value = vec[user_index];      // Panics on out-of-bounds, still memory-safe
// vs.
let value = unsafe { vec.get_unchecked(user_index) };  // Unsafe, potential vulnerability
```
→ REJECT: Only get_unchecked is potentially vulnerable

**Trap 5: snprintf with buffer size**
```c
char buffer[100];
snprintf(buffer, sizeof(buffer), "User: %s", input);  // Cannot overflow
```
→ REJECT: snprintf with size = bounded, NOT a vulnerability

**Trap 6: Explicit bounds check before array access**
```c
if (index < 0 || index >= ARRAY_SIZE) {
    return ERROR_OUT_OF_BOUNDS;
}
array[index] = value;  // Safe - bounds checked above
```
→ REJECT: Bounds check exists and protects the access

## When IS It a Real Vulnerability?

Only mark as VALID_SECURITY_ISSUE if:
1. NO bounds checking anywhere in the flow
2. NO length validation before the operation
3. Size comes from attacker-controlled input without validation
4. The unsafe operation is reachable from external input

Example of REAL vulnerability:
```c
void process(char *user_input) {
    char buffer[64];
    strcpy(buffer, user_input);  // NO bounds check, NO length validation
}
```
This IS vulnerable because there is NO protection.

## Evidence Citation Format

Always cite evidence as:
- `file_path:line_start-line_end` for code snippets
- `artifact_id:finding_123` for previously collected evidence
- Never provide exploit payloads or weaponization guidance
