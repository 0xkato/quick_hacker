# Path Traversal Validity Checklist

Use this checklist when evaluating a suspected path traversal vulnerability.
Validate only if ALL conditions are met.

## Required Conditions

### 1. Attacker Controls Path Segments
- [ ] Attacker-controlled data affects filesystem path used in file operation
- [ ] Input includes or can inject directory traversal sequences (`../`, `..\\`, encoded variants)
- [ ] Path construction allows attacker to navigate outside intended directory

### 2. Base Directory Enforcement Absent or Bypassable
- [ ] No base directory enforcement OR enforcement is bypassable
- [ ] No path canonicalization OR canonicalization happens after unsafe operations
- [ ] Path validation uses blocklists (checking for `../`) instead of allowlists
- [ ] Symlink resolution or URL encoding can bypass restrictions

### 3. Sink Performs File Operations
- [ ] Path is used in actual file operation (read, write, delete, include, serve)
- [ ] Examples: `fopen()`, `readFile()`, `file_get_contents()`, `unlink()`, `require()`, static file serving
- [ ] Not just path validation or logging without file access

## Common False Positive Traps

DISPROVE the vulnerability if any of these apply:

- **Safe-Join with Base Directory**: Frameworks/libraries that properly enforce base directory boundaries.
  - Example: `path.join(BASE_DIR, userInput)` followed by `path.normalize()` and prefix check, or `fs.realpath()` with base validation

- **Strict Filename Allowlists**: Input validated against allowlist of specific filenames without directory separators.
  - Example: `allowedFiles = ['report.pdf', 'summary.txt']; if (allowedFiles.includes(userInput)) { readFile(userInput) }`

- **Path Canonicalization with Prefix Validation**: Proper canonicalization followed by verification that result stays within base.
  - Example: `realPath = os.path.realpath(os.path.join(base, userInput)); if realPath.startswith(base): open(realPath)`

- **No Directory Separators Allowed**: Input validation explicitly rejects directory separators and path navigation.
  - Example: `if (/[\/\\.]/.test(filename)) { throw error; } fs.readFile(SAFE_DIR + '/' + filename)`

## Evidence Requirements

To validate, you must show:
1. **Exact source**: Where attacker data enters (file path + line number + code snippet)
2. **Exact sink**: Where file operation occurs (file path + line number + code snippet)
3. **Dataflow trace**: How attacker data reaches the sink affecting path location
4. **Mitigation analysis**: Why base-dir enforcement/canonicalization are absent, incomplete, or bypassable
5. **Reachability**: Evidence the code path is reachable (routing/auth/config)

## Classification

- ✅ **VALIDATED_VULNERABILITY**: All conditions met, attacker can access files outside intended directory
- ⚠️ **NEEDS_HUMAN_REVIEW**: Strong signal but uncertain about framework-level path protections or symlink handling
- 🔧 **HARDENING_OPPORTUNITY**: Risky pattern but credible defenses (safe-join, canonicalization, allowlists) reduce exploitability
- ❌ **NOT_A_VULNERABILITY**: Effective mitigation confirmed (base-dir enforcement, strict allowlist, proper canonicalization)
