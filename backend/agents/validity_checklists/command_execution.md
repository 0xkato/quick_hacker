# Command Execution Validity Checklist

Use this checklist when evaluating a suspected command execution vulnerability.
Validate only if ALL conditions are met.

## Required Conditions

### 1. Attacker Data Reaches Command Sink
- [ ] Attacker-controlled data flows into a function that executes shell commands
- [ ] The sink interprets attacker data as command syntax (shell involvement confirmed)
- [ ] Examples: `system()`, `exec()`, `shell_exec()`, `popen()`, backticks, `eval()` with shell context

### 2. No Effective Allowlist or Argument Isolation
- [ ] No allowlist restricts input to safe values OR allowlist is bypassable
- [ ] Command is constructed via string concatenation or interpolation (not argv arrays)
- [ ] Attacker can inject shell metacharacters (`;`, `|`, `&`, `$()`, backticks, etc.)

### 3. Reachability
- [ ] Code path is reachable (routing/auth/config analysis confirms)
- [ ] Not dead code, disabled feature, or admin-only with strong auth

## Common False Positive Traps

DISPROVE the vulnerability if any of these apply:

- **Argv Arrays Without Shell**: Functions like `execve()` or `subprocess.Popen()` with `shell=False` use argv arrays that don't interpret shell metacharacters.
  - Example: `subprocess.Popen(['git', 'log', user_input], shell=False)` is safe from command injection (though may have other issues)

- **Fixed Subcommands with Allowlists**: Commands where attacker input only affects arguments, and arguments are validated against a strict allowlist.
  - Example: `exec("convert #{sanitized_format} input.png output.png")` where format is allowlisted to `['png', 'jpg', 'gif']`

- **Hardcoded Commands Only**: User input affects data passed to command but not command structure.
  - Example: `system("process_file < #{tempfile_path}")` where tempfile is created by system, not attacker

- **Parameterized Execution**: Modern APIs that properly separate command from arguments.
  - Example: Node.js `child_process.execFile()` or Python `subprocess.run()` with list arguments and `shell=False`

## Evidence Requirements

To validate, you must show:
1. **Exact source**: Where attacker data enters (file path + line number + code snippet)
2. **Exact sink**: Where command execution occurs (file path + line number + code snippet)
3. **Dataflow trace**: How attacker data reaches the sink without being neutralized
4. **Mitigation analysis**: Why allowlists/escaping are absent, incomplete, or bypassable
5. **Reachability**: Evidence the code path is reachable (routing/auth/config)

## Classification

- ✅ **VALIDATED_VULNERABILITY**: All conditions met, shell involvement confirmed, no effective mitigations
- ⚠️ **NEEDS_HUMAN_REVIEW**: Strong signal but uncertain about shell involvement or framework-level protections
- 🔧 **HARDENING_OPPORTUNITY**: Risky pattern but credible defenses (argv arrays, allowlists) reduce exploitability
- ❌ **NOT_A_VULNERABILITY**: Effective mitigation confirmed (no shell, strong allowlist, parameterized execution)
