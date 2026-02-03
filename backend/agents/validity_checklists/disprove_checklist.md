# Disprove-First Self-Critique Checklist

Before finalizing ANY finding as VALIDATED_VULNERABILITY, you MUST attempt to disprove it by answering these 6 questions. This is MANDATORY and enforced by the `finalize_finding` tool.

## The 6 Disprove Questions

### 1. Is the sink actually reachable from the source?
- [ ] I have verified routing/call sites/control flow
- [ ] I have checked for framework routing or middleware that might block access
- [ ] I have evidence the code path can execute under stated attacker model

**If NO**: Downgrade to NEEDS_HUMAN_REVIEW or NOT_A_VULNERABILITY

---

### 2. Is the input truly attacker-controlled?
- [ ] I have identified the exact source of the input
- [ ] I have verified authentication/authorization gates
- [ ] Input is not from internal-only systems or trusted sources
- [ ] The stated attacker model can actually control this input

**If NO**: Downgrade to NOT_A_VULNERABILITY or HARDENING_OPPORTUNITY

---

### 3. Is the suspicious code actually executed?
- [ ] Code is not dead/test-only/dev-only/example code
- [ ] Code is not disabled by default configuration
- [ ] Code is reachable in common/default deployment configurations

**If NO**: Downgrade based on the reason:
- Dead/test-only/example code → NOT_A_VULNERABILITY
- Disabled by default but could be enabled → HARDENING_OPPORTUNITY

---

### 4. Does the framework provide automatic protection?
- [ ] I have checked for framework-level automatic protections:
  - ORM parameterization (SQL)
  - Autoescaping (XSS)
  - Safe path joining (path traversal)
  - Allowlisted APIs (SSRF)
  - Command argv arrays without shell (command injection)
- [ ] I have verified these protections are NOT present or are bypassed

**If YES (framework protects)**: Downgrade to NOT_A_VULNERABILITY

---

### 5. Is the sanitizer/validator actually effective?
- [ ] I have identified all validators/sanitizers on this path
- [ ] I have analyzed each one for effectiveness in THIS context
- [ ] I have analyzed their effectiveness (not just noted their presence) and determined they do not prevent exploitation in this context
- [ ] There is no safer interpretation of how the validation works

**If validator is effective**: Downgrade to NOT_A_VULNERABILITY

---

### 5.5 CRITICAL: Does the attack scenario ASSUME bypassing existing controls?

**This is the #1 source of false positives.** If the attack says:
- "if the attacker bypasses the length check..."
- "if validation is disabled..."
- "assuming sanitization can be evaded..."
- "if the bounds check is circumvented..."

Then the attack is SPECULATIVE because:
1. The control EXISTS in the code
2. You cannot ASSUME it can be bypassed
3. You must PROVE it can be bypassed, not assume

**EXAMPLE FALSE POSITIVE:**
```c
strncpy(buffer, input, BUFFER_SIZE - 1);  // LENGTH CHECK EXISTS
```
Finding says: "Buffer overflow if attacker provides input longer than buffer"
WRONG: The strncpy with size limit PREVENTS overflow. This is NOT a vulnerability.

**RULE:** If a security control exists in the code, you must either:
1. PROVE the control can be bypassed (show the bypass technique), OR
2. Mark the finding as SPECULATIVE or BY_DESIGN

You CANNOT mark as VALID_SECURITY_ISSUE if you're assuming bypass of an existing control.

**If attack assumes bypassing an existing control**: Downgrade to SPECULATIVE

---

### 6. Is there a safer interpretation?
- [ ] I have considered alternative interpretations of the code behavior
- [ ] I have checked for:
  - Command APIs using argv arrays (not shell)
  - JSON/YAML parsers (not pickle/eval)
  - URL builders with allowlists
  - Template engines with autoescaping
  - Contextually-correct encoders
- [ ] The dangerous interpretation is the only reasonable one

**If safer interpretation exists**: Re-analyze with safer interpretation

---

## How to Use This Checklist

1. **Before calling `finalize_finding`**: Work through all 6 questions
2. **For each question**: Explicitly check the boxes and provide evidence
3. **If ANY question suggests "not a vulnerability"**: Downgrade the classification
4. **Only if all 6 questions pass**: Proceed with VALIDATED_VULNERABILITY classification
5. **Document your answers**: The `finalize_finding` tool requires your answers to all 6 questions

## Critical Unknowns

If you cannot answer a question due to:
- Missing code/configuration
- Complex framework behavior you cannot determine statically
- Runtime-only behavior
- External system dependencies

Then classify as **NEEDS_HUMAN_REVIEW** and document the specific unknowns.

## Zero False Positive Contract

**Prefer FALSE NEGATIVES over FALSE POSITIVES**

- If in doubt, downgrade to NEEDS_HUMAN_REVIEW
- If you have critical unknowns, use NEEDS_HUMAN_REVIEW
- Reporting a false positive is worse than missing a real vulnerability
- When you cannot fully validate, do NOT claim VALIDATED_VULNERABILITY

---

*This checklist enforces the zero-FP protocol's disprove-first requirement.*
