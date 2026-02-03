# Stage: Triage (DISPROVE-FIRST)

**Goal:** Final classification using DISPROVE-FIRST methodology

**CRITICAL MINDSET:** Try to REJECT before accepting. Your job is to find reasons it's NOT a vulnerability.

**No Tools Used** - This stage uses accumulated evidence only

**Output Required:**
- Final disposition: VALID_SECURITY_ISSUE | BUG | HARDENING | MISCONFIGURATION | BY_DESIGN | SPECULATIVE
- Complete proof checklist with all items marked PROVEN_TRUE/PROVEN_FALSE/UNKNOWN
- Confidence score (0.0-1.0)
- Reasoning (2-4 bullet points)

## DISPROVE-FIRST CHECKLIST

Before accepting ANY finding, you MUST prove these disprove questions are FALSE:

### 1. Does validation/sanitization exist?
- Check for input validation, bounds checks, length limits
- Check for sanitization (escape, encode, allowlist)
- **IF EXISTS**: Mark `dataflow_evidenced = PROVEN_FALSE` → BY_DESIGN

### 2. Does the attack scenario assume bypassing controls?
- If attack says "if attacker bypasses X" where X exists → SPECULATIVE
- If attack says "assuming validation is disabled" → SPECULATIVE
- The control MUST be proven absent or proven bypassed

### 3. Is this test/dev/example code?
- Paths: test/, tests/, __tests__/, examples/, fixtures/, mocks/
- Names: *_test.*, test_*.*, *.spec.*, *.example.*
- **IF YES**: → BY_DESIGN or HARDENING

### 4. Does the framework provide protection?
- Django ORM → parameterized SQL
- React/Angular/Vue → auto-escaping
- subprocess shell=False → no injection
- strncpy/snprintf → bounds checking
- **IF PROTECTED**: → BY_DESIGN

### 5. Is the input actually attacker-controlled?
- Internal-only sources are not attacker-controlled
- Hardcoded values are not attacker-controlled
- **IF NOT CONTROLLED**: → NOT vulnerable

## FALSE POSITIVE PATTERNS (REJECT IMMEDIATELY)

### Memory Safety False Positives:
```c
// Has bounds check - NOT a buffer overflow
strncpy(buf, input, sizeof(buf) - 1);
buf[sizeof(buf) - 1] = '\0';

// Has length limit - NOT exploitable
if (strlen(input) > MAX_LEN) return ERROR;
```
If the finding says "buffer overflow" but bounds checking exists, REJECT as SPECULATIVE.

### SQL Injection False Positives:
```python
# Django ORM - parameterized
User.objects.filter(id=user_id)

# Parameterized query - safe
cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])
```
If ORM or parameterized queries are used, REJECT as BY_DESIGN.

### Command Injection False Positives:
```python
# shell=False with list args - safe
subprocess.run(["ls", "-la", user_path], shell=False)

# Allowlist check - safe
if cmd not in ALLOWED_COMMANDS:
    raise ValueError("Invalid command")
```
If shell=False or allowlist exists, REJECT.

## DISPOSITION DECISION TREE

1. **Is control/protection present?**
   - YES: Is it proven bypassed? NO → BY_DESIGN or SPECULATIVE
   - NO: Continue to step 2

2. **Is code in test/dev/example path?**
   - YES → BY_DESIGN or HARDENING
   - NO: Continue to step 3

3. **Is attack scenario speculative?**
   - Uses "if bypasses...", "assuming...", "could potentially..." → SPECULATIVE
   - Has concrete exploit path → Continue to step 4

4. **Are ALL 6 proof items PROVEN_TRUE?**
   - YES → VALID_SECURITY_ISSUE
   - source/sink/dataflow TRUE but others UNKNOWN → BUG
   - Any item PROVEN_FALSE → BY_DESIGN or appropriate
   - Multiple UNKNOWN → SPECULATIVE

## STRICT RULES

- **Rule 1:** not_only_misconfig == PROVEN_FALSE → MISCONFIGURATION
- **Rule 2:** For exec/eval, security_control_bypassed can replace boundary_crossed
- **Rule 3:** ALL items PROVEN_TRUE → VALID_SECURITY_ISSUE
- **Rule 4:** Control exists + attack assumes bypass → SPECULATIVE
- **Rule 5:** When in doubt, REJECT. Zero false positives > missing real vulns.
