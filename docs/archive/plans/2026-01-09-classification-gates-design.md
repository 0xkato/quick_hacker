# Vulnerability Classification Gates Design

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reduce false positives by adding mandatory classification gates to agent prompts that enforce threat-model-aware vulnerability labeling.

**Architecture:** Pre-finding classification gates embedded in all agent prompts. Agents must complete a deterministic checklist before labeling anything "Security issue." Classification is threat-model-aware - the same technical finding may be SECURITY_ISSUE or MISCONFIGURATION depending on project threat model.

**Tech Stack:** Python (backend), TypeScript (frontend), Pydantic schemas, prompt engineering

---

## Problem Statement

Current agents over-classify findings as security vulnerabilities when they are actually:
- **Misconfigurations** - Only exploitable when security is intentionally disabled
- **Hardening opportunities** - Defense-in-depth, no concrete exploit chain
- **Expected insecure modes** - Documented dev/test configurations

This creates noise and undermines trust in findings.

---

## Design Overview

### Classification Taxonomy

| Classification | Definition | Example |
|---------------|------------|---------|
| `security_issue` | Real vulnerability exploitable within threat model | SQL injection on public endpoint |
| `bug` | Code defect, not security-exploitable in context | Logic error in admin-only feature (threat model A) |
| `misconfiguration` | Only exploitable when security intentionally disabled | RCE when `REQUIRE_AUTH=false` |
| `hardening` | Defense-in-depth improvement, no concrete exploit | Missing security headers |

### Two-Dimensional Classification

- **Classification** (what type): security_issue / bug / misconfiguration / hardening
- **Severity** (how bad): CRITICAL / HIGH / MEDIUM / LOW / INFO

These are orthogonal. A MISCONFIGURATION can be HIGH severity. A SECURITY_ISSUE can be MEDIUM.

---

## Schema Changes

### New Enum

```python
class FindingClassification(str, Enum):
    SECURITY_ISSUE = "security_issue"
    BUG = "bug"
    MISCONFIGURATION = "misconfiguration"
    HARDENING = "hardening"
```

### New Finding Fields

```python
class Finding(BaseModel):
    # ... existing fields ...

    # Classification gate outputs (mandatory)
    classification: FindingClassification
    config_dependent: bool                  # Only exploitable when security flag disabled?
    config_flag: Optional[str]              # Which flag? e.g., "REQUIRE_AUTH"
    default_secure: Optional[bool]          # Is default config secure? (None = unknown)
    contradiction_present: bool             # Docs vs behavior mismatch?
    fix_type: Literal["code", "config", "docs", "warning"]
    classification_reasoning: str           # Why this classification? (defensible reasoning)
```

---

## Classification Gate Checklist

Agents must answer these questions in order before classifying:

### Gate 1: Configuration Dependency Check

```
1. Does this exploit work in the RECOMMENDED/DEFAULT configuration?
   - YES → Continue to Gate 2
   - NO → What flag must be disabled?
     - If flag is security-related (auth, TLS, sandbox) → Classification = MISCONFIGURATION
     - If flag is feature-related (debug mode, dev tools) → Continue to Gate 2

2. Is the "unsafe" mode explicitly documented/supported?
   - YES + no contradiction → MISCONFIGURATION (expected insecure mode)
   - YES + contradiction (docs say safe but isn't) → SECURITY_ISSUE
   - NO (undocumented unsafe behavior) → SECURITY_ISSUE
```

### Gate 2: Threat Model Alignment

```
3. Is this exploitable by the configured threat model actor?
   - Threat Model A (unauthenticated): Can internet attacker exploit?
   - Threat Model AB (+ auth user): Can authenticated user exploit?
   - Threat Model ABC (+ insider): Can privileged user exploit?

   If NO → Classification = MISCONFIGURATION or HARDENING
   If YES → Continue to Gate 3
```

### Gate 3: Exploit Chain Validity

```
4. Is there a defensible attack scenario?
   - Must explain: What credential/access is auto-available to attacker?
   - Must explain: How does attacker leverage this specific issue?
   - Must explain: What's the concrete impact?

   If reasoning is sound → SECURITY_ISSUE
   If speculative/requires unlikely conditions → HARDENING
```

---

## Threat Model Classification Matrix

| Finding Type | Model A (unauth) | Model AB (+ auth) | Model ABC (+ insider) |
|-------------|------------------|-------------------|----------------------|
| Unauth RCE | SECURITY_ISSUE | SECURITY_ISSUE | SECURITY_ISSUE |
| Auth bypass | SECURITY_ISSUE | SECURITY_ISSUE | SECURITY_ISSUE |
| Priv escalation | MISCONFIG* | SECURITY_ISSUE | SECURITY_ISSUE |
| Auth-user IDOR | MISCONFIG* | SECURITY_ISSUE | SECURITY_ISSUE |
| Admin-only vuln | MISCONFIG* | MISCONFIG* | SECURITY_ISSUE |
| Weak JWT secret | SECURITY_ISSUE | SECURITY_ISSUE | BUG |
| CORS * + cookies | SECURITY_ISSUE | SECURITY_ISSUE | HARDENING |
| Missing headers | HARDENING | HARDENING | HARDENING |
| Auth-disabled RCE | MISCONFIG | MISCONFIG | MISCONFIG |

*MISCONFIG = actor outside threat model scope; still reported but not as vulnerability

---

## Fix Recommendation Constraints

### SECURITY_ISSUE (within threat model)

```
fix_type: "code"
Allowed:
- Input validation/sanitization
- Authentication/authorization checks
- Secure defaults in code
- Removing dangerous functionality
- Cryptographic fixes
```

### MISCONFIGURATION (outside threat model)

```
fix_type: "config" | "warning" | "docs"
Allowed:
- Better defaults (auth on by default)
- Loud warnings when running insecure
- Auto-disable dangerous features in insecure mode
- Require explicit --i-know-what-im-doing flags
- Bind to localhost by default
- Documentation for secure deployment

NOT allowed:
- "Always require auth regardless of REQUIRE_AUTH flag"
- Removing documented configuration options
- Code changes that ignore user's explicit config choice
```

### HARDENING

```
fix_type: "docs" | "warning"
Allowed:
- Security headers recommendations
- Defense-in-depth suggestions
- Best practices documentation
- Optional stricter modes
```

### BUG

```
fix_type: "code"
- Standard bug fixes, no security-specific constraints
```

---

## Universal Classification Prompt

Injected into all agent system prompts:

```markdown
## CLASSIFICATION REQUIREMENTS (MANDATORY)

Before reporting ANY finding, you MUST complete this checklist:

### Step 1: Configuration Dependency
- Does this work in DEFAULT configuration? (yes/no)
- If NO: Which security flag must be disabled?
- Is that flag documented/supported? (yes/no)

### Step 2: Threat Model Check
Current threat model: {threat_model}
- Is this exploitable by an actor IN the threat model? (yes/no)
- If NO: This is MISCONFIGURATION, not SECURITY_ISSUE

### Step 3: Attack Scenario
Provide a DEFENSIBLE explanation:
- What access/credential does attacker have (per threat model)?
- How do they reach and trigger this issue?
- What is the concrete impact?

If you cannot provide sound reasoning, classify as HARDENING.

### Step 4: Classification Decision
Based on steps 1-3, assign:
- classification: security_issue | bug | misconfiguration | hardening
- config_dependent: true | false
- config_flag: "FLAG_NAME" or null
- default_secure: true | false | null
- contradiction_present: true | false
- fix_type: code | config | docs | warning
- classification_reasoning: "Because..."

### RULES
- You are NOT PERMITTED to label something SECURITY_ISSUE if it only works when security is intentionally disabled
- You are NOT PERMITTED to recommend removing documented config flags
- You MUST downgrade to MISCONFIGURATION if exploit requires config outside threat model
- "Attacker must know JWT secret" = NOT a vuln (secret compromise is separate threat)
- "Attacker must disable auth" = NOT a vuln (that's expected insecure mode)
```

---

## Finding Output Format

### SECURITY_ISSUE Example

```json
{
  "title": "SQL Injection in user search endpoint",
  "severity": "HIGH",
  "vulnerability_type": "sql_injection",
  "file_path": "api/routes/users.py",
  "line_start": 142,
  "code_snippet": "query = f\"SELECT * FROM users WHERE name = '{user_input}'\"",

  "classification": "security_issue",
  "config_dependent": false,
  "config_flag": null,
  "default_secure": false,
  "contradiction_present": false,
  "fix_type": "code",
  "classification_reasoning": "Exploitable by unauthenticated attacker (threat model A). User input flows directly to SQL query without sanitization. No auth required to reach /api/users/search endpoint. Impact: database read/write access.",

  "attack_scenario": "Attacker sends GET /api/users/search?q=' OR 1=1-- to dump all users",
  "recommended_fix": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE name = ?', (user_input,))",
  "confidence": 0.9
}
```

### MISCONFIGURATION Example

```json
{
  "title": "Unauthenticated access to admin endpoints",
  "severity": "HIGH",
  "vulnerability_type": "broken_access_control",
  "file_path": "api/routes/admin.py",
  "line_start": 28,

  "classification": "misconfiguration",
  "config_dependent": true,
  "config_flag": "REQUIRE_AUTH",
  "default_secure": true,
  "contradiction_present": false,
  "fix_type": "warning",
  "classification_reasoning": "Only exploitable when REQUIRE_AUTH=false, which is a documented dev-mode setting. Default is REQUIRE_AUTH=true. Threat model A assumes default secure config.",

  "attack_scenario": "When auth disabled, attacker can access /admin/* endpoints",
  "recommended_fix": "Add startup warning: 'REQUIRE_AUTH=false detected. Do not expose to untrusted networks.'",
  "confidence": 0.95
}
```

---

## Implementation Files

| File | Change |
|------|--------|
| `backend/models/schemas.py` | Add `FindingClassification` enum, add 6 new fields to `Finding` and `FindingCreate` |
| `backend/prompts/classification_gate.py` | NEW: Universal classification prompt template |
| `backend/prompts/scanner_prompt.py` | Inject classification gate + threat model context |
| `backend/prompts/analyzer_prompt.py` | Inject classification gate + threat model context |
| `backend/agents/base_agent.py` | Update `_parse_structured_findings` to require new fields |
| `backend/agents/quick_audit_agent.py` | Add classification fields to pattern-based findings |
| `backend/agents/react_agent.py` | Inject classification prompt into system message |
| `backend/agents/deep_audit_agent.py` | Inject classification prompt into system message |
| `backend/agents/ultrathink_agent.py` | Inject classification prompt into system message |
| `frontend/types/index.ts` | Add new Finding fields to TypeScript interface |
| `frontend/components/FindingsPanel/` | Display classification badge alongside severity |

---

## Success Criteria

1. **Zero "auth disabled = vuln" false positives** - Findings requiring disabled auth are MISCONFIGURATION
2. **Threat model consistency** - Same finding classified differently based on project threat model
3. **No invented fixes** - Agents never recommend overriding documented config flags
4. **Defensible reasoning** - Every finding has clear classification_reasoning
5. **Backward compatible** - Existing findings still display (with null/default classification fields)

---

*Generated: 2026-01-09*
