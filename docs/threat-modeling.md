# Threat Modeling Integration

## Overview

Quick Hacker's LLM validation system uses threat modeling profiles to guide validation decisions. Threat models define attacker capabilities, excluded attack types, required impacts, and excluded contexts to ensure findings align with program scope.

## Threat Model Profile Structure

A threat model profile is a dictionary with four main components:

```python
threat_model_profile = {
    "attacker_capabilities": [
        "remote_unauthenticated",
        "remote_authenticated",
        "local_unprivileged",
        "local_privileged"
    ],
    "excluded_attack_types": [
        "social_engineering_only",
        "local_privilege_escalation",
        "denial_of_service"
    ],
    "required_impact": [
        "code_execution",
        "data_exfiltration",
        "authentication_bypass"
    ],
    "excluded_contexts": [
        "test_code",
        "example_code",
        "documentation"
    ]
}
```

## Components

### 1. Attacker Capabilities

Defines what level of access an attacker has:

**Remote Unauthenticated:**
- Attacker has no credentials
- Can only access public-facing services
- Common for web applications, APIs

**Remote Authenticated:**
- Attacker has valid low-privilege credentials
- Can access authenticated endpoints
- Common for multi-tenant applications

**Local Unprivileged:**
- Attacker has local user account
- No root/admin privileges
- Common for desktop applications

**Local Privileged:**
- Attacker has root/admin access
- Can modify system files
- Rarely in scope for security programs

### 2. Excluded Attack Types

Attack categories that are out of scope:

**Social Engineering Only:**
- Requires tricking users
- No technical vulnerability
- Examples: phishing, pretexting

**Local Privilege Escalation:**
- Requires local access first
- Escalates from user to root
- Often out of scope for web apps

**Denial of Service:**
- Service availability attacks
- Resource exhaustion
- Often excluded from bug bounties

**Physical Access:**
- Requires physical device access
- Examples: evil maid attacks
- Usually out of scope

### 3. Required Impact

Minimum impact required for findings:

**Code Execution:**
- Attacker can run arbitrary code
- Examples: RCE, command injection

**Data Exfiltration:**
- Attacker can steal sensitive data
- Examples: SQL injection, IDOR

**Authentication Bypass:**
- Attacker can bypass login
- Examples: auth flaws, session hijacking

**Authorization Bypass:**
- Attacker can access unauthorized resources
- Examples: IDOR, path traversal

**Data Modification:**
- Attacker can modify sensitive data
- Examples: XSS, CSRF

### 4. Excluded Contexts

Code contexts that are out of scope:

**Test Code:**
- Unit tests, integration tests
- Examples: `*_test.py`, `test_*.py`

**Example Code:**
- Demos, tutorials, examples
- Examples: `examples/`, `demo/`

**Documentation:**
- Markdown, HTML docs
- Examples: `docs/`, `*.md`

**Build Scripts:**
- CI/CD, build automation
- Examples: `Makefile`, `.github/workflows/`

## Integration with Validation

The LLM validator uses threat model profiles to:

### 1. Assess Attacker Capabilities
Reject findings that require capabilities beyond the threat model:

**Example:**
- Threat model: `["remote_unauthenticated"]`
- Finding: Requires local file access
- **Decision**: INVALID (requires local access)

### 2. Filter Attack Types
Skip findings that match excluded types:

**Example:**
- Excluded: `["social_engineering_only"]`
- Finding: Phishing via link (no technical sink)
- **Decision**: INVALID (social engineering only)

### 3. Verify Impact
Ensure findings have required impact:

**Example:**
- Required: `["code_execution", "data_exfiltration"]`
- Finding: Information disclosure (low impact)
- **Decision**: INVALID (insufficient impact)

### 4. Context Filtering
Ignore findings in excluded contexts:

**Example:**
- Excluded: `["test_code", "example_code"]`
- Finding: Command injection in `tests/test_api.py`
- **Decision**: INVALID (test code)

## Example Threat Models

### GitHub VRP

GitHub's Vulnerability Rewards Program has strict requirements:

```python
github_threat_model = {
    "attacker_capabilities": [
        "remote_unauthenticated"
    ],
    "excluded_attack_types": [
        "social_engineering_only",
        "denial_of_service",
        "local_privilege_escalation",
        "physical_access"
    ],
    "required_impact": [
        "code_execution",
        "data_exfiltration",
        "authentication_bypass",
        "authorization_bypass"
    ],
    "excluded_contexts": [
        "test_code",
        "example_code",
        "documentation",
        "archived_repositories"
    ]
}
```

**Rationale:**
- Only remote unauthenticated attacks (no local access)
- High-impact issues only (RCE, data theft, auth bypass)
- Excludes test code and documentation
- No social engineering or DoS

### HackerOne (Permissive Program)

More permissive program accepting a wider range of issues:

```python
hackerone_threat_model = {
    "attacker_capabilities": [
        "remote_unauthenticated",
        "remote_authenticated"
    ],
    "excluded_attack_types": [
        "social_engineering_only"  # Only exclude pure SE
    ],
    "required_impact": [
        "code_execution",
        "data_exfiltration",
        "authentication_bypass",
        "authorization_bypass",
        "data_modification"
    ],
    "excluded_contexts": [
        "test_code",
        "example_code"
    ]
}
```

**Rationale:**
- Accepts remote authenticated attacks
- Broader impact categories (includes data modification)
- Fewer exclusions (DoS may be in scope)
- Still excludes test code

### Internal Security Audit

Internal audit with comprehensive coverage:

```python
internal_audit_threat_model = {
    "attacker_capabilities": [
        "remote_unauthenticated",
        "remote_authenticated",
        "local_unprivileged"
    ],
    "excluded_attack_types": [],  # Accept all attack types
    "required_impact": [],  # Any impact level
    "excluded_contexts": [
        "archived_repositories"  # Only exclude archived code
    ]
}
```

**Rationale:**
- Comprehensive scope (all capabilities)
- No attack type exclusions (even SE, DoS)
- No impact requirements (all issues)
- Minimal context exclusions

### Research Disclosure

Security research with broad scope:

```python
research_threat_model = {
    "attacker_capabilities": [
        "remote_unauthenticated",
        "remote_authenticated"
    ],
    "excluded_attack_types": [
        "social_engineering_only"
    ],
    "required_impact": [
        "code_execution",
        "data_exfiltration",
        "authentication_bypass",
        "authorization_bypass",
        "data_modification",
        "security_control_bypass"
    ],
    "excluded_contexts": [
        "test_code",
        "example_code",
        "archived_repositories"
    ]
}
```

**Rationale:**
- Remote attacks (authenticated and unauthenticated)
- Broad impact categories (includes security control bypass)
- Excludes test/example code
- Good balance for responsible disclosure

## Configuring Threat Models

### Protocol-Level Configuration

Threat models are typically configured at the protocol level:

```python
from models.schemas import ProtocolPolicy

protocol = ProtocolPolicy(
    id="custom-program",
    display_name="Custom Bug Bounty Program",

    # ... other protocol settings

    # Threat model is passed to validator at runtime
)
```

### Runtime Configuration

Threat models are passed to the validator during triage:

```python
from services.validation.llm_validator import LLMFindingValidator

validator = LLMFindingValidator(
    anthropic_api_key=api_key,
    repo_root="/path/to/repo",
    model="claude-sonnet-4-20250514"
)

result = await validator.validate(
    finding=finding,
    evidence=evidence,
    classification=classification,
    threat_model_profile=github_threat_model,  # Pass threat model here
    criticism_level="high"
)
```

### Environment-Specific Models

Create threat models for different environments:

```python
# Production environment (strict)
production_threat_model = {
    "attacker_capabilities": ["remote_unauthenticated"],
    "excluded_attack_types": ["denial_of_service", "social_engineering_only"],
    "required_impact": ["code_execution", "data_exfiltration"],
    "excluded_contexts": ["test_code", "example_code", "documentation"]
}

# Staging environment (moderate)
staging_threat_model = {
    "attacker_capabilities": ["remote_unauthenticated", "remote_authenticated"],
    "excluded_attack_types": ["social_engineering_only"],
    "required_impact": ["code_execution", "data_exfiltration", "data_modification"],
    "excluded_contexts": ["test_code", "example_code"]
}

# Development environment (permissive)
development_threat_model = {
    "attacker_capabilities": ["remote_unauthenticated", "remote_authenticated", "local_unprivileged"],
    "excluded_attack_types": [],
    "required_impact": [],
    "excluded_contexts": ["archived_repositories"]
}
```

## Best Practices

### 1. Align with Program Scope
- Review bug bounty program rules
- Match threat model to program scope
- Update when program scope changes

### 2. Be Specific About Capabilities
- Clearly define what attacker can do
- Don't assume capabilities not in list
- Document rationale for capabilities

### 3. Document Exclusions
- Explain why attack types are excluded
- Reference program policies
- Keep exclusions list current

### 4. Balance Coverage and Noise
- Too permissive → false positives
- Too restrictive → false negatives
- Find right balance for program

### 5. Review Regularly
- Program scope changes over time
- New attack types emerge
- Update threat models accordingly

### 6. Use Context Appropriately
- Test code is usually out of scope
- But test infrastructure may be in scope
- Consider carefully what to exclude

### 7. Combine with Validation Reasoning
- Threat model filters coarse-grained
- LLM validation is fine-grained
- Use both together for best results

## Impact on Validation Decision

The threat model profile influences the LLM validator's prompt:

### High-Level Guidance
The validator receives instructions like:
- "Only accept findings exploitable by remote unauthenticated attacker"
- "Reject findings that require social engineering"
- "Findings must demonstrate code execution or data exfiltration"

### Specific Investigation Tasks
The validator is instructed to check:
- Is this reachable by remote attacker?
- Does this require user cooperation?
- What is the actual impact?
- Is this in test code or production code?

### Decision Criteria
The validator applies criteria based on threat model:
- **VALID**: Finding matches threat model constraints
- **INVALID**: Finding violates threat model constraints

## Validation Examples with Threat Models

### Example 1: Remote Unauthenticated Requirement

**Threat Model:**
```python
{"attacker_capabilities": ["remote_unauthenticated"]}
```

**Finding:** SQL injection in admin panel (requires authentication)

**LLM Investigation:**
1. Confirms SQL injection is present
2. Checks route requires `@login_required` decorator
3. Verifies attacker needs valid credentials

**Decision:**
```
DECISION: INVALID

CATEGORY: requires_authentication

REASONING:
- SQL injection is technically present at admin/users.py:45
- However, route requires authentication via @login_required decorator
- Threat model specifies remote_unauthenticated attacker only
- Finding violates threat model constraints
```

### Example 2: Social Engineering Exclusion

**Threat Model:**
```python
{"excluded_attack_types": ["social_engineering_only"]}
```

**Finding:** XSS via user-submitted content (requires admin approval)

**LLM Investigation:**
1. Confirms XSS payload is unescaped
2. Checks content submission flow
3. Finds admin must approve content before rendering

**Decision:**
```
DECISION: INVALID

CATEGORY: requires_user_interaction

REASONING:
- XSS payload is present and unescaped
- But content requires admin approval before rendering
- This is social engineering (convincing admin to approve)
- Threat model excludes social engineering only attacks
```

### Example 3: Impact Requirement

**Threat Model:**
```python
{"required_impact": ["code_execution", "data_exfiltration"]}
```

**Finding:** Information disclosure (version number in header)

**LLM Investigation:**
1. Confirms version number is exposed
2. Checks if this enables further attacks
3. Determines impact is information disclosure only

**Decision:**
```
DECISION: INVALID

CATEGORY: insufficient_impact

REASONING:
- Version number is exposed in X-Powered-By header
- This is information disclosure, not code execution or data theft
- No direct path to code execution from version info
- Finding does not meet required impact threshold
```

## Related Documentation

- [LLM Validation Configuration Guide](llm-validation-guide.md) - Detailed validation configuration
- [Protocol Policies Guide](protocol-policies.md) - Protocol configuration
- [System Specification](SYSTEM-SPECIFICATION.md) - Architecture details
