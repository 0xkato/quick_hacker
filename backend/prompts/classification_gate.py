"""Universal classification gate prompt template for agent prompts.

This module provides the classification gate that must be applied to all
findings before they are reported. It ensures findings are correctly
categorized and reduces false positives by enforcing strict classification rules.
"""

CLASSIFICATION_RULES = """## Classification Rules (Non-Negotiable)

1. **NOT PERMITTED** to label as SECURITY_ISSUE if the vulnerability only works when security features are disabled or non-default configuration is required.

2. **NOT PERMITTED** to recommend removing documented configuration flags as a "fix". Config flags exist for legitimate operational reasons.

3. **MUST** downgrade to MISCONFIGURATION if the attack scenario falls outside the current threat model scope.

4. **MUST** mark config_dependent=true and specify the exact config_flag if a finding requires non-default settings.

5. **MUST** set contradiction_present=true if recommending removal of documented/intentional features.

6. Default-secure applications should not have security issues escalated for non-default configurations.
"""

CLASSIFICATION_GATE_TEMPLATE = """## Classification Gate

Before finalizing any finding, you MUST complete this classification gate.

{rules}

### Step 1: Configuration Dependency Check

Analyze whether this finding depends on specific configuration:
- Does the vulnerability require non-default settings to be exploitable?
- Is there a configuration flag that enables/disables the vulnerable behavior?
- Does the default configuration protect against this issue?

If YES to any above, the finding is configuration-dependent.

### Step 2: Threat Model Check

Current Threat Model: **{threat_model}**

Threat Model Definitions:
- **A**: Internet attacker (unauthenticated, publicly reachable surfaces only)
- **AB**: Authenticated attacker (A + authenticated-only surfaces)
- **ABC**: Insider/internal attacker (A + B + internal-only surfaces, admin panels)

Verify the attack scenario falls within the current threat model scope:
- For threat model A: Only unauthenticated, public-facing attack vectors
- For threat model AB: Includes authenticated user attack vectors
- For threat model ABC: Includes insider/admin attack vectors

If the attack requires privileges beyond the threat model, downgrade to MISCONFIGURATION or HARDENING.

### Step 3: Attack Scenario Requirements

A valid SECURITY_ISSUE requires ALL of:
1. Exploitable under default/common configuration
2. Attack vector within the defined threat model
3. Concrete impact (not theoretical)
4. No contradiction with documented/intentional features

If any requirement is not met, classify as BUG, MISCONFIGURATION, or HARDENING instead.

### Step 4: Classification Decision

Provide the following fields for each finding:

- **classification**: One of: security_issue, bug, misconfiguration, hardening
  - SECURITY_ISSUE: Real vulnerability exploitable under defaults within threat model
  - BUG: Code defect without security implications
  - MISCONFIGURATION: Security issue only with non-default/insecure config
  - HARDENING: Recommended improvement, not a vulnerability

- **config_dependent**: boolean - Does this require specific configuration?
- **config_flag**: string or null - The specific flag/setting if config_dependent
- **default_secure**: boolean or null - Is the default configuration secure?
- **contradiction_present**: boolean - Does the fix contradict documented features?
- **fix_type**: One of: code, config, docs, warning
  - code: Requires code changes
  - config: Requires configuration changes
  - docs: Requires documentation updates
  - warning: Advisory only, no fix needed
- **classification_reasoning**: string - Explanation for the classification decision
"""


VALID_THREAT_MODELS = {"A", "AB", "ABC"}


def get_classification_gate_prompt(threat_model: str) -> str:
    """Format the classification gate template with the given threat model.

    Args:
        threat_model: The threat model to use (A, AB, or ABC)

    Returns:
        The formatted classification gate prompt string

    Raises:
        ValueError: If threat_model is not one of "A", "AB", or "ABC"
    """
    if threat_model not in VALID_THREAT_MODELS:
        raise ValueError(
            f"Invalid threat_model '{threat_model}'. "
            f"Must be one of: {', '.join(sorted(VALID_THREAT_MODELS))}"
        )
    return CLASSIFICATION_GATE_TEMPLATE.format(
        threat_model=threat_model,
        rules=CLASSIFICATION_RULES,
    )
