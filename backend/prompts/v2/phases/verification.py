"""Phase 4: Verification Pipeline - Multi-gate validation.

Each finding must pass ALL gates to be confirmed.
Any gate can REJECT with reason.
"""

from typing import Dict, Any


class EvidenceVerificationPrompt:
    """Gate 1: Try to disprove the evidence."""

    @staticmethod
    def get_prompt() -> str:
        return """
<evidence_verification>
GATE 1: EVIDENCE VERIFICATION

Your job is to DISPROVE this finding. Act as a skeptical reviewer.

CHECK:
1. SOURCE VERIFICATION
   - Is the source actually attacker-controllable?
   - Could it be sanitized before reaching this point?
   - Is there auth that limits access?

2. PATH VERIFICATION
   - Does data actually flow along claimed path?
   - Are there transforms/sanitizations along the way?
   - Could exceptions interrupt the flow?

3. SINK VERIFICATION
   - Does the sink do what's claimed?
   - Are there framework protections?
   - Is sink reachable with malicious input?

OUTPUT:
{
  "gate": "evidence_verification",
  "verdict": "PASS" | "FAIL",
  "confidence": 0.0-1.0,
  "concerns": ["list of doubts"],
  "counter_evidence": "what argues against this being real"
}

BE HARSH. Better to reject real finding than accept false one.
</evidence_verification>
"""


class DevilsAdvocatePrompt:
    """Gate 2: Argue against the finding."""

    @staticmethod
    def get_prompt() -> str:
        return """
<devils_advocate>
GATE 2: DEVIL'S ADVOCATE

Pretend you're the developer who wrote this code and believes it's secure.
Find every reason this finding might be WRONG.

ARGUE AGAINST:
1. ALTERNATIVE EXPLANATION
   Why might this NOT be vulnerable?

2. MISSING CONTEXT
   What code/config might exist that makes this safe?

3. FRAMEWORK PROTECTION
   How might the framework handle this securely?

4. ATTACK BARRIERS
   What would prevent exploitation?

5. FALSE POSITIVE INDICATORS
   What suggests this might be a FP?

OUTPUT:
{
  "gate": "devils_advocate",
  "verdict": "PASS" | "FAIL",
  "strongest_counter_argument": "...",
  "remaining_confidence": 0.0-1.0,
  "should_proceed": true/false
}

Only PASS if you cannot find compelling counter-arguments.
</devils_advocate>
"""


class ProofOfConceptPrompt:
    """Gate 3: Generate concrete proof."""

    @staticmethod
    def get_prompt() -> str:
        return """
<proof_of_concept>
GATE 3: PROOF OF CONCEPT

Generate a CONCRETE proof that this vulnerability works.

REQUIRED:
1. EXACT PAYLOAD
   The precise input an attacker would send.
   Not "malicious input" - the ACTUAL string.

2. ENTRY POINT
   Exactly how payload reaches application.
   HTTP request? Function call? File input?

3. EXECUTION TRACE
   Step by step what happens:
   - Line X: Payload enters as Y
   - Line X: Y passed to Z
   - Line X: Dangerous operation executes

4. OBSERVABLE RESULT
   What attacker sees/achieves.

5. VERIFICATION METHOD
   How to test this works (curl command, test case, etc.)

OUTPUT:
{
  "gate": "proof_of_concept",
  "can_prove": true/false,
  "payload": "exact input",
  "entry_point": "how it enters",
  "execution_trace": ["step1", "step2"],
  "expected_result": "what happens",
  "verification": "how to test"
}

If you CANNOT provide concrete proof, verdict is FAIL.
</proof_of_concept>
"""


class FinalGatePrompt:
    """Gate 4: Final decision - stake your reputation."""

    @staticmethod
    def get_prompt() -> str:
        return """
<final_gate>
GATE 4: FINAL DECISION

This finding has passed:
- Evidence verification
- Devil's advocate
- Proof of concept

ONE LAST CHECK:

Would you stake your professional reputation on this finding?

Consider:
- If wrong, credibility damaged
- Client will investigate thoroughly
- Other researchers will review
- False positives waste time and money

OUTPUT:
{
  "gate": "final_gate",
  "stake_reputation": true/false,
  "confidence_percentage": 85-100,
  "strongest_evidence": "single best proof this is real",
  "remaining_doubt": "any uncertainty",
  "final_verdict": "CONFIRMED" | "REJECT",
  "reasoning": "one sentence"
}

RULES:
- confidence < 85% → REJECT
- stake_reputation = false → REJECT
- Any significant doubt → REJECT

Only CONFIRM if genuinely certain.
</final_gate>
"""


def build_verification_pipeline(finding: Dict[str, Any]) -> str:
    """Build complete verification pipeline prompt.

    Args:
        finding: The validated finding to verify

    Returns:
        Complete verification pipeline prompt
    """
    parts = [
        "=== VERIFICATION PIPELINE ===",
        f"Finding to verify: {finding.get('title', 'Unknown')}",
        f"Type: {finding.get('cwe', 'Unknown')}",
        "",
        "This finding must pass ALL 4 gates to be CONFIRMED.",
        "Any gate can REJECT the finding.",
        "",
        EvidenceVerificationPrompt.get_prompt(),
        DevilsAdvocatePrompt.get_prompt(),
        ProofOfConceptPrompt.get_prompt(),
        FinalGatePrompt.get_prompt(),
    ]

    return "\n\n".join(parts)
