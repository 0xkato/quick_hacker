"""
Category-aware blocking gaps for vulnerability triage.

Determines which checklist items MUST be PROVEN to upgrade from SPECULATIVE to VALID.
Aligned with StrictClassifier Rule 4 and Rule 3b exception.
"""

from models.schemas import ProofChecklist, ChecklistStatus


def get_blocking_gaps_for_category(category: str, checklist: ProofChecklist) -> list[str]:
    """
    Returns list of checklist fields that MUST be PROVEN to upgrade from SPECULATIVE.
    Aligned with StrictClassifier Rule 4 and Rule 3b exception.

    Args:
        category: Vulnerability category (e.g., "SQL_INJECTION", "CODE_INJECTION")
        checklist: Current proof checklist with tri-state values

    Returns:
        List of checklist field names that are blocking (currently UNKNOWN but required)
    """
    # Rule 3b: Exec/Eval exception
    if category in ["CODE_INJECTION", "COMMAND_INJECTION"]:
        if checklist.security_control_bypassed and checklist.security_control_bypassed.status == ChecklistStatus.PROVEN:
            # boundary_crossed can be replaced by security_control_bypassed
            required_fields = [
                "source_controlled_input",
                "sink_present",
                "dataflow_evidenced",
                "reachable",
                "not_only_misconfig",
                "security_control_bypassed"  # Replaces boundary_crossed
            ]
        else:
            # Standard proof chain
            required_fields = [
                "source_controlled_input",
                "sink_present",
                "dataflow_evidenced",
                "reachable",
                "boundary_crossed",
                "not_only_misconfig"
            ]
    # Hardcoded secrets: dataflow not applicable
    elif category == "SECRETS":
        required_fields = [
            "sink_present",          # Secret is present in code
            "not_only_misconfig"     # Not just a config issue
        ]
    # XSS: Escaping evidence is critical
    elif category == "XSS":
        required_fields = [
            "source_controlled_input",
            "sink_present",
            "dataflow_evidenced",
            "reachable",
            "boundary_crossed",
            "not_only_misconfig",
            "security_control_bypassed"  # Must prove output is NOT escaped
        ]
    # Default: All 6 items required
    else:
        required_fields = [
            "source_controlled_input",
            "sink_present",
            "dataflow_evidenced",
            "reachable",
            "boundary_crossed",
            "not_only_misconfig"
        ]

    # Return only the fields that are currently blocking (UNKNOWN but required)
    blocking = []
    for field in required_fields:
        item = getattr(checklist, field)
        if item and item.status == ChecklistStatus.UNKNOWN:
            blocking.append(field)

    return blocking
