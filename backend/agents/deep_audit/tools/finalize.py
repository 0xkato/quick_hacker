"""Finalization tools for Overseer."""

import json
from datetime import datetime
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from agents.deep_audit.state import CampaignState
    from agents.deep_audit.filesystem import MemoriesFilesystem


# Will be set by Overseer
_filesystem: "MemoriesFilesystem" = None
_campaign_state: "CampaignState" = None


def set_filesystem(filesystem: "MemoriesFilesystem"):
    """Set the filesystem instance."""
    global _filesystem
    _filesystem = filesystem


def set_campaign_state(state: "CampaignState"):
    """Set the campaign state instance."""
    global _campaign_state
    _campaign_state = state


def update_campaign_state(state_update_json: str) -> str:
    """Update the campaign state with new information.

    Args:
        state_update_json: JSON string with fields to update:
            {
                "repo_profile": {...},  // Optional
                "hypotheses": [...],     // Optional - will merge
                "confirmed_findings": [...], // Optional - will append
                "dismissed": [...],      // Optional - will append
                "current_wave": 2,       // Optional
                "scopes": {...}          // Optional - will merge
            }

    Returns:
        JSON with success status and updated state summary
    """
    if _filesystem is None or _campaign_state is None:
        return json.dumps({"error": "State or filesystem not initialized"})

    try:
        updates = json.loads(state_update_json)

        # Apply updates
        if "repo_profile" in updates:
            _campaign_state.repo_profile = updates["repo_profile"]

        if "current_wave" in updates:
            _campaign_state.current_wave = updates["current_wave"]

        if "threat_model_path" in updates:
            _campaign_state.threat_model_path = updates["threat_model_path"]

        if "authz_map_path" in updates:
            _campaign_state.authz_map_path = updates["authz_map_path"]

        # Merge hypotheses (update existing or add new)
        if "hypotheses" in updates:
            from agents.deep_audit.state import Hypothesis
            for h_data in updates["hypotheses"]:
                # Check if hypothesis exists
                existing = next((h for h in _campaign_state.hypotheses if h.id == h_data.get("id")), None)
                if existing:
                    # Update existing
                    for key, value in h_data.items():
                        if hasattr(existing, key):
                            setattr(existing, key, value)
                    existing.updated_at = datetime.utcnow()
                else:
                    # Add new
                    _campaign_state.hypotheses.append(Hypothesis(**h_data))

        # Append confirmed findings
        if "confirmed_findings" in updates:
            _campaign_state.confirmed_findings.extend(updates["confirmed_findings"])

        # Append dismissed
        if "dismissed" in updates:
            from agents.deep_audit.state import Dismissal
            for d_data in updates["dismissed"]:
                _campaign_state.dismissed.append(Dismissal(**d_data))

        # Merge scopes
        if "scopes" in updates:
            from agents.deep_audit.state import ScopeStatus
            for scope_id, scope_data in updates["scopes"].items():
                if scope_id in _campaign_state.scopes:
                    # Update existing
                    for key, value in scope_data.items():
                        if hasattr(_campaign_state.scopes[scope_id], key):
                            setattr(_campaign_state.scopes[scope_id], key, value)
                else:
                    # Add new
                    _campaign_state.scopes[scope_id] = ScopeStatus(**scope_data)

        # Merge entrypoints
        if "entrypoints" in updates:
            from agents.deep_audit.state import Entrypoint
            existing_ids = {e.id for e in _campaign_state.entrypoints}
            for e_data in updates["entrypoints"]:
                if e_data.get("id") not in existing_ids:
                    _campaign_state.entrypoints.append(Entrypoint(**e_data))

        # Save to filesystem
        state_dict = _campaign_state.model_dump()
        _filesystem.save_campaign_state(state_dict)

        # Return summary
        return json.dumps({
            "success": True,
            "summary": {
                "current_wave": _campaign_state.current_wave,
                "hypotheses_count": len(_campaign_state.hypotheses),
                "confirmed_findings_count": len(_campaign_state.confirmed_findings),
                "dismissed_count": len(_campaign_state.dismissed),
                "scopes_count": len(_campaign_state.scopes),
                "entrypoints_count": len(_campaign_state.entrypoints),
                "time_remaining_seconds": _campaign_state.time_remaining(),
            }
        }, indent=2)

    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid JSON: {e}"})
    except Exception as e:
        return json.dumps({"error": str(e)})


def finalize_report(final_notes: str = "") -> str:
    """Generate the final campaign report.

    Called when time budget is exhausted or campaign is complete.
    Produces /memories/overseer/final_report.md

    Args:
        final_notes: Additional notes to include in report

    Returns:
        JSON with report path and summary
    """
    if _filesystem is None or _campaign_state is None:
        return json.dumps({"error": "State or filesystem not initialized"})

    try:
        # Build final report
        report_lines = [
            "# Security Audit Final Report",
            "",
            f"**Project:** {_campaign_state.project_id}",
            f"**Scan Tier:** {_campaign_state.scan_tier}",
            f"**Started:** {_campaign_state.started_at.isoformat()}",
            f"**Completed:** {datetime.utcnow().isoformat()}",
            f"**Waves Completed:** {_campaign_state.current_wave}",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            f"- **Confirmed Findings:** {len(_campaign_state.confirmed_findings)}",
            f"- **Dismissed Signals:** {len(_campaign_state.dismissed)}",
            f"- **Unresolved Hypotheses:** {len(_campaign_state.get_pending_hypotheses())}",
            f"- **Scopes Analyzed:** {len(_campaign_state.scopes)}",
            f"- **Entrypoints Found:** {len(_campaign_state.entrypoints)}",
            "",
        ]

        # Confirmed findings section
        if _campaign_state.confirmed_findings:
            report_lines.extend([
                "## Confirmed Findings",
                "",
            ])
            for i, finding in enumerate(_campaign_state.confirmed_findings, 1):
                report_lines.extend([
                    f"### {i}. {finding.get('title', 'Untitled')}",
                    "",
                    f"**Severity:** {finding.get('severity', 'Unknown')}",
                    f"**Location:** {finding.get('location', 'Unknown')}",
                    f"**Type:** {finding.get('vulnerability_type', 'Unknown')}",
                    "",
                    finding.get('description', 'No description'),
                    "",
                ])
        else:
            report_lines.extend([
                "## Confirmed Findings",
                "",
                "No confirmed vulnerabilities found.",
                "",
            ])

        # Unresolved hypotheses section
        pending = _campaign_state.get_pending_hypotheses()
        if pending:
            report_lines.extend([
                "## Unresolved Hypotheses",
                "",
                "The following signals were not fully investigated due to time constraints:",
                "",
            ])
            for h in sorted(pending, key=lambda x: x.severity, reverse=True):
                report_lines.append(
                    f"- **[{h.severity}]** {h.signal_type} at {h.location} "
                    f"(confidence: {h.confidence}, status: {h.status})"
                )
            report_lines.append("")

        # Dismissed signals section
        if _campaign_state.dismissed:
            report_lines.extend([
                "## Dismissed Signals",
                "",
            ])
            for d in _campaign_state.dismissed[:10]:  # Limit to 10
                report_lines.append(f"- {d.signal_type} at {d.location}: {d.reason}")
            if len(_campaign_state.dismissed) > 10:
                report_lines.append(f"- ... and {len(_campaign_state.dismissed) - 10} more")
            report_lines.append("")

        # Coverage section
        report_lines.extend([
            "## Coverage",
            "",
        ])
        for scope_id, scope in _campaign_state.scopes.items():
            report_lines.append(f"- `{scope.path}`: depth {scope.depth}")
        report_lines.append("")

        # Final notes
        if final_notes:
            report_lines.extend([
                "## Additional Notes",
                "",
                final_notes,
                "",
            ])

        # Wave history
        report_lines.extend([
            "## Wave History",
            "",
        ])
        for wave in _campaign_state.wave_history:
            report_lines.append(
                f"- Wave {wave.wave_id}: {len(wave.tasks)} tasks, "
                f"+{wave.hypotheses_added} hypotheses, {wave.hypotheses_resolved} resolved"
            )
        report_lines.append("")

        report_content = "\n".join(report_lines)

        # Write report
        report_path = "/memories/overseer/final_report.md"
        _filesystem.write_file(report_path, report_content)

        # Also save final state
        _filesystem.save_campaign_state(_campaign_state.model_dump())

        return json.dumps({
            "success": True,
            "report_path": report_path,
            "summary": {
                "confirmed_findings": len(_campaign_state.confirmed_findings),
                "dismissed": len(_campaign_state.dismissed),
                "unresolved": len(pending),
                "waves_completed": _campaign_state.current_wave,
            }
        }, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)})


# Tool definitions
UPDATE_CAMPAIGN_STATE_TOOL = {
    "name": "update_campaign_state",
    "description": """Update the campaign state with new information. Use after synthesizing wave results.

Fields that can be updated:
- repo_profile: Repository profile dict
- hypotheses: List of hypothesis objects (will merge by ID)
- confirmed_findings: List of finding dicts (will append)
- dismissed: List of dismissal objects (will append)
- scopes: Dict of scope_id -> scope status (will merge)
- entrypoints: List of entrypoint objects (will append new)
- current_wave: Current wave number
- threat_model_path: Path to threat model
- authz_map_path: Path to auth boundary map""",
    "input_schema": {
        "type": "object",
        "properties": {
            "state_update_json": {
                "type": "string",
                "description": "JSON string with fields to update"
            }
        },
        "required": ["state_update_json"]
    }
}

FINALIZE_REPORT_TOOL = {
    "name": "finalize_report",
    "description": "Generate the final campaign report. Call when time budget is exhausted or investigation is complete.",
    "input_schema": {
        "type": "object",
        "properties": {
            "final_notes": {
                "type": "string",
                "description": "Additional notes to include in the final report"
            }
        },
        "required": []
    }
}
