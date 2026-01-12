"""Custom tools for Deep Audit agents."""

import json
import hashlib
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

from services.project_service import project_service
from models.schemas import Finding, Severity


def _compute_signal_fingerprint(signal: Dict[str, Any]) -> str:
    """Compute unique fingerprint for a signal."""
    # Use signal_id as fingerprint (must be unique per project)
    signal_id = signal.get("signal_id", "")
    if not signal_id:
        # Fallback: hash key fields
        key = f"{signal.get('file_path')}:{signal.get('line_range')}:{signal.get('signal_type')}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]
    return signal_id


def upsert_sink_signals(project_id: str, signals: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Upsert sink signals to project sink_signals.json file.

    Deduplicates by signal fingerprint.

    Args:
        project_id: Project identifier
        signals: List of signal dictionaries

    Returns:
        {"success": bool, "upserted_count": int, "duplicate_count": int}
    """
    project_path = project_service.get_project_path(project_id)
    if not project_path:
        return {"success": False, "error": f"Project not found: {project_id}"}

    signals_file = Path(project_path) / "sink_signals.json"

    # Load existing signals
    existing_signals = []
    existing_fingerprints = set()
    if signals_file.exists():
        try:
            with open(signals_file) as f:
                data = json.load(f)
                existing_signals = data.get("signals", [])
                existing_fingerprints = {
                    _compute_signal_fingerprint(s) for s in existing_signals
                }
        except (json.JSONDecodeError, IOError):
            # File corrupt or unreadable, start fresh
            pass

    # Add new signals (skip duplicates)
    upserted_count = 0
    duplicate_count = 0

    for signal in signals:
        fingerprint = _compute_signal_fingerprint(signal)
        if fingerprint not in existing_fingerprints:
            # Add timestamp if not present
            if "created_at" not in signal:
                signal["created_at"] = datetime.utcnow().isoformat()
            existing_signals.append(signal)
            existing_fingerprints.add(fingerprint)
            upserted_count += 1
        else:
            duplicate_count += 1

    # Write back to file
    signals_file.parent.mkdir(parents=True, exist_ok=True)
    with open(signals_file, "w") as f:
        json.dump({"signals": existing_signals, "updated_at": datetime.utcnow().isoformat()}, f, indent=2)

    return {
        "success": True,
        "upserted_count": upserted_count,
        "duplicate_count": duplicate_count,
        "total_signals": len(existing_signals),
    }


def promote_finding(
    project_id: str,
    agent_id: str,
    finding: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Promote a verified signal to a Finding.

    This tool should ONLY be called by the Auditor subagent after verification.

    Args:
        project_id: Project identifier
        agent_id: Agent identifier
        finding: Finding data dictionary

    Returns:
        {"success": bool, "finding": Finding dict}
    """
    try:
        # Map severity string to enum
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        severity_str = finding.get("severity", "medium").lower()
        severity_enum = severity_map.get(severity_str, Severity.MEDIUM)

        # Create Finding object
        finding_obj = Finding(
            id=f"{agent_id}-{finding.get('signal_id', 'finding')}-{datetime.utcnow().timestamp()}",
            agent_id=agent_id,
            repo_id=project_id,
            severity=severity_enum,
            title=finding.get("title", "Security Finding"),
            description=finding.get("description", ""),
            file_path=finding.get("file_path", ""),
            line_start=finding.get("line_start", 1),
            line_end=finding.get("line_end"),
            code_snippet=finding.get("vulnerable_code", ""),
            vulnerable_code=finding.get("vulnerable_code", ""),
            vulnerability_type=finding.get("vulnerability_type", "Unknown"),
            cwe_id=finding.get("cwe_id"),
            attack_scenario=finding.get("attack_scenario"),
            proof_of_concept=finding.get("proof_of_concept"),
            recommended_fix=finding.get("recommended_fix"),
            confidence=finding.get("confidence", 0.5),
            source_trace=finding.get("source_trace"),
            created_at=datetime.utcnow(),
            metadata=finding.get("metadata", {}),
        )

        return {
            "success": True,
            "finding": finding_obj.model_dump(mode='json'),
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }
