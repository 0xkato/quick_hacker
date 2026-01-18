"""Validity checklist operations for ToolCore."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from models.sink_signals import CandidateStatus


class ValidityMixin:
    """Mixin for validity checklist operations.

    This mixin provides methods for getting validity checklists and
    finalizing findings with the disprove-first self-critique checklist.
    """

    def get_validity_checklist(self, vulnerability_class: str) -> dict[str, Any]:
        """Get validity checklist for a specific vulnerability class.

        Returns the appropriate validity checklist markdown content to help
        agents systematically validate suspected vulnerabilities and avoid
        false positives.

        Args:
            vulnerability_class: The vulnerability class to get checklist for.
                Valid values: sql_injection, command_execution, path_traversal,
                ssrf, xss, deserialization, auth_bypass, sensitive_data_exposure,
                or "disprove" for the disprove-first self-critique checklist.

        Returns:
            Dictionary with:
            - success: True if checklist found, False if error
            - class: The vulnerability class requested
            - content: Markdown content of the checklist (if success=True)
            - error: Error message (if success=False)
        """
        # Map vulnerability class to filename
        checklist_files = {
            "sql_injection": "sql_injection.md",
            "command_execution": "command_execution.md",
            "path_traversal": "path_traversal.md",
            "ssrf": "ssrf.md",
            "xss": "xss.md",
            "deserialization": "deserialization.md",
            "auth_bypass": "auth_bypass.md",
            "sensitive_data_exposure": "sensitive_data_exposure.md",
            "disprove": "disprove_checklist.md",
        }

        # Validate vulnerability class
        if vulnerability_class not in checklist_files:
            valid_classes = ", ".join(sorted(checklist_files.keys()))
            return {
                "success": False,
                "class": vulnerability_class,
                "error": f"Unknown vulnerability class '{vulnerability_class}'. Valid classes: {valid_classes}"
            }

        # Build path to checklist file
        # Assuming checklists are in backend/agents/validity_checklists/
        backend_dir = Path(__file__).parent.parent.parent
        checklist_path = backend_dir / "agents" / "validity_checklists" / checklist_files[vulnerability_class]

        # Read checklist content
        try:
            content = checklist_path.read_text(encoding="utf-8")
            return {
                "success": True,
                "class": vulnerability_class,
                "content": content
            }
        except FileNotFoundError:
            return {
                "success": False,
                "class": vulnerability_class,
                "error": f"Checklist file not found: {checklist_path}"
            }
        except Exception as e:
            return {
                "success": False,
                "class": vulnerability_class,
                "error": f"Error reading checklist: {str(e)}"
            }

    def finalize_finding(
        self,
        signal_id: str,
        classification: CandidateStatus | str,
        disprove_answers: dict[str, str],
        reasoning: str
    ) -> dict[str, Any]:
        """Finalize a finding with the disprove-first self-critique checklist.

        This method enforces the zero-FP protocol by requiring agents to answer
        all 6 disprove questions before finalizing a finding. It validates the
        classification and ensures the reasoning is provided.

        Args:
            signal_id: The SinkSignal ID being finalized
            classification: Final classification (must be a valid CandidateStatus
                except PENDING)
            disprove_answers: Answers to the 6 disprove questions, with keys
                q1, q2, q3, q4, q5, q6 and string values
            reasoning: Detailed reasoning for the classification decision

        Returns:
            Dictionary with:
            - success: True if finalization accepted, False if validation failed
            - classification: The validated classification (if success=True)
            - disprove_answers: The provided answers (if success=True)
            - reasoning: The provided reasoning (if success=True)
            - error: Error message (if success=False)
        """
        # Convert string to enum if needed
        if isinstance(classification, str):
            try:
                classification = CandidateStatus(classification)
            except ValueError:
                return {
                    "success": False,
                    "error": f"Invalid classification '{classification}'. Must be one of: {', '.join(c.value for c in CandidateStatus)}"
                }

        # Validate classification (cannot be PENDING)
        if classification == CandidateStatus.PENDING:
            return {
                "success": False,
                "error": "Cannot finalize with PENDING classification. Must choose a final outcome: VALIDATED_VULNERABILITY, NEEDS_HUMAN_REVIEW, HARDENING_OPPORTUNITY, NOT_A_VULNERABILITY, or DUPLICATE."
            }

        # Validate disprove answers (must have all 6 questions)
        required_questions = {"q1", "q2", "q3", "q4", "q5", "q6"}
        provided_questions = set(disprove_answers.keys())

        if provided_questions != required_questions:
            missing = required_questions - provided_questions
            extra = provided_questions - required_questions
            error_parts = []
            if missing:
                error_parts.append(f"Missing answers for: {', '.join(sorted(missing))}")
            if extra:
                error_parts.append(f"Unexpected questions: {', '.join(sorted(extra))}")

            return {
                "success": False,
                "error": f"Must answer all 6 questions. {' '.join(error_parts)}"
            }

        # Validate answer values are non-empty strings
        for question_key in required_questions:
            answer = disprove_answers[question_key]
            if not isinstance(answer, str) or not answer.strip():
                return {
                    "success": False,
                    "error": f"Answer for '{question_key}' must be a non-empty string. Disprove checklist requires substantive answers, not placeholders."
                }

        # Validate reasoning is provided
        if not reasoning or not reasoning.strip():
            return {
                "success": False,
                "error": "Reasoning is required for finalization."
            }

        # Return successful finalization
        return {
            "success": True,
            "signal_id": signal_id,
            "classification": classification,
            "disprove_answers": disprove_answers,
            "reasoning": reasoning
        }
