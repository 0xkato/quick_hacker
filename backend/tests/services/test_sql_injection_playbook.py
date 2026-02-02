"""
Test suite for SQL Injection playbook integration with StrictClassifier.

Tests verify:
1. Parameterized queries → BY_DESIGN (mitigated_by_parameterization)
2. Unsafe interpolation → VALID_SECURITY_ISSUE
3. Threat model gating → HARDENING (DISPROVEN_BY_PROFILE)
4. Complete allowlists → BY_DESIGN (mitigated_by_allowlist)
5. Second-order SQLi → Requires double-proof
"""

import pytest
from services.classification import StrictClassifier
from models.schemas import (
    Finding,
    Evidence,
    InputChannel,
    ChecklistStatus,
    ChecklistItem,
    ProofChecklist,
    Disposition,
    VulnerabilityCategory
)


class TestSQLiParameterizedQueries:
    """Test that parameterized queries are correctly identified as safe."""

    def test_parameterized_positional_placeholder(self):
        """Positional placeholder (?) with separate parameter list is safe."""
        # Arrange
        finding = Finding(
            id="test_001",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Potential SQL Injection",
            description="User input in SQL query",
            file_path="db/users.py",
            line_start=45,
            severity="high",
            vulnerability_type="SQL Injection",
            confidence=0.8,
            created_at="2026-01-17T00:00:00Z"
        )

        # Put the code snippet in Evidence so detection logic can analyze it
        evidence = Evidence(
            finding_id="test_001",
            snippet='cursor.execute("SELECT * FROM users WHERE id = ?", [user_id])',
            handler_snippet='@app.get("/users")\ndef get_user():\n    user_id = request.args.get("id")\n    cursor.execute("SELECT * FROM users WHERE id = ?", [user_id])',
            input_channel=InputChannel.network,
            input_channel_deterministic=True,
            input_channel_signals=["route_registration", "request_data_read"],
            input_channel_reason="HTTP route + request.args.get"
        )

        classifier = StrictClassifier()

        # Act - let classify() build the checklist by detecting patterns
        result = classifier.classify(
            finding=finding,
            evidence=evidence,
            threat_model_profile=None
        )

        # Assert - check that detection found parameterization
        assert result.disposition == Disposition.BY_DESIGN, \
            f"Expected BY_DESIGN, got {result.disposition}"
        assert result.proof_checklist.dataflow_evidenced.status == ChecklistStatus.DISPROVEN, \
            f"Expected dataflow DISPROVEN, got {result.proof_checklist.dataflow_evidenced.status}"
        assert result.proof_checklist.dataflow_evidenced.reason_code == "mitigated_by_parameterization", \
            f"Expected reason_code mitigated_by_parameterization, got {result.proof_checklist.dataflow_evidenced.reason_code}"

    def test_parameterized_named_placeholder(self):
        """Named placeholder (:name) with parameter dict is safe."""
        finding = Finding(
            id="test_002",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Potential SQL Injection",
            description="User input in SQL query",
            file_path="db/users.py",
            line_start=50,
            severity="high",
            vulnerability_type="SQL Injection",
            confidence=0.8,
            created_at="2026-01-17T00:00:00Z"
        )

        evidence = Evidence(
            finding_id="test_002",
            snippet='cursor.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})',
            handler_snippet='user_id = request.json["id"]\ncursor.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})',
            input_channel=InputChannel.network,
            input_channel_deterministic=True,
            input_channel_signals=["route_registration", "request_data_read"]
        )

        classifier = StrictClassifier()
        result = classifier.classify(finding, evidence, None)

        assert result.disposition == Disposition.BY_DESIGN, \
            f"Expected BY_DESIGN, got {result.disposition}"
        assert result.proof_checklist.dataflow_evidenced.reason_code == "mitigated_by_parameterization", \
            f"Expected reason_code mitigated_by_parameterization, got {result.proof_checklist.dataflow_evidenced.reason_code}"


class TestSQLiUnsafeInterpolation:
    """Test that unsafe string interpolation is correctly identified as vulnerable."""

    def test_f_string_interpolation_with_network_input(self):
        """f-string interpolation with attacker-controlled input is vulnerable."""
        finding = Finding(
            id="test_003",
            agent_id="agent-001",
            repo_id="repo-001",
            title="SQL Injection in user search",
            description="User input directly in query",
            file_path="api/users.py",
            line_start=45,
            severity="high",
            vulnerability_type="SQL Injection",
            confidence=0.8,
            created_at="2026-01-17T00:00:00Z"
        )

        evidence = Evidence(
            finding_id="test_003",
            snippet='cursor.execute(f"SELECT * FROM users ORDER BY {sort_field}")',
            handler_snippet='@app.get("/users")\ndef users():\n    sort_field = request.args.get("sort")\n    cursor.execute(f"SELECT * FROM users ORDER BY {sort_field}")',
            input_channel=InputChannel.network,
            input_channel_deterministic=True,
            input_channel_signals=["route_registration", "request_data_read"],
            input_channel_reason="HTTP route + request.args.get"
        )

        # Threat model enables network channel
        threat_model_profile = {
            "attacker_capabilities": ["remote_network"],
            "execution_contexts": ["product_runtime"],
            "assets": ["user_data"]
        }

        classifier = StrictClassifier()
        result = classifier.classify(finding, evidence, threat_model_profile)

        assert result.disposition == Disposition.VALID_SECURITY_ISSUE, \
            f"Expected VALID_SECURITY_ISSUE, got {result.disposition}"
        assert result.proof_checklist.dataflow_evidenced.status == ChecklistStatus.PROVEN, \
            f"Expected dataflow PROVEN, got {result.proof_checklist.dataflow_evidenced.status}"
        assert result.proof_checklist.dataflow_evidenced.reason_code == "unsafe_identifier_influence", \
            f"Expected reason_code unsafe_identifier_influence, got {result.proof_checklist.dataflow_evidenced.reason_code}"

    def test_string_concatenation_is_unsafe(self):
        """String concatenation with user input is vulnerable."""
        finding = Finding(
            id="test_004",
            agent_id="agent-001",
            repo_id="repo-001",
            title="SQL Injection via concatenation",
            description="Query built with + operator",
            file_path="db/queries.py",
            line_start=30,
            severity="high",
            vulnerability_type="SQL Injection",
            confidence=0.8,
            created_at="2026-01-17T00:00:00Z"
        )

        evidence = Evidence(
            finding_id="test_004",
            snippet='cursor.execute("SELECT * FROM users WHERE name = \'" + user_name + "\'")',
            handler_snippet='user_name = request.form["name"]\ncursor.execute("SELECT * FROM users WHERE name = \'" + user_name + "\'")',
            input_channel=InputChannel.network,
            input_channel_deterministic=True,
            input_channel_signals=["route_registration", "request_data_read"]
        )

        threat_model_profile = {
            "attacker_capabilities": ["remote_network"]
        }

        classifier = StrictClassifier()
        result = classifier.classify(finding, evidence, threat_model_profile)

        assert result.disposition == Disposition.VALID_SECURITY_ISSUE, \
            f"Expected VALID_SECURITY_ISSUE, got {result.disposition}"
        assert result.proof_checklist.dataflow_evidenced.status == ChecklistStatus.PROVEN, \
            f"Expected dataflow PROVEN, got {result.proof_checklist.dataflow_evidenced.status}"
        assert result.proof_checklist.dataflow_evidenced.reason_code == "unsafe_structure_taint", \
            f"Expected reason_code unsafe_structure_taint, got {result.proof_checklist.dataflow_evidenced.reason_code}"


class TestThreatModelGating:
    """Test that threat model correctly gates attacker-controlled input."""

    def test_network_input_without_network_capability_is_hardening(self):
        """If threat model disables network channel, finding becomes HARDENING."""
        finding = Finding(
            id="test_005",
            agent_id="agent-001",
            repo_id="repo-001",
            title="SQL Injection",
            description="Network input in query",
            file_path="api/users.py",
            line_start=45,
            severity="high",
            vulnerability_type="SQL Injection",
            confidence=0.8,
            created_at="2026-01-17T00:00:00Z"
        )

        evidence = Evidence(
            finding_id="test_005",
            snippet='cursor.execute(f"SELECT * FROM users WHERE id={user_id}")',
            handler_snippet='user_id = request.args.get("id")\ncursor.execute(f"SELECT * FROM users WHERE id={user_id}")',
            input_channel=InputChannel.network,
            input_channel_deterministic=True,
            input_channel_signals=["route_registration", "request_data_read"]
        )

        # Threat model DISABLES network channel
        threat_model_profile = {
            "attacker_capabilities": [],  # No remote_network capability
            "execution_contexts": ["dev_tooling"],
            "assets": ["source_code"]
        }

        classifier = StrictClassifier()
        result = classifier.classify(finding, evidence, threat_model_profile)

        # Should be HARDENING (out of threat model scope, but still useful to know)
        assert result.disposition == Disposition.HARDENING, \
            f"Expected HARDENING, got {result.disposition}"
        assert result.proof_checklist.source_controlled_input.reason_code == "disabled_by_profile", \
            f"Expected reason_code disabled_by_profile, got {result.proof_checklist.source_controlled_input.reason_code}"


class TestAllowlistMitigation:
    """Test that complete allowlists are recognized as safe."""

    def test_complete_allowlist_is_safe(self):
        """Complete allowlist for identifiers is a valid mitigation."""
        finding = Finding(
            id="test_006",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Dynamic column in query",
            description="User controls column name",
            file_path="api/users.py",
            line_start=50,
            severity="high",
            vulnerability_type="SQL Injection",
            confidence=0.8,
            created_at="2026-01-17T00:00:00Z"
        )

        evidence = Evidence(
            finding_id="test_006",
            snippet='ALLOWED_COLUMNS = {"id", "name", "email"}\nif col not in ALLOWED_COLUMNS: raise ValueError()\ncursor.execute(f"SELECT {col} FROM users")',
            handler_snippet='col = request.args.get("column")\nALLOWED_COLUMNS = {"id", "name", "email"}\nif col not in ALLOWED_COLUMNS: raise ValueError()\ncursor.execute(f"SELECT {col} FROM users")',
            input_channel=InputChannel.network,
            input_channel_deterministic=True,
            input_channel_signals=["route_registration", "request_data_read"]
        )

        threat_model_profile = {
            "attacker_capabilities": ["remote_network"]
        }

        classifier = StrictClassifier()
        result = classifier.classify(finding, evidence, threat_model_profile)

        assert result.disposition == Disposition.BY_DESIGN, \
            f"Expected BY_DESIGN, got {result.disposition}"
        assert result.proof_checklist.dataflow_evidenced.reason_code == "mitigated_by_allowlist", \
            f"Expected reason_code mitigated_by_allowlist, got {result.proof_checklist.dataflow_evidenced.reason_code}"


class TestSecondOrderSQLInjection:
    """Test that second-order SQLi requires double-proof."""

    def test_second_order_with_both_proofs_is_vulnerable(self):
        """Second-order SQLi with both write control and unsafe use is valid."""
        finding = Finding(
            id="test_007",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Second-order SQL Injection",
            description="Stored input later used unsafely",
            file_path="app/logs.py",
            line_start=80,
            severity="high",
            vulnerability_type="SQL Injection",
            confidence=0.8,
            created_at="2026-01-17T00:00:00Z"
        )

        evidence = Evidence(
            finding_id="test_007",
            snippet='# PROOF 1: Attacker write control\n# File: api/register.py:30\nusername = request.form.get("username")\ncursor.execute("INSERT INTO users (username) VALUES (?)", [username])\n\n# PROOF 2: Later unsafe use\n# File: app/logs.py:80\nusername = cursor.execute("SELECT username FROM users WHERE id=?", [uid]).fetchone()[0]\ncursor.execute(f"SELECT * FROM logs WHERE username = \'{username}\'")',
            handler_snippet='# Registration endpoint shows safe storage, logs query shows unsafe retrieval',
            input_channel=InputChannel.network,
            input_channel_deterministic=True,
            input_channel_signals=["route_registration", "request_data_read"]
        )

        threat_model_profile = {
            "attacker_capabilities": ["remote_network"]
        }

        classifier = StrictClassifier()
        result = classifier.classify(finding, evidence, threat_model_profile)

        # The detection will find the unsafe f-string in the second query
        # With all checklist items satisfied, this should be VALID_SECURITY_ISSUE
        assert result.disposition == Disposition.VALID_SECURITY_ISSUE, \
            f"Expected VALID_SECURITY_ISSUE, got {result.disposition}"
        # The f-string pattern should be detected
        assert result.proof_checklist.dataflow_evidenced.status == ChecklistStatus.PROVEN, \
            f"Expected dataflow PROVEN, got {result.proof_checklist.dataflow_evidenced.status}"
        assert result.proof_checklist.dataflow_evidenced.reason_code == "unsafe_identifier_influence", \
            f"Expected reason_code unsafe_identifier_influence, got {result.proof_checklist.dataflow_evidenced.reason_code}"

    def test_second_order_without_unsafe_use_is_speculative(self):
        """If later use is safe (parameterized), no second-order vuln."""
        finding = Finding(
            id="test_008",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Potential second-order SQLi",
            description="User input stored but later use is safe",
            file_path="app/logs.py",
            line_start=80,
            severity="high",
            vulnerability_type="SQL Injection",
            confidence=0.8,
            created_at="2026-01-17T00:00:00Z"
        )

        evidence = Evidence(
            finding_id="test_008",
            snippet='# Storage\nusername = request.form["username"]\ncursor.execute("INSERT INTO users (username) VALUES (?)", [username])\n\n# Later SAFE use\nusername = cursor.execute("SELECT username FROM users WHERE id=?", [uid]).fetchone()[0]\ncursor.execute("SELECT * FROM logs WHERE username = ?", [username])',
            handler_snippet='Both storage and retrieval are parameterized',
            input_channel=InputChannel.network,
            input_channel_deterministic=True,
            input_channel_signals=["route_registration", "request_data_read"]
        )

        threat_model_profile = {
            "attacker_capabilities": ["remote_network"]
        }

        classifier = StrictClassifier()
        result = classifier.classify(finding, evidence, threat_model_profile)

        # Should be BY_DESIGN (safe by mitigation) - all uses are parameterized
        assert result.disposition == Disposition.BY_DESIGN, \
            f"Expected BY_DESIGN, got {result.disposition}"
        assert result.proof_checklist.dataflow_evidenced.reason_code == "mitigated_by_parameterization", \
            f"Expected reason_code mitigated_by_parameterization, got {result.proof_checklist.dataflow_evidenced.reason_code}"


class TestInternalOnlyFunctions:
    """Test that internal-only functions are properly scoped."""

    def test_internal_cron_job_without_threat_model_ci_is_not_vulnerable(self):
        """Internal cron job with no CI threat model is out of scope."""
        finding = Finding(
            id="test_009",
            agent_id="agent-001",
            repo_id="repo-001",
            title="SQL Injection in cron",
            description="String interpolation in internal function",
            file_path="jobs/report.py",
            line_start=20,
            severity="high",
            vulnerability_type="SQL Injection",
            confidence=0.8,
            created_at="2026-01-17T00:00:00Z"
        )

        evidence = Evidence(
            finding_id="test_009",
            snippet='def _generate_report(user_id):\n    cursor.execute(f"SELECT * FROM users WHERE id={user_id}")',
            handler_snippet='# Called only by internal cron scheduler',
            input_channel=InputChannel.unknown,  # Cannot determine input channel
            input_channel_deterministic=False,
            input_channel_signals=[]
        )

        # Threat model only includes network, not CI/local
        threat_model_profile = {
            "attacker_capabilities": ["remote_network"],
            "execution_contexts": ["product_runtime"]
        }

        classifier = StrictClassifier()

        checklist = ProofChecklist(
            source_controlled_input=ChecklistItem(
                value=False,
                status=ChecklistStatus.UNKNOWN,  # Or DISPROVEN if proven internal
                reason="Input channel cannot be deterministically inferred (no HTTP route/request)",
                reason_code=None
            ),
            sink_present=ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason="cursor.execute present",
                reason_code=None
            ),
            dataflow_evidenced=ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason="f-string interpolation present",
                reason_code="unsafe_structure_taint"
            ),
            reachable=ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason="Called by cron",
                reason_code=None
            ),
            boundary_crossed=ChecklistItem(
                value=False,
                status=ChecklistStatus.DISPROVEN,
                reason="Internal-only function, threat model excludes CI/local execution",
                reason_code=None
            ),
            not_only_misconfig=ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason="Code-level",
                reason_code=None
            ),
            security_control_bypassed=ChecklistItem(
                value=True,
                status=ChecklistStatus.PROVEN,
                reason="No parameterization",
                reason_code="unsafe_structure_taint"
            )
        )

        result = classifier.classify(finding, evidence, threat_model_profile)

        # Should be HARDENING or SPECULATIVE (not VALID because A or E is not PROVEN)
        assert result.disposition in [Disposition.HARDENING, Disposition.SPECULATIVE]
        assert result.disposition != Disposition.VALID_SECURITY_ISSUE


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
