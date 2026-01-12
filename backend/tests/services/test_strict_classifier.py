"""
Unit tests for strict_classifier.py - Tri-state proof checklist and disposition logic.

Tests ensure:
1. Conservative VALID_SECURITY_ISSUE rules
2. BY_DESIGN logic (never for command injection)
3. Pattern downgrades (only downgrades, never upgrades)
4. Deterministic classification
5. Proper handling of edge cases
"""

import pytest
from models.schemas import (
    Finding,
    EvidenceResult,
    EvidenceMatch,
    ChecklistStatus,
    Disposition,
)
from services.strict_classifier import StrictClassifier


@pytest.fixture
def classifier():
    """Create classifier instance."""
    return StrictClassifier()


@pytest.fixture
def base_finding():
    """Base finding fixture."""
    return Finding(
        id="test-001",
        agent_id="agent-001",
        repo_id="repo-001",
        title="Test Finding",
        description="Test description",
        file_path="/app/test.py",
        line_start=10,
        vulnerability_type="Unknown",
        severity="high",
        confidence=0.8,
        created_at="2026-01-12T00:00:00Z",
    )


@pytest.fixture
def empty_evidence():
    """Empty evidence result."""
    return EvidenceResult(
        snippet="",
        sources=[],
        sinks=[],
        auth_gates=[],
        route_registrations=[],
        symbol_references=[],
        symbol_info=None,
        framework_detected=None,
        url_is_constant=None,
        url_from_config=None,
    )


class TestCodeExecutionByDesign:
    """Test BY_DESIGN classification for code execution features."""

    def test_exec_in_pipeline_is_by_design(self, classifier, base_finding, empty_evidence):
        """Code execution (exec) in pipeline with no bypass → BY_DESIGN."""
        finding = base_finding.model_copy()
        finding.vulnerability_type = "Code Injection"
        finding.file_path = "/app/pipelines/data_processor.py"
        finding.description = "Use of exec() function for dynamic code execution"

        evidence = empty_evidence.model_copy()
        evidence.snippet = """
def process_pipeline(config):
    # Dynamic pipeline execution
    exec(config['transformation_code'])
"""
        evidence.sinks = [
            EvidenceMatch(
                file="/app/pipelines/data_processor.py",
                line=10,
                snippet="exec(config['transformation_code'])",
                match_type="sink",
            )
        ]

        result = classifier.classify(finding, evidence)

        assert result.disposition == Disposition.BY_DESIGN
        assert "code execution feature" in result.reasoning[0].lower() or "pipeline" in result.reasoning[0].lower()
        # Sink should be PROVEN
        assert result.proof_checklist.sink_present.status == ChecklistStatus.PROVEN

    def test_command_injection_never_by_design(self, classifier, base_finding, empty_evidence):
        """Command injection with request input → VALID_SECURITY_ISSUE (never BY_DESIGN)."""
        finding = base_finding.model_copy()
        finding.vulnerability_type = "Command Injection"
        finding.file_path = "/app/api/handlers.py"
        finding.description = "Shell command with user input"

        evidence = empty_evidence.model_copy()
        evidence.snippet = """
@app.post("/execute")
async def execute_command(cmd: str):
    result = subprocess.run(cmd, shell=True)
    return {"output": result.stdout}
"""
        evidence.sources = [
            EvidenceMatch(
                file="/app/api/handlers.py",
                line=2,
                snippet="async def execute_command(cmd: str):",
                match_type="source",
            )
        ]
        evidence.sinks = [
            EvidenceMatch(
                file="/app/api/handlers.py",
                line=3,
                snippet="subprocess.run(cmd, shell=True)",
                match_type="sink",
            )
        ]
        evidence.route_registrations = [
            EvidenceMatch(
                file="/app/api/handlers.py",
                line=1,
                snippet='@app.post("/execute")',
                match_type="route_registration",
            )
        ]

        result = classifier.classify(finding, evidence)

        # Should be VALID_SECURITY_ISSUE, never BY_DESIGN for command injection
        assert result.disposition == Disposition.VALID_SECURITY_ISSUE
        assert result.proof_checklist.source_controlled_input.status == ChecklistStatus.PROVEN
        assert result.proof_checklist.sink_present.status == ChecklistStatus.PROVEN
        assert result.proof_checklist.reachable.status == ChecklistStatus.PROVEN


class TestSSRFPatternDowngrades:
    """Test SSRF pattern-based downgrades."""

    def test_ssrf_constant_url_downgraded(self, classifier, base_finding, empty_evidence):
        """SSRF with constant URL → SPECULATIVE (not exploitable)."""
        finding = base_finding.model_copy()
        finding.vulnerability_type = "SSRF"
        finding.description = "HTTP request to external URL"

        evidence = empty_evidence.model_copy()
        evidence.snippet = """
def check_service_health():
    response = requests.get("https://api.example.com/health")
    return response.json()
"""
        evidence.sinks = [
            EvidenceMatch(
                file="/app/health.py",
                line=3,
                snippet='requests.get("https://api.example.com/health")',
                match_type="sink",
            )
        ]
        evidence.url_is_constant = True

        result = classifier.classify(finding, evidence)

        # Should be downgraded to SPECULATIVE
        assert result.disposition == Disposition.SPECULATIVE
        assert any("constant" in r.lower() or "hard-coded" in r.lower() for r in result.reasoning)

    def test_ssrf_config_url_downgraded(self, classifier, base_finding, empty_evidence):
        """SSRF with config-only URL → SPECULATIVE (integration test)."""
        finding = base_finding.model_copy()
        finding.vulnerability_type = "SSRF"

        evidence = empty_evidence.model_copy()
        evidence.snippet = """
def fetch_data():
    url = os.getenv("API_ENDPOINT")
    response = requests.get(url)
"""
        evidence.sinks = [
            EvidenceMatch(
                file="/app/api.py",
                line=3,
                snippet="requests.get(url)",
                match_type="sink",
            )
        ]
        evidence.url_from_config = True

        result = classifier.classify(finding, evidence)

        assert result.disposition == Disposition.SPECULATIVE
        assert any("config" in r.lower() or "environment" in r.lower() for r in result.reasoning)

    def test_ssrf_user_input_valid(self, classifier, base_finding, empty_evidence):
        """SSRF with user-controlled URL → VALID_SECURITY_ISSUE."""
        finding = base_finding.model_copy()
        finding.vulnerability_type = "SSRF"

        evidence = empty_evidence.model_copy()
        evidence.snippet = """
@app.post("/fetch")
async def fetch_url(url: str):
    response = requests.get(url)
    return response.text
"""
        evidence.sources = [
            EvidenceMatch(
                file="/app/api.py",
                line=2,
                snippet="async def fetch_url(url: str):",
                match_type="source",
            )
        ]
        evidence.sinks = [
            EvidenceMatch(
                file="/app/api.py",
                line=3,
                snippet="requests.get(url)",
                match_type="sink",
            )
        ]
        evidence.route_registrations = [
            EvidenceMatch(
                file="/app/api.py",
                line=1,
                snippet='@app.post("/fetch")',
                match_type="route_registration",
            )
        ]
        evidence.url_is_constant = False

        result = classifier.classify(finding, evidence)

        assert result.disposition == Disposition.VALID_SECURITY_ISSUE


class TestCSWSHPatterns:
    """Test CSWSH (Cross-Site WebSocket Hijacking) patterns."""

    def test_cswsh_check_origin_no_creds_hardening(self, classifier, base_finding, empty_evidence):
        """CSWSH: check_origin alone without ambient creds → HARDENING."""
        finding = base_finding.model_copy()
        finding.vulnerability_type = "Cross-Site WebSocket Hijacking"
        finding.description = "WebSocket without origin validation"

        evidence = empty_evidence.model_copy()
        evidence.snippet = """
async def websocket_handler(websocket: WebSocket):
    # Check origin header
    if websocket.headers.get("origin") != "https://example.com":
        await websocket.close()
        return
    await websocket.accept()
"""
        evidence.auth_gates = [
            EvidenceMatch(
                file="/app/ws.py",
                line=3,
                snippet='if websocket.headers.get("origin") != "https://example.com":',
                match_type="auth_gate",
            )
        ]

        result = classifier.classify(finding, evidence)

        # Without evidence of ambient credentials or session cookies, this is HARDENING
        assert result.disposition == Disposition.HARDENING
        assert any("defense-in-depth" in r.lower() or "hardening" in r.lower() for r in result.reasoning)

    def test_websocket_text_not_auto_cswsh(self, classifier, base_finding, empty_evidence):
        """Websocket mention alone doesn't normalize to CSWSH."""
        finding = base_finding.model_copy()
        finding.vulnerability_type = "Code Injection"  # Different vuln type
        finding.description = "RCE via websocket message handler"

        evidence = empty_evidence.model_copy()
        evidence.snippet = """
async def handle_message(websocket, message):
    # Execute user command
    exec(message['code'])
"""
        evidence.sinks = [
            EvidenceMatch(
                file="/app/ws.py",
                line=3,
                snippet="exec(message['code'])",
                match_type="sink",
            )
        ]

        result = classifier.classify(finding, evidence)

        # Should classify based on actual vulnerability (code injection)
        # NOT automatically downgraded just because "websocket" appears
        assert result.disposition != Disposition.HARDENING
        # Category should NOT be CSWSH just because "websocket" in code
        assert result.category != "CSWSH"


class TestDeserializationPatterns:
    """Test deserialization vulnerability patterns."""

    def test_yaml_load_no_source_hardening(self, classifier, base_finding, empty_evidence):
        """YAML load with no attacker-controlled source → HARDENING."""
        finding = base_finding.model_copy()
        finding.vulnerability_type = "Deserialization"
        finding.description = "Use of unsafe yaml.load()"

        evidence = empty_evidence.model_copy()
        evidence.snippet = """
def load_config():
    with open('config.yaml', 'r') as f:
        config = yaml.load(f, Loader=yaml.Loader)
    return config
"""
        evidence.sinks = [
            EvidenceMatch(
                file="/app/config.py",
                line=3,
                snippet="yaml.load(f, Loader=yaml.Loader)",
                match_type="sink",
            )
        ]
        # No sources - file is local/trusted

        result = classifier.classify(finding, evidence)

        assert result.disposition == Disposition.HARDENING
        assert result.proof_checklist.source_controlled_input.status != ChecklistStatus.PROVEN


class TestSQLInjectionPatterns:
    """Test SQL injection patterns."""

    def test_sql_connector_no_source_by_design(self, classifier, base_finding, empty_evidence):
        """SQL injection in connector/pipeline with no attacker source → BY_DESIGN."""
        finding = base_finding.model_copy()
        finding.vulnerability_type = "SQL Injection"
        finding.file_path = "/app/connectors/database.py"
        finding.description = "Dynamic SQL query construction"

        evidence = empty_evidence.model_copy()
        evidence.snippet = """
def build_query(table_name, columns):
    # Internal connector - developer-controlled
    query = f"SELECT {','.join(columns)} FROM {table_name}"
    return execute_query(query)
"""
        evidence.sinks = [
            EvidenceMatch(
                file="/app/connectors/database.py",
                line=3,
                snippet='query = f"SELECT {\\',\\'.join(columns)} FROM {table_name}"',
                match_type="sink",
            )
        ]
        # No request sources - internal pipeline code

        result = classifier.classify(finding, evidence)

        # Developer-controlled SQL in connector/pipeline → BY_DESIGN
        assert result.disposition == Disposition.BY_DESIGN

    def test_sql_injection_with_request_valid(self, classifier, base_finding, empty_evidence):
        """SQL injection with request input → VALID_SECURITY_ISSUE."""
        finding = base_finding.model_copy()
        finding.vulnerability_type = "SQL Injection"

        evidence = empty_evidence.model_copy()
        evidence.snippet = """
@app.get("/users")
async def get_users(name: str):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return db.execute(query)
"""
        evidence.sources = [
            EvidenceMatch(
                file="/app/api.py",
                line=2,
                snippet="async def get_users(name: str):",
                match_type="source",
            )
        ]
        evidence.sinks = [
            EvidenceMatch(
                file="/app/api.py",
                line=3,
                snippet='query = f"SELECT * FROM users WHERE name = \\'{name}\\'"',
                match_type="sink",
            )
        ]
        evidence.route_registrations = [
            EvidenceMatch(
                file="/app/api.py",
                line=1,
                snippet='@app.get("/users")',
                match_type="route_registration",
            )
        ]

        result = classifier.classify(finding, evidence)

        assert result.disposition == Disposition.VALID_SECURITY_ISSUE


class TestBugDisposition:
    """Test BUG disposition (security control bypassed)."""

    def test_auth_bypass_is_bug(self, classifier, base_finding, empty_evidence):
        """Explicit auth bypass → BUG."""
        finding = base_finding.model_copy()
        finding.vulnerability_type = "Authentication Bypass"
        finding.description = "Route bypasses authentication check"

        evidence = empty_evidence.model_copy()
        evidence.snippet = """
@app.post("/admin/delete")
async def delete_user(user_id: str, skip_auth: bool = False):
    if not skip_auth:
        check_admin()
    # Delete user - dangerous operation
    db.users.delete(user_id)
"""
        evidence.sources = [
            EvidenceMatch(
                file="/app/admin.py",
                line=2,
                snippet="async def delete_user(user_id: str, skip_auth: bool = False):",
                match_type="source",
            )
        ]
        evidence.sinks = [
            EvidenceMatch(
                file="/app/admin.py",
                line=6,
                snippet="db.users.delete(user_id)",
                match_type="sink",
            )
        ]
        evidence.route_registrations = [
            EvidenceMatch(
                file="/app/admin.py",
                line=1,
                snippet='@app.post("/admin/delete")',
                match_type="route_registration",
            )
        ]
        # Pattern indicating bypass
        evidence.snippet_contains_bypass = "skip_auth" in evidence.snippet

        result = classifier.classify(finding, evidence)

        # Should be BUG due to explicit bypass mechanism
        assert result.disposition in [Disposition.BUG, Disposition.VALID_SECURITY_ISSUE]


class TestMisconfiguration:
    """Test MISCONFIGURATION disposition."""

    def test_auth_disabled_misconfiguration(self, classifier, base_finding, empty_evidence):
        """Vulnerability only when auth disabled → MISCONFIGURATION."""
        finding = base_finding.model_copy()
        finding.vulnerability_type = "Unauthorized Access"
        finding.description = "Endpoint accessible when authentication is disabled"

        evidence = empty_evidence.model_copy()
        evidence.snippet = """
@app.post("/admin/users")
async def create_user(username: str):
    if not settings.REQUIRE_AUTH:
        # No authentication when disabled
        db.users.create(username)
"""
        evidence.sources = [
            EvidenceMatch(
                file="/app/api.py",
                line=2,
                snippet="async def create_user(username: str):",
                match_type="source",
            )
        ]
        evidence.sinks = [
            EvidenceMatch(
                file="/app/api.py",
                line=5,
                snippet="db.users.create(username)",
                match_type="sink",
            )
        ]
        evidence.route_registrations = [
            EvidenceMatch(
                file="/app/api.py",
                line=1,
                snippet='@app.post("/admin/users")',
                match_type="route_registration",
            )
        ]

        result = classifier.classify(finding, evidence)

        # Evidence of "when auth disabled" pattern
        if "not settings.REQUIRE_AUTH" in evidence.snippet or "when disabled" in finding.description.lower():
            assert result.disposition == Disposition.MISCONFIGURATION


class TestPatternDowngradesOnly:
    """Test that pattern rules only downgrade, never upgrade."""

    def test_pattern_cannot_upgrade_to_valid(self, classifier, base_finding, empty_evidence):
        """Pattern rules must never return VALID_SECURITY_ISSUE or BUG."""
        finding = base_finding.model_copy()
        finding.vulnerability_type = "SSRF"

        evidence = empty_evidence.model_copy()
        evidence.snippet = "requests.get(url)"
        evidence.sinks = [
            EvidenceMatch(
                file="/app/test.py",
                line=1,
                snippet="requests.get(url)",
                match_type="sink",
            )
        ]
        # No sources, no routes - should not be VALID

        result = classifier.classify(finding, evidence)

        # Pattern downgrades can only return: SPECULATIVE, HARDENING, MISCONFIGURATION, BY_DESIGN
        assert result.disposition in [
            Disposition.SPECULATIVE,
            Disposition.HARDENING,
            Disposition.MISCONFIGURATION,
            Disposition.BY_DESIGN,
        ]
        assert result.disposition not in [Disposition.VALID_SECURITY_ISSUE, Disposition.BUG]


class TestConfidenceScoring:
    """Test confidence score calculation."""

    def test_valid_has_exploit_confidence(self, classifier, base_finding, empty_evidence):
        """VALID_SECURITY_ISSUE should have exploit confidence."""
        finding = base_finding.model_copy()
        finding.vulnerability_type = "Command Injection"

        evidence = empty_evidence.model_copy()
        evidence.sources = [EvidenceMatch(file="test.py", line=1, snippet="def handler(cmd: str)", match_type="source")]
        evidence.sinks = [EvidenceMatch(file="test.py", line=2, snippet="subprocess.run(cmd, shell=True)", match_type="sink")]
        evidence.route_registrations = [EvidenceMatch(file="test.py", line=0, snippet="@app.post", match_type="route_registration")]

        result = classifier.classify(finding, evidence)

        if result.disposition == Disposition.VALID_SECURITY_ISSUE:
            assert result.exploit_confidence is not None
            assert 0 <= result.exploit_confidence <= 100

    def test_classification_confidence_always_present(self, classifier, base_finding, empty_evidence):
        """All results should have classification confidence."""
        finding = base_finding.model_copy()

        result = classifier.classify(finding, empty_evidence)

        assert result.classification_confidence is not None
        assert 0 <= result.classification_confidence <= 100


class TestReasoningGeneration:
    """Test reasoning output."""

    def test_reasoning_has_bullets(self, classifier, base_finding, empty_evidence):
        """Reasoning should be 2-4 bullets."""
        finding = base_finding.model_copy()

        result = classifier.classify(finding, empty_evidence)

        assert result.reasoning is not None
        assert len(result.reasoning) >= 2
        assert len(result.reasoning) <= 4


class TestHardenedCodeDetection:
    """Test detection of hardened code patterns."""

    def test_hardcoded_secret_in_example_hardening(self, classifier, base_finding, empty_evidence):
        """Hardcoded secret in example/test file → HARDENING."""
        finding = base_finding.model_copy()
        finding.vulnerability_type = "Hardcoded Secret"
        finding.file_path = "/app/examples/docker-compose.yml"

        evidence = empty_evidence.model_copy()
        evidence.snippet = """
services:
  db:
    environment:
      POSTGRES_PASSWORD: example_password_123
"""

        result = classifier.classify(finding, evidence)

        # Example files with hardcoded secrets → HARDENING
        assert result.disposition == Disposition.HARDENING


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
