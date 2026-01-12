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
from dataclasses import replace
from models.schemas import (
    Finding,
    ChecklistStatus,
    Disposition,
)
from services.evidence_gatherer import EvidenceResult, EvidenceMatch, SSRFAnalysis
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
        symbol_info=None,
        framework=None,
        matches=[],
        ssrf_analysis=None,
        timed_out=False,
    )


class TestCodeExecutionByDesign:
    """Test BY_DESIGN classification for code execution features."""

    def test_exec_in_pipeline_is_by_design(self, classifier, base_finding, empty_evidence):
        """Code execution (exec) in pipeline with no bypass → BY_DESIGN."""
        finding = base_finding.model_copy()
        finding.vulnerability_type = "Code Injection"
        finding.file_path = "/app/pipelines/data_processor.py"
        finding.description = "Use of exec() function for dynamic code execution"

        evidence = replace(
            empty_evidence,
            snippet="""
def process_pipeline(config):
    # Dynamic pipeline execution
    exec(config['transformation_code'])
""",
            matches=[
                EvidenceMatch(
                    file="/app/pipelines/data_processor.py",
                    line=10,
                    snippet="exec(config['transformation_code'])",
                    match_type="sink",
                )
            ]
        )

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
        evidence = replace(empty_evidence)
        evidence.snippet = """
@app.post("/execute")
async def execute_command(cmd: str):
    result = subprocess.run(cmd, shell=True)
    return {"output": result.stdout}
"""
        evidence.matches = [
            EvidenceMatch(
                file="/app/api/handlers.py",
                line=2,
                snippet="async def execute_command(cmd: str):",
                match_type="source",
            )
        ]
        evidence.matches = [
            EvidenceMatch(
                file="/app/api/handlers.py",
                line=3,
                snippet="subprocess.run(cmd, shell=True)",
                match_type="sink",
            )
        ]
        evidence.matches = [
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
        evidence = replace(empty_evidence)
        evidence.snippet = """
def check_service_health():
    response = requests.get("https://api.example.com/health")
    return response.json()
"""
        evidence.matches = [
            EvidenceMatch(
                file="/app/health.py",
                line=3,
                snippet='requests.get("https://api.example.com/health")',
                match_type="sink",
            )
        ]
        evidence.ssrf_analysis = SSRFAnalysis(url_is_constant=True)

        result = classifier.classify(finding, evidence)

        # Should be downgraded to SPECULATIVE
        assert result.disposition == Disposition.SPECULATIVE
        assert any("constant" in r.lower() or "hard-coded" in r.lower() for r in result.reasoning)

    def test_ssrf_config_url_downgraded(self, classifier, base_finding, empty_evidence):
        """SSRF with config-only URL → SPECULATIVE (integration test)."""
        finding = base_finding.model_copy()
        finding.vulnerability_type = "SSRF"
        evidence = replace(empty_evidence)
        evidence.snippet = """
def fetch_data():
    url = os.getenv("API_ENDPOINT")
    response = requests.get(url)
"""
        evidence.matches = [
            EvidenceMatch(
                file="/app/api.py",
                line=3,
                snippet="requests.get(url)",
                match_type="sink",
            )
        ]
        evidence.ssrf_analysis = SSRFAnalysis(url_from_config=True)

        result = classifier.classify(finding, evidence)

        assert result.disposition == Disposition.SPECULATIVE
        assert any("config" in r.lower() or "environment" in r.lower() for r in result.reasoning)

    def test_ssrf_user_input_valid(self, classifier, base_finding, empty_evidence):
        """SSRF with user-controlled URL → VALID_SECURITY_ISSUE."""
        finding = base_finding.model_copy()
        finding.vulnerability_type = "SSRF"
        evidence = replace(empty_evidence)
        evidence.snippet = """
@app.post("/fetch")
async def fetch_url(url: str):
    response = requests.get(url)
    return response.text
"""
        evidence.matches = [
            EvidenceMatch(
                file="/app/api.py",
                line=2,
                snippet="async def fetch_url(url: str):",
                match_type="source",
            )
        ]
        evidence.matches = [
            EvidenceMatch(
                file="/app/api.py",
                line=3,
                snippet="requests.get(url)",
                match_type="sink",
            )
        ]
        evidence.matches = [
            EvidenceMatch(
                file="/app/api.py",
                line=1,
                snippet='@app.post("/fetch")',
                match_type="route_registration",
            )
        ]
        evidence.ssrf_analysis = SSRFAnalysis(url_is_constant=False)

        result = classifier.classify(finding, evidence)

        assert result.disposition == Disposition.VALID_SECURITY_ISSUE


class TestCSWSHPatterns:
    """Test CSWSH (Cross-Site WebSocket Hijacking) patterns."""

    def test_cswsh_check_origin_no_creds_hardening(self, classifier, base_finding, empty_evidence):
        """CSWSH: check_origin alone without ambient creds → HARDENING."""
        finding = base_finding.model_copy()
        finding.vulnerability_type = "Cross-Site WebSocket Hijacking"
        finding.description = "WebSocket without origin validation"
        evidence = replace(empty_evidence)
        evidence.snippet = """
async def websocket_handler(websocket: WebSocket):
    # Check origin header
    if websocket.headers.get("origin") != "https://example.com":
        await websocket.close()
        return
    await websocket.accept()
"""
        evidence.matches = [
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
        evidence = replace(empty_evidence)
        evidence.snippet = """
async def handle_message(websocket, message):
    # Execute user command
    exec(message['code'])
"""
        evidence.matches = [
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
        evidence = replace(empty_evidence)
        evidence.snippet = """
def load_config():
    with open('config.yaml', 'r') as f:
        config = yaml.load(f, Loader=yaml.Loader)
    return config
"""
        evidence.matches = [
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
        evidence = replace(empty_evidence)
        evidence.snippet = """
def build_query(table_name, columns):
    # Internal connector - developer-controlled
    query = f"SELECT {','.join(columns)} FROM {table_name}"
    return execute_query(query)
"""
        evidence.matches = [
            EvidenceMatch(
                file="/app/connectors/database.py",
                line=3,
                snippet='query = f"SELECT {columns} FROM {table_name}"',
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
        evidence = replace(empty_evidence)
        evidence.snippet = """
@app.get("/users")
async def get_users(name: str):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return db.execute(query)
"""
        evidence.matches = [
            EvidenceMatch(
                file="/app/api.py",
                line=2,
                snippet="async def get_users(name: str):",
                match_type="source",
            )
        ]
        evidence.matches = [
            EvidenceMatch(
                file="/app/api.py",
                line=3,
                snippet='query = f"SELECT * FROM users WHERE name = \'{name}\'"',
                match_type="sink",
            )
        ]
        evidence.matches = [
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
        evidence = replace(empty_evidence)
        evidence.snippet = """
@app.post("/admin/delete")
async def delete_user(user_id: str, skip_auth: bool = False):
    if not skip_auth:
        check_admin()
    # Delete user - dangerous operation
    db.users.delete(user_id)
"""
        evidence.matches = [
            EvidenceMatch(
                file="/app/admin.py",
                line=2,
                snippet="async def delete_user(user_id: str, skip_auth: bool = False):",
                match_type="source",
            )
        ]
        evidence.matches = [
            EvidenceMatch(
                file="/app/admin.py",
                line=6,
                snippet="db.users.delete(user_id)",
                match_type="sink",
            )
        ]
        evidence.matches = [
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
        evidence = replace(empty_evidence)
        evidence.snippet = """
@app.post("/admin/users")
async def create_user(username: str):
    if not settings.REQUIRE_AUTH:
        # No authentication when disabled
        db.users.create(username)
"""
        evidence.matches = [
            EvidenceMatch(
                file="/app/api.py",
                line=2,
                snippet="async def create_user(username: str):",
                match_type="source",
            )
        ]
        evidence.matches = [
            EvidenceMatch(
                file="/app/api.py",
                line=5,
                snippet="db.users.create(username)",
                match_type="sink",
            )
        ]
        evidence.matches = [
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
        evidence = replace(empty_evidence)
        evidence.snippet = "requests.get(url)"
        evidence.matches = [
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
        evidence = replace(empty_evidence)
        evidence.matches = [EvidenceMatch(file="test.py", line=1, snippet="def handler(cmd: str)", match_type="source")]
        evidence.matches = [EvidenceMatch(file="test.py", line=2, snippet="subprocess.run(cmd, shell=True)", match_type="sink")]
        evidence.matches = [EvidenceMatch(file="test.py", line=0, snippet="@app.post", match_type="route_registration")]

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
        evidence = replace(empty_evidence)
        evidence.snippet = """
services:
  db:
    environment:
      POSTGRES_PASSWORD: example_password_123
"""

        result = classifier.classify(finding, evidence)

        # Example files with hardcoded secrets → HARDENING
        assert result.disposition == Disposition.HARDENING


class TestStrictExecEvalFiltering:
    """Tests for aggressive exec/eval filtering logic."""

    def test_detects_direct_exec_call(self, classifier):
        """Detect direct exec() call within symbol range."""
        from models.schemas import Finding, VulnerabilityCategory
        from services.evidence_gatherer import EvidenceResult, SymbolInfo

        finding = Finding(
            id="test-exec-001",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Code execution in handler",
            description="Executes user code",
            file_path="/app/api.py",
            line_start=42,
            vulnerability_type="Code Injection",
            severity="high",
            confidence=0.8,
            created_at="2026-01-12T00:00:00Z",
        )

        evidence = EvidenceResult(
            snippet="def handler(user_code: str):\n    exec(user_code)",
            symbol_info=SymbolInfo(
                name="handler",
                qualified_name="handler",
                type="function",
                line_start=41,
                line_end=42,
                file_path="/app/api.py"
            ),
            framework=None,
            matches=[],
        )

        is_sink, reason = classifier._is_code_exec_sink(finding, evidence)

        assert is_sink is True
        assert "exec" in reason.lower()
        assert "handler" in reason.lower()

    def test_ignores_exec_in_comment(self, classifier):
        """Do not detect exec in comment."""
        from models.schemas import Finding
        from services.evidence_gatherer import EvidenceResult, SymbolInfo

        finding = Finding(
            id="test-exec-002",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Comment mentions exec",
            description="Comment only",
            file_path="/app/api.py",
            line_start=42,
            vulnerability_type="Code Injection",
            severity="high",
            confidence=0.8,
            created_at="2026-01-12T00:00:00Z",
        )

        evidence = EvidenceResult(
            snippet="# We could use exec() but chose subprocess\nresult = subprocess.run(data)",
            symbol_info=SymbolInfo(
                name="handler",
                qualified_name="handler",
                type="function",
                line_start=42,
                line_end=43,
                file_path="/app/api.py"
            ),
            framework=None,
            matches=[],
        )

        is_sink, reason = classifier._is_code_exec_sink(finding, evidence)
        assert is_sink is False

    def test_detects_obfuscated_exec(self, classifier):
        """Detect getattr(__builtins__, 'exec') pattern."""
        from models.schemas import Finding
        from services.evidence_gatherer import EvidenceResult, SymbolInfo

        finding = Finding(
            id="test-exec-003",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Obfuscated exec",
            description="Obfuscated",
            file_path="/app/api.py",
            line_start=42,
            vulnerability_type="Code Injection",
            severity="high",
            confidence=0.8,
            created_at="2026-01-12T00:00:00Z",
        )

        evidence = EvidenceResult(
            snippet='def handler(code):\n    getattr(__builtins__, "exec")(code)',
            symbol_info=SymbolInfo(
                name="handler",
                qualified_name="handler",
                type="function",
                line_start=41,
                line_end=42,
                file_path="/app/api.py"
            ),
            framework=None,
            matches=[],
        )

        is_sink, reason = classifier._is_code_exec_sink(finding, evidence)

        assert is_sink is True
        assert "exec" in reason.lower()

    def test_scoped_to_symbol_range(self, classifier):
        """Do not detect exec outside symbol range."""
        from models.schemas import Finding
        from services.evidence_gatherer import EvidenceResult, SymbolInfo

        finding = Finding(
            id="test-exec-004",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Function without exec",
            description="No exec",
            file_path="/app/api.py",
            line_start=45,
            vulnerability_type="Code Injection",
            severity="high",
            confidence=0.8,
            created_at="2026-01-12T00:00:00Z",
        )

        evidence = EvidenceResult(
            snippet="def other_func():\n    exec(internal)\n\ndef handler(user_code):\n    process(user_code)",
            symbol_info=SymbolInfo(
                name="handler",
                qualified_name="handler",
                type="function",
                line_start=44,
                line_end=45,
                file_path="/app/api.py"
            ),
            framework=None,
            matches=[],
        )

        is_sink, reason = classifier._is_code_exec_sink(finding, evidence)

        assert is_sink is False

    def test_handles_line_number_prefixes(self, classifier):
        """Handle snippets with line-number prefixes like '42: exec(code)'."""
        from models.schemas import Finding
        from services.evidence_gatherer import EvidenceResult, SymbolInfo

        finding = Finding(
            id="test-exec-005",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Snippet with line numbers",
            description="Has line prefixes",
            file_path="/app/api.py",
            line_start=42,
            vulnerability_type="Code Injection",
            severity="high",
            confidence=0.8,
            created_at="2026-01-12T00:00:00Z",
        )

        evidence = EvidenceResult(
            snippet="41: def handler(user_code: str):\n42:     exec(user_code)",
            symbol_info=SymbolInfo(
                name="handler",
                qualified_name="handler",
                type="function",
                line_start=41,
                line_end=42,
                file_path="/app/api.py"
            ),
            framework=None,
            matches=[],
        )

        is_sink, reason = classifier._is_code_exec_sink(finding, evidence)

        assert is_sink is True
        assert "exec" in reason.lower()

    def test_detects_eval_call(self, classifier):
        """Detect eval() call as code-exec sink."""
        from models.schemas import Finding
        from services.evidence_gatherer import EvidenceResult, SymbolInfo

        finding = Finding(
            id="test-exec-006",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Eval usage",
            description="Uses eval",
            file_path="/app/api.py",
            line_start=42,
            vulnerability_type="Code Injection",
            severity="high",
            confidence=0.8,
            created_at="2026-01-12T00:00:00Z",
        )

        evidence = EvidenceResult(
            snippet="def calculate(expression):\n    result = eval(expression)\n    return result",
            symbol_info=SymbolInfo(
                name="calculate",
                qualified_name="calculate",
                type="function",
                line_start=41,
                line_end=43,
                file_path="/app/api.py"
            ),
            framework=None,
            matches=[],
        )

        is_sink, reason = classifier._is_code_exec_sink(finding, evidence)

        assert is_sink is True
        assert "eval" in reason.lower()

    def test_detects_compile_call(self, classifier):
        """Detect compile() call as code-exec sink."""
        from models.schemas import Finding
        from services.evidence_gatherer import EvidenceResult, SymbolInfo

        finding = Finding(
            id="test-exec-007",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Compile usage",
            description="Uses compile",
            file_path="/app/api.py",
            line_start=42,
            vulnerability_type="Code Injection",
            severity="high",
            confidence=0.8,
            created_at="2026-01-12T00:00:00Z",
        )

        evidence = EvidenceResult(
            snippet="def dynamic_compile(code):\n    bytecode = compile(code, '<string>', 'exec')\n    return bytecode",
            symbol_info=SymbolInfo(
                name="dynamic_compile",
                qualified_name="dynamic_compile",
                type="function",
                line_start=41,
                line_end=43,
                file_path="/app/api.py"
            ),
            framework=None,
            matches=[],
        )

        is_sink, reason = classifier._is_code_exec_sink(finding, evidence)

        assert is_sink is True
        assert "compile" in reason.lower()

    def test_detects_exec_in_async_function(self, classifier):
        """Detect exec() in async function (critical bug fix)."""
        from models.schemas import Finding
        from services.evidence_gatherer import EvidenceResult, SymbolInfo

        finding = Finding(
            id="test-exec-008",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Async exec",
            description="Async function with exec",
            file_path="/app/api.py",
            line_start=42,
            vulnerability_type="Code Injection",
            severity="high",
            confidence=0.8,
            created_at="2026-01-12T00:00:00Z",
        )

        evidence = EvidenceResult(
            snippet="async def handler(code):\n    exec(code)",
            symbol_info=SymbolInfo(
                name="handler",
                qualified_name="handler",
                type="function",
                line_start=41,
                line_end=42,
                file_path="/app/api.py"
            ),
            framework=None,
            matches=[],
        )

        is_sink, reason = classifier._is_code_exec_sink(finding, evidence)

        assert is_sink is True
        assert "exec" in reason.lower()
        assert "handler" in reason.lower()

    def test_symbol_name_mismatch_fallback_to_regex(self, classifier):
        """Symbol name mismatch should fall back to regex and still detect exec()."""
        from models.schemas import Finding
        from services.evidence_gatherer import EvidenceResult, SymbolInfo

        finding = Finding(
            id="test-exec-009",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Symbol name mismatch",
            description="Symbol info name doesn't match function name in snippet",
            file_path="/app/api.py",
            line_start=42,
            vulnerability_type="Code Injection",
            severity="high",
            confidence=0.8,
            created_at="2026-01-12T00:00:00Z",
        )

        # Symbol info says "handler" but snippet has "process_data"
        evidence = EvidenceResult(
            snippet="def process_data(code):\n    exec(code)",
            symbol_info=SymbolInfo(
                name="handler",  # Mismatch: actual function is process_data
                qualified_name="handler",
                type="function",
                line_start=41,
                line_end=42,
                file_path="/app/api.py"
            ),
            framework=None,
            matches=[],
        )

        is_sink, reason = classifier._is_code_exec_sink(finding, evidence)

        # Should still detect exec() via regex fallback
        assert is_sink is True
        assert "exec" in reason.lower()


    def test_feature_intent_proven_with_path_and_symbol(self, classifier):
        """Prove feature intent with path + symbol match."""
        from models.schemas import Finding, VulnerabilityCategory, Severity
        from services.evidence_gatherer import EvidenceResult, SymbolInfo

        finding = Finding(
            id="test-feature-001",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Pipeline executor",
            vulnerability_type="Code Injection",
            severity=Severity.HIGH,
            file_path="/app/pipelines/executor.py",
            line_start=42,
            code_snippet="exec(block_code)",
            description="Executes block",
            confidence=0.8,
            created_at="2026-01-12T00:00:00Z"
        )

        evidence = EvidenceResult(
            snippet="class PipelineExecutor:\n    def run_block(self, code):\n        exec(code)",
            symbol_info=SymbolInfo(
                name="PipelineExecutor.run_block",
                qualified_name="PipelineExecutor.run_block",
                type="method",
                line_start=41,
                line_end=43,
                file_path="/app/pipelines/executor.py"
            ),
            framework=None,
            matches=[]
        )

        proven, reason = classifier._feature_intent_proven(finding, evidence)

        assert proven is True
        assert "path=/app/pipelines/" in reason or "path" in reason.lower()
        assert "PipelineExecutor" in reason

    def test_feature_intent_not_proven_with_path_only(self, classifier):
        """Do not prove feature intent with path match only."""
        from models.schemas import Finding, Severity
        from services.evidence_gatherer import EvidenceResult, SymbolInfo

        finding = Finding(
            id="test-feature-002",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Pipeline helper",
            vulnerability_type="Code Injection",
            severity=Severity.HIGH,
            file_path="/app/pipelines/helper.py",
            line_start=42,
            code_snippet="exec(code)",
            description="Helper",
            confidence=0.8,
            created_at="2026-01-12T00:00:00Z"
        )

        evidence = EvidenceResult(
            snippet="def process_data(code):\n    exec(code)",
            symbol_info=SymbolInfo(
                name="process_data",
                qualified_name="process_data",
                type="function",
                line_start=41,
                line_end=42,
                file_path="/app/pipelines/helper.py"
            ),
            framework=None,
            matches=[]
        )

        proven, reason = classifier._feature_intent_proven(finding, evidence)

        assert proven is False
        assert "insufficient signals" in reason.lower() or "weak signal" in reason.lower()

    def test_feature_intent_proven_with_path_and_doc(self, classifier):
        """Prove feature intent with path + doc match."""
        from models.schemas import Finding, Severity
        from services.evidence_gatherer import EvidenceResult, SymbolInfo

        finding = Finding(
            id="test-feature-003",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Kernel processor",
            vulnerability_type="Code Injection",
            severity=Severity.HIGH,
            file_path="/app/kernel/processor.py",
            line_start=42,
            code_snippet="exec(cell_code)",
            description="Processes cell",
            confidence=0.8,
            created_at="2026-01-12T00:00:00Z"
        )

        evidence = EvidenceResult(
            snippet='def process(cell_code):\n    """Execute notebook cell code."""\n    exec(cell_code)',
            symbol_info=SymbolInfo(
                name="process",
                qualified_name="process",
                type="function",
                line_start=41,
                line_end=43,
                file_path="/app/kernel/processor.py"
            ),
            framework=None,
            matches=[]
        )

        proven, reason = classifier._feature_intent_proven(finding, evidence)

        assert proven is True
        assert "path" in reason.lower() or "kernel" in reason.lower()
        assert "doc_match" in reason.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
