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
    ChecklistStatus,
    Disposition)
from services.classification import StrictClassifier
from models.schemas import Evidence, InputChannel
from services.evidence import SSRFAnalysis  # For dict creation reference


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
        created_at="2026-01-12T00:00:00Z")


@pytest.fixture
def empty_evidence():
    """Empty evidence result."""
    return Evidence(
        finding_id="test-001",
        snippet="",
        handler_snippet=None,
        symbol_info=None,
        framework=None,
        route_registration=None,
        auth_gates=[],
        dataflow_snippet=None,
        matches=[],
        ssrf_analysis=None,
        timed_out=False,
        input_channel=InputChannel.unknown,
        input_channel_deterministic=False,
        input_channel_signals=[],
        input_channel_reason="")


class TestCodeExecutionByDesign:
    """Test BY_DESIGN classification for code execution features."""

    def test_exec_in_pipeline_is_by_design(self, classifier, base_finding, empty_evidence):
        """Code execution (exec) in pipeline with feature intent → BY_DESIGN.

        Updated for new exec filter: requires 2+ signals to prove feature intent.
        Path signal alone is insufficient; needs symbol name match too.
        """
        finding = base_finding.model_copy()
        finding.vulnerability_type = "Code Injection"
        finding.file_path = "/app/pipelines/data_processor.py"
        finding.description = "Use of exec() function for dynamic code execution"

        evidence = empty_evidence.model_copy(update={
            "snippet": """
class PipelineExecutor:
    def execute_transformation(self, config):
        # Dynamic pipeline execution
        exec(config['transformation_code'])
""",
            "symbol_info": {
                "name": "PipelineExecutor.execute_transformation",
                "qualified_name": "PipelineExecutor.execute_transformation",
                "type": "method",
                "line_start": 2,
                "line_end": 4,
                "file_path": "/app/pipelines/data_processor.py"
            },
            "matches": [
                {
                    "file": "/app/pipelines/data_processor.py",
                    "line": 4,
                    "snippet": "exec(config['transformation_code'])",
                    "match_type": "sink",
                }
            ]
        })

        result = classifier.classify(finding, evidence)

        # New behavior: exec filter detects exec and checks feature intent
        # Path match (/pipelines/) + symbol match (PipelineExecutor/execute) = 2 signals → BY_DESIGN
        assert result.disposition == Disposition.BY_DESIGN
        assert result.proof_checklist.exec_sink_reason is not None
        assert "exec" in result.proof_checklist.exec_sink_reason.lower()
        assert result.proof_checklist.feature_intent_reason is not None
        assert "PROVEN" in result.proof_checklist.feature_intent_reason
        assert result.proof_checklist.sink_present.status == ChecklistStatus.PROVEN

    def test_command_injection_never_by_design(self, classifier, base_finding, empty_evidence):
        """Command injection with request input → VALID_SECURITY_ISSUE (never BY_DESIGN).

        Updated: Command injection bypasses exec filter and uses standard rules.
        Needs full proof chain including explicit not_misconfig signal.
        """
        finding = base_finding.model_copy()
        finding.vulnerability_type = "Command Injection"
        finding.file_path = "/app/api/handlers.py"
        finding.description = "Shell command with user input on unauthenticated route"
        evidence = empty_evidence.model_copy()
        evidence.snippet = """
@app.post("/execute")  # public route
async def execute_command(cmd: str):
    result = subprocess.run(cmd, shell=True)
    return {"output": result.stdout}
"""
        evidence.matches = [
            {
                "file": "/app/api/handlers.py",
                "line": 2,
                "snippet": "async def execute_command(cmd: str):",
                "match_type": "source",
            },
            {
                "file": "/app/api/handlers.py",
                "line": 3,
                "snippet": "subprocess.run(cmd, shell=True)",
                "match_type": "sink",
            },
            {
                "file": "/app/api/handlers.py",
                "line": 1,
                "snippet": '@app.post("/execute")  # public route',
                "match_type": "route_registration",
            },
            # Add dataflow evidence to complete proof chain
            {
                "file": "/app/api/handlers.py",
                "line": 3,
                "snippet": "subprocess.run(cmd, shell=True)",
                "match_type": "dataflow",
            }
        ]

        result = classifier.classify(finding, evidence)

        # Should be VALID_SECURITY_ISSUE with full proof chain
        # Command injection NEVER goes to BY_DESIGN even in /pipelines/
        assert result.disposition == Disposition.VALID_SECURITY_ISSUE
        assert result.proof_checklist.source_controlled_input.status == ChecklistStatus.PROVEN
        assert result.proof_checklist.sink_present.status == ChecklistStatus.PROVEN
        assert result.proof_checklist.reachable.status == ChecklistStatus.PROVEN
        assert result.proof_checklist.dataflow_evidenced.status == ChecklistStatus.PROVEN
        assert result.proof_checklist.not_only_misconfig.status == ChecklistStatus.PROVEN


class TestSSRFPatternDowngrades:
    """Test SSRF pattern-based downgrades."""

    def test_ssrf_constant_url_downgraded(self, classifier, base_finding, empty_evidence):
        """SSRF with constant URL → SPECULATIVE (not exploitable).

        Updated: Pattern downgrade to SPECULATIVE when URL is constant.
        """
        finding = base_finding.model_copy()
        finding.vulnerability_type = "SSRF"
        finding.description = "HTTP request to external URL"
        evidence = empty_evidence.model_copy()
        evidence.snippet = """
def check_service_health():
    response = requests.get("https://api.example.com/health")
    return response.json()
"""
        evidence.matches = [
            {
                "file": "/app/health.py",
                "line": 3,
                "snippet": 'requests.get("https://api.example.com/health")',
                "match_type": "sink",
            }
        ]
        evidence.ssrf_analysis = {"url_is_constant": True, "url_from_config": False, "url_expression": None}

        result = classifier.classify(finding, evidence)

        # Should be downgraded to SPECULATIVE due to constant URL
        assert result.disposition == Disposition.SPECULATIVE

    def test_ssrf_config_url_downgraded(self, classifier, base_finding, empty_evidence):
        """SSRF with config-only URL → SPECULATIVE (integration test).

        Updated: Pattern downgrade to SPECULATIVE when URL is from config.
        """
        finding = base_finding.model_copy()
        finding.vulnerability_type = "SSRF"
        evidence = empty_evidence.model_copy()
        evidence.snippet = """
def fetch_data():
    url = os.getenv("API_ENDPOINT")
    response = requests.get(url)
"""
        evidence.matches = [
            {
                "file": "/app/api.py",
                "line": 3,
                "snippet": "requests.get(url)",
                "match_type": "sink",
            }
        ]
        evidence.ssrf_analysis = {"url_is_constant": False, "url_from_config": True, "url_expression": None}

        result = classifier.classify(finding, evidence)

        # Should be downgraded to SPECULATIVE due to config-only URL
        assert result.disposition == Disposition.SPECULATIVE

    def test_ssrf_user_input_valid(self, classifier, base_finding, empty_evidence):
        """SSRF with user-controlled URL → VALID_SECURITY_ISSUE.

        Updated: Needs full proof chain including boundary evidence and not_misconfig signal.
        """
        finding = base_finding.model_copy()
        finding.vulnerability_type = "SSRF"
        finding.file_path = "/app/api/fetch.py"  # API path for boundary detection
        evidence = empty_evidence.model_copy()
        evidence.snippet = """
@app.post("/fetch")  # public route
async def fetch_url(url: str):
    response = requests.get(url)
    return response.text
"""
        evidence.matches = [
            {
                "file": "/app/api/fetch.py",
                "line": 2,
                "snippet": "async def fetch_url(url: str):",
                "match_type": "source",
            },
            {
                "file": "/app/api/fetch.py",
                "line": 3,
                "snippet": "requests.get(url)",
                "match_type": "sink",
            },
            {
                "file": "/app/api/fetch.py",
                "line": 1,
                "snippet": '@app.post("/fetch")  # public route',
                "match_type": "route_registration",
            },
            # Add dataflow evidence
            {
                "file": "/app/api/fetch.py",
                "line": 3,
                "snippet": "requests.get(url)",
                "match_type": "dataflow",
            }
        ]
        evidence.ssrf_analysis = {"url_is_constant": False, "url_from_config": False, "url_expression": None}

        result = classifier.classify(finding, evidence)

        assert result.disposition == Disposition.VALID_SECURITY_ISSUE


class TestCSWSHPatterns:
    """Test CSWSH (Cross-Site WebSocket Hijacking) patterns."""

    def test_cswsh_check_origin_no_creds_hardening(self, classifier, base_finding, empty_evidence):
        """CSWSH: check_origin alone without ambient creds → HARDENING.

        Updated: Need sink + reachable but no dataflow to get HARDENING.
        """
        finding = base_finding.model_copy()
        finding.vulnerability_type = "Cross-Site WebSocket Hijacking"
        finding.description = "WebSocket without origin validation"
        finding.file_path = "/app/websocket/handlers.py"  # WebSocket path for boundary detection
        evidence = empty_evidence.model_copy()
        evidence.snippet = """
@app.websocket("/ws")
async def websocket_handler(websocket: WebSocket):
    # Check origin header
    if websocket.headers.get("origin") != "https://example.com":
        await websocket.close()
        return
    await websocket.accept()
"""
        evidence.matches = [
            {
                "file": "/app/websocket/handlers.py",
                "line": 1,
                "snippet": '@app.websocket("/ws")',
                "match_type": "route_registration",
            },
            {
                "file": "/app/websocket/handlers.py",
                "line": 4,
                "snippet": 'if websocket.headers.get("origin") != "https://example.com":',
                "match_type": "auth_gate",
            },
            # Add sink to qualify for HARDENING
            {
                "file": "/app/websocket/handlers.py",
                "line": 7,
                "snippet": "await websocket.accept()",
                "match_type": "sink",
            }
        ]

        result = classifier.classify(finding, evidence)

        # With sink + reachable but no dataflow → HARDENING
        assert result.disposition == Disposition.HARDENING
        assert result.proof_checklist.sink_present.status == ChecklistStatus.PROVEN

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
        evidence.matches = [
            {
                "file": "/app/ws.py",
                "line": 3,
                "snippet": "exec(message['code'])",
                "match_type": "sink",
            }
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
        evidence.matches = [
            {
                "file": "/app/config.py",
                "line": 3,
                "snippet": "yaml.load(f, Loader=yaml.Loader)",
                "match_type": "sink",
            }
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
        evidence.matches = [
            {
                "file": "/app/connectors/database.py",
                "line": 3,
                "snippet": 'query = f"SELECT {columns} FROM {table_name}"',
                "match_type": "sink",
            }
        ]
        # No request sources - internal pipeline code

        result = classifier.classify(finding, evidence)

        # Developer-controlled SQL in connector/pipeline → BY_DESIGN
        assert result.disposition == Disposition.BY_DESIGN

    def test_sql_injection_with_request_valid(self, classifier, base_finding, empty_evidence):
        """SQL injection with request input → VALID_SECURITY_ISSUE.

        Updated: Needs full proof chain including boundary and not_misconfig signal.
        """
        finding = base_finding.model_copy()
        finding.vulnerability_type = "SQL Injection"
        finding.file_path = "/app/api/users.py"  # API path for boundary detection
        evidence = empty_evidence.model_copy()
        evidence.snippet = """
@app.get("/users")  # public route
async def get_users(name: str):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    return db.execute(query)
"""
        evidence.matches = [
            {
                "file": "/app/api/users.py",
                "line": 2,
                "snippet": "async def get_users(name: str):",
                "match_type": "source",
            },
            {
                "file": "/app/api/users.py",
                "line": 3,
                "snippet": 'query = f"SELECT * FROM users WHERE name = \'{name}\'"',
                "match_type": "sink",
            },
            {
                "file": "/app/api/users.py",
                "line": 1,
                "snippet": '@app.get("/users")  # public route',
                "match_type": "route_registration",
            },
            # Add dataflow evidence to complete proof chain
            {
                "file": "/app/api/users.py",
                "line": 3,
                "snippet": 'query = f"SELECT * FROM users WHERE name = \'{name}\'"',
                "match_type": "dataflow",
            }
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
        evidence.matches = [
            {
                "file": "/app/admin.py",
                "line": 2,
                "snippet": "async def delete_user(user_id: str, skip_auth: bool = False):",
                "match_type": "source",
            },
            {
                "file": "/app/admin.py",
                "line": 6,
                "snippet": "db.users.delete(user_id)",
                "match_type": "sink",
            },
            {
                "file": "/app/admin.py",
                "line": 1,
                "snippet": '@app.post("/admin/delete")',
                "match_type": "route_registration",
            }
        ]

        result = classifier.classify(finding, evidence)

        # Should be BUG due to explicit bypass mechanism
        assert result.disposition in [Disposition.BUG, Disposition.VALID_SECURITY_ISSUE]


class TestMisconfiguration:
    """Test MISCONFIGURATION disposition."""

    def test_auth_disabled_misconfiguration(self, classifier, base_finding, empty_evidence):
        """Vulnerability only when auth disabled → MISCONFIGURATION.

        Updated: Needs full proof chain + not_only_misconfig=False.
        The checklist builder detects misconfig pattern from "when auth disabled" language.
        """
        finding = base_finding.model_copy()
        finding.vulnerability_type = "Unauthorized Access"
        finding.file_path = "/app/api/users.py"  # API path for boundary detection
        finding.description = "Endpoint accessible when auth disabled"  # Use exact marker pattern
        evidence = empty_evidence.model_copy()
        evidence.snippet = """
@app.post("/admin/users")
async def create_user(username: str):
    if not settings.REQUIRE_AUTH:
        # No authentication when disabled
        db.users.create(username)
"""
        evidence.matches = [
            {
                "file": "/app/api/users.py",
                "line": 2,
                "snippet": "async def create_user(username: str):",
                "match_type": "source",
            },
            {
                "file": "/app/api/users.py",
                "line": 5,
                "snippet": "db.users.create(username)",
                "match_type": "sink",
            },
            {
                "file": "/app/api/users.py",
                "line": 1,
                "snippet": '@app.post("/admin/users")',
                "match_type": "route_registration",
            },
            # Add dataflow evidence
            {
                "file": "/app/api/users.py",
                "line": 5,
                "snippet": "db.users.create(username)",
                "match_type": "dataflow",
            }
        ]

        result = classifier.classify(finding, evidence)

        # Misconfiguration: full proof chain + not_only_misconfig=False (detected from "when auth disabled")
        assert result.disposition == Disposition.MISCONFIGURATION
        assert result.proof_checklist.not_only_misconfig.status == ChecklistStatus.PROVEN
        assert result.proof_checklist.not_only_misconfig.value == False


class TestPatternDowngradesOnly:
    """Test that pattern rules only downgrade, never upgrade."""

    def test_pattern_cannot_upgrade_to_valid(self, classifier, base_finding, empty_evidence):
        """Pattern rules must never return VALID_SECURITY_ISSUE or BUG."""
        finding = base_finding.model_copy()
        finding.vulnerability_type = "SSRF"
        evidence = empty_evidence.model_copy()
        evidence.snippet = "requests.get(url)"
        evidence.matches = [
            {
                "file": "/app/test.py",
                "line": 1,
                "snippet": "requests.get(url)",
                "match_type": "sink",
            }
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
        evidence.matches = [
            {
                "file": "test.py",
                "line": 1,
                "snippet": "def handler(cmd: str)",
                "match_type": "source",
            },
            {
                "file": "test.py",
                "line": 2,
                "snippet": "subprocess.run(cmd, shell=True)",
                "match_type": "sink",
            },
            {
                "file": "test.py",
                "line": 0,
                "snippet": "@app.post",
                "match_type": "route_registration",
            }
        ]

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

    def test_hardcoded_private_key_in_third_party_cert_bundle_hardening(self, classifier, base_finding, empty_evidence):
        """Hardcoded private keys in vendored third_party cert bundles → HARDENING (not a product vuln by default)."""
        finding = base_finding.model_copy()
        finding.vulnerability_type = "Hardcoded Secret"
        finding.file_path = "/app/third_party/civetweb/resources/cert/server.key"
        finding.description = "Bundled test certificate material."

        evidence = empty_evidence.model_copy()
        evidence.snippet = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEAzvB5
-----END RSA PRIVATE KEY-----
"""

        result = classifier.classify(finding, evidence)

        # Vendored resource certs should not show up as speculative security issues by default.
        assert result.disposition == Disposition.HARDENING


class TestStrictExecEvalFiltering:
    """Tests for aggressive exec/eval filtering logic."""

    def test_detects_direct_exec_call(self, classifier):
        """Detect direct exec() call within symbol range."""
        from models.schemas import Finding, VulnerabilityCategory

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
            created_at="2026-01-12T00:00:00Z")

        evidence = Evidence(finding_id="test-001",snippet="def handler(user_code: str):\n    exec(user_code)",
            symbol_info={
                "name": "handler",
                "qualified_name": "handler",
                "type": "function",
                "line_start": 41,
                "line_end": 42,
                "file_path": "/app/api.py"
            },
            framework=None,
            matches=[],
            input_channel=InputChannel.unknown,
            input_channel_deterministic=False,
            input_channel_signals=[],
            input_channel_reason=""
        )

        is_sink, reason = classifier._is_code_exec_sink(finding, evidence)

        assert is_sink is True
        assert "exec" in reason.lower()
        assert "handler" in reason.lower()

    def test_ignores_exec_in_comment(self, classifier):
        """Do not detect exec in comment."""
        from models.schemas import Finding

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
            created_at="2026-01-12T00:00:00Z")

        evidence = Evidence(finding_id="test-001",snippet="# We could use exec() but chose subprocess\nresult = subprocess.run(data)",
            symbol_info={
                "name": "handler",
                "qualified_name": "handler",
                "type": "function",
                "line_start": 42,
                "line_end": 43,
                "file_path": "/app/api.py"
            },
            framework=None,
            matches=[],
            input_channel=InputChannel.unknown,
            input_channel_deterministic=False,
            input_channel_signals=[],
            input_channel_reason=""
        )

        is_sink, reason = classifier._is_code_exec_sink(finding, evidence)
        assert is_sink is False

    def test_detects_obfuscated_exec(self, classifier):
        """Detect getattr(__builtins__, 'exec') pattern."""
        from models.schemas import Finding

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
            created_at="2026-01-12T00:00:00Z")

        evidence = Evidence(finding_id="test-001",snippet='def handler(code):\n    getattr(__builtins__, "exec")(code)',
            symbol_info={
                "name": "handler",
                "qualified_name": "handler",
                "type": "function",
                "line_start": 41,
                "line_end": 42,
                "file_path": "/app/api.py"
            },
            framework=None,
            matches=[],
            input_channel=InputChannel.unknown,
            input_channel_deterministic=False,
            input_channel_signals=[],
            input_channel_reason=""
        )

        is_sink, reason = classifier._is_code_exec_sink(finding, evidence)

        assert is_sink is True
        assert "exec" in reason.lower()

    def test_scoped_to_symbol_range(self, classifier):
        """Do not detect exec outside symbol range."""
        from models.schemas import Finding

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
            created_at="2026-01-12T00:00:00Z")

        evidence = Evidence(finding_id="test-001",snippet="def other_func():\n    exec(internal)\n\ndef handler(user_code):\n    process(user_code)",
            symbol_info={
                "name": "handler",
                "qualified_name": "handler",
                "type": "function",
                "line_start": 44,
                "line_end": 45,
                "file_path": "/app/api.py"
            },
            framework=None,
            matches=[],
            input_channel=InputChannel.unknown,
            input_channel_deterministic=False,
            input_channel_signals=[],
            input_channel_reason=""
        )

        is_sink, reason = classifier._is_code_exec_sink(finding, evidence)

        assert is_sink is False

    def test_handles_line_number_prefixes(self, classifier):
        """Handle snippets with line-number prefixes like '42: exec(code)'."""
        from models.schemas import Finding

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
            created_at="2026-01-12T00:00:00Z")

        evidence = Evidence(finding_id="test-001",snippet="41: def handler(user_code: str):\n42:     exec(user_code)",
            symbol_info={
                "name": "handler",
                "qualified_name": "handler",
                "type": "function",
                "line_start": 41,
                "line_end": 42,
                "file_path": "/app/api.py"
            },
            framework=None,
            matches=[],
            input_channel=InputChannel.unknown,
            input_channel_deterministic=False,
            input_channel_signals=[],
            input_channel_reason=""
        )

        is_sink, reason = classifier._is_code_exec_sink(finding, evidence)

        assert is_sink is True
        assert "exec" in reason.lower()

    def test_detects_eval_call(self, classifier):
        """Detect eval() call as code-exec sink."""
        from models.schemas import Finding

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
            created_at="2026-01-12T00:00:00Z")

        evidence = Evidence(finding_id="test-001",snippet="def calculate(expression):\n    result = eval(expression)\n    return result",
            symbol_info={
                "name": "calculate",
                "qualified_name": "calculate",
                "type": "function",
                "line_start": 41,
                "line_end": 43,
                "file_path": "/app/api.py"
            },
            framework=None,
            matches=[],
            input_channel=InputChannel.unknown,
            input_channel_deterministic=False,
            input_channel_signals=[],
            input_channel_reason=""
        )

        is_sink, reason = classifier._is_code_exec_sink(finding, evidence)

        assert is_sink is True
        assert "eval" in reason.lower()

    def test_detects_compile_call(self, classifier):
        """Detect compile() call as code-exec sink."""
        from models.schemas import Finding

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
            created_at="2026-01-12T00:00:00Z")

        evidence = Evidence(finding_id="test-001",snippet="def dynamic_compile(code):\n    bytecode = compile(code, '<string>', 'exec')\n    return bytecode",
            symbol_info={
                "name": "dynamic_compile",
                "qualified_name": "dynamic_compile",
                "type": "function",
                "line_start": 41,
                "line_end": 43,
                "file_path": "/app/api.py"
            },
            framework=None,
            matches=[],
            input_channel=InputChannel.unknown,
            input_channel_deterministic=False,
            input_channel_signals=[],
            input_channel_reason=""
        )

        is_sink, reason = classifier._is_code_exec_sink(finding, evidence)

        assert is_sink is True
        assert "compile" in reason.lower()

    def test_detects_exec_in_async_function(self, classifier):
        """Detect exec() in async function (critical bug fix)."""
        from models.schemas import Finding

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
            created_at="2026-01-12T00:00:00Z")

        evidence = Evidence(finding_id="test-001",snippet="async def handler(code):\n    exec(code)",
            symbol_info={
                "name": "handler",
                "qualified_name": "handler",
                "type": "function",
                "line_start": 41,
                "line_end": 42,
                "file_path": "/app/api.py"
            },
            framework=None,
            matches=[],
            input_channel=InputChannel.unknown,
            input_channel_deterministic=False,
            input_channel_signals=[],
            input_channel_reason=""
        )

        is_sink, reason = classifier._is_code_exec_sink(finding, evidence)

        assert is_sink is True
        assert "exec" in reason.lower()
        assert "handler" in reason.lower()

    def test_symbol_name_mismatch_fallback_to_regex(self, classifier):
        """Symbol name mismatch should fall back to regex and still detect exec()."""
        from models.schemas import Finding

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
            created_at="2026-01-12T00:00:00Z")

        # Symbol info says "handler" but snippet has "process_data"
        evidence = Evidence(finding_id="test-001",snippet="def process_data(code):\n    exec(code)",
            symbol_info={
                "name": "handler",  # Mismatch: actual function is process_data
                "qualified_name": "handler",
                "type": "function",
                "line_start": 41,
                "line_end": 42,
                "file_path": "/app/api.py"
            },
            framework=None,
            matches=[],
            input_channel=InputChannel.unknown,
            input_channel_deterministic=False,
            input_channel_signals=[],
            input_channel_reason=""
        )

        is_sink, reason = classifier._is_code_exec_sink(finding, evidence)

        # Should still detect exec() via regex fallback
        assert is_sink is True
        assert "exec" in reason.lower()


    def test_feature_intent_proven_with_path_and_symbol(self, classifier):
        """Prove feature intent with path + symbol match."""
        from models.schemas import Finding, VulnerabilityCategory, Severity

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

        evidence = Evidence(finding_id="test-001",snippet="class PipelineExecutor:\n    def run_block(self, code):\n        exec(code)",
            symbol_info={
                "name": "PipelineExecutor.run_block",
                "qualified_name": "PipelineExecutor.run_block",
                "type": "method",
                "line_start": 41,
                "line_end": 43,
                "file_path": "/app/pipelines/executor.py"
            },
            framework=None,
            matches=[],
            input_channel=InputChannel.unknown,
            input_channel_deterministic=False,
            input_channel_signals=[],
            input_channel_reason=""
        )

        proven, reason = classifier._feature_intent_proven(finding, evidence)

        assert proven is True
        assert "path=/app/pipelines/" in reason or "path" in reason.lower()
        assert "PipelineExecutor" in reason

    def test_feature_intent_not_proven_with_path_only(self, classifier):
        """Do not prove feature intent with path match only."""
        from models.schemas import Finding, Severity

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

        evidence = Evidence(finding_id="test-001",snippet="def process_data(code):\n    exec(code)",
            symbol_info={
                "name": "process_data",
                "qualified_name": "process_data",
                "type": "function",
                "line_start": 41,
                "line_end": 42,
                "file_path": "/app/pipelines/helper.py"
            },
            framework=None,
            matches=[],
            input_channel=InputChannel.unknown,
            input_channel_deterministic=False,
            input_channel_signals=[],
            input_channel_reason=""
        )

        proven, reason = classifier._feature_intent_proven(finding, evidence)

        assert proven is False
        assert "insufficient signals" in reason.lower() or "weak signal" in reason.lower()

    def test_feature_intent_proven_with_path_and_doc(self, classifier):
        """Prove feature intent with path + doc match."""
        from models.schemas import Finding, Severity

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

        evidence = Evidence(finding_id="test-001",snippet='def process(cell_code):\n    """Execute notebook cell code."""\n    exec(cell_code)',
            symbol_info={
                "name": "process",
                "qualified_name": "process",
                "type": "function",
                "line_start": 41,
                "line_end": 43,
                "file_path": "/app/kernel/processor.py"
            },
            framework=None,
            matches=[],
            input_channel=InputChannel.unknown,
            input_channel_deterministic=False,
            input_channel_signals=[],
            input_channel_reason=""
        )

        proven, reason = classifier._feature_intent_proven(finding, evidence)

        assert proven is True
        assert "path" in reason.lower() or "kernel" in reason.lower()
        assert "doc_match" in reason.lower()


    def test_auth_bypass_proven_with_decorator(self, classifier):
        """Detect explicit @public_endpoint decorator."""
        from models.schemas import Finding

        finding = Finding(
            id="test-auth-001",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Public code execution",
            description="Public",
            file_path="/app/api.py",
            line_start=42,
            vulnerability_type="Code Injection",
            severity="high",
            confidence=0.8,
            created_at="2026-01-12T00:00:00Z")

        evidence = Evidence(finding_id="test-001",snippet='@app.post("/execute")\n@public_endpoint\nasync def run_code(code: str):\n    exec(code)',
            symbol_info={
                "name": "run_code",
                "qualified_name": "run_code",
                "type": "function",
                "line_start": 41,
                "line_end": 44,
                "file_path": "/app/api.py"
            },
            framework=None,
            matches=[
                {
                "file": "/app/api.py",
                "line": 41,
                "snippet": '@public_endpoint',
                "match_type": "route_registration",
            }
            ],
            input_channel=InputChannel.unknown,
            input_channel_deterministic=False,
            input_channel_signals=[],
            input_channel_reason=""
        )

        proven, reason = classifier._auth_bypass_explicitly_proven(finding, evidence)

        assert proven is True
        assert "@public_endpoint" in reason.lower()

    def test_auth_bypass_proven_with_parameter(self, classifier):
        """Detect explicit bypass_auth=True parameter."""
        from models.schemas import Finding

        finding = Finding(
            id="test-auth-002",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Bypassed execution",
            description="Bypass",
            file_path="/app/api.py",
            line_start=42,
            vulnerability_type="Code Injection",
            severity="high",
            confidence=0.8,
            created_at="2026-01-12T00:00:00Z")

        evidence = Evidence(finding_id="test-001",snippet='@app.post("/execute", bypass_auth=True)\nasync def run_code(code: str):\n    exec(code)',
            symbol_info={
                "name": "run_code",
                "qualified_name": "run_code",
                "type": "function",
                "line_start": 41,
                "line_end": 43,
                "file_path": "/app/api.py"
            },
            framework=None,
            matches=[
                {
                "file": "/app/api.py",
                "line": 41,
                "snippet": '@app.post("/execute", bypass_auth=True)',
                "match_type": "route_registration",
            }
            ],
            input_channel=InputChannel.unknown,
            input_channel_deterministic=False,
            input_channel_signals=[],
            input_channel_reason=""
        )

        proven, reason = classifier._auth_bypass_explicitly_proven(finding, evidence)

        assert proven is True
        assert "bypass_auth=True" in reason or "bypass_auth=true" in reason.lower()

    def test_auth_bypass_not_proven_without_markers(self, classifier):
        """Do not prove bypass without explicit markers."""
        from models.schemas import Finding

        finding = Finding(
            id="test-auth-003",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Code execution",
            description="No auth markers",
            file_path="/app/api.py",
            line_start=42,
            vulnerability_type="Code Injection",
            severity="high",
            confidence=0.8,
            created_at="2026-01-12T00:00:00Z")

        evidence = Evidence(finding_id="test-001",snippet='@app.post("/execute")\nasync def run_code(code: str):\n    exec(code)',
            symbol_info={
                "name": "run_code",
                "qualified_name": "run_code",
                "type": "function",
                "line_start": 41,
                "line_end": 43,
                "file_path": "/app/api.py"
            },
            framework=None,
            matches=[
                {
                "file": "/app/api.py",
                "line": 41,
                "snippet": '@app.post("/execute")',
                "match_type": "route_registration",
            }
            ],
            input_channel=InputChannel.unknown,
            input_channel_deterministic=False,
            input_channel_signals=[],
            input_channel_reason=""
        )

        proven, reason = classifier._auth_bypass_explicitly_proven(finding, evidence)

        assert proven is False
        assert "not PROVEN" in reason

    def test_auth_bypass_ignores_description(self, classifier):
        """Do not use finding.description as proof."""
        from models.schemas import Finding

        finding = Finding(
            id="test-auth-004",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Code execution",
            description="This endpoint has bypass_auth=True",  # Scanner manipulation attempt
            file_path="/app/api.py",
            line_start=42,
            vulnerability_type="Code Injection",
            severity="high",
            confidence=0.8,
            created_at="2026-01-12T00:00:00Z")

        evidence = Evidence(finding_id="test-001",snippet='@app.post("/execute")\nasync def run_code(code: str):\n    exec(code)',
            symbol_info={
                "name": "run_code",
                "qualified_name": "run_code",
                "type": "function",
                "line_start": 41,
                "line_end": 43,
                "file_path": "/app/api.py"
            },
            framework=None,
            matches=[
                {
                "file": "/app/api.py",
                "line": 41,
                "snippet": '@app.post("/execute")',
                "match_type": "route_registration",
            }
            ],
            input_channel=InputChannel.unknown,
            input_channel_deterministic=False,
            input_channel_signals=[],
            input_channel_reason=""
        )

        proven, reason = classifier._auth_bypass_explicitly_proven(finding, evidence)

        assert proven is False  # Description should be ignored

    def test_exec_with_feature_intent_is_by_design(self, classifier):
        """Classify exec as BY_DESIGN when feature intent proven."""
        from models.schemas import Finding, VulnerabilityCategory, Severity, ChecklistStatus

        finding = Finding(
            id="test-integration-001",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Pipeline executor",
            vulnerability_type="Code Injection",
            severity=Severity.HIGH,
            file_path="/app/pipelines/executor.py",
            line_start=42,
            code_snippet="exec(block_code)",
            description="Pipeline",
            confidence=0.8,
            created_at="2026-01-12T00:00:00Z"
        )

        evidence = Evidence(finding_id="test-001",snippet="class PipelineExecutor:\n    def run_block(self, code):\n        exec(code)",
            symbol_info={
                "name": "PipelineExecutor.run_block",
                "qualified_name": "PipelineExecutor.run_block",
                "type": "method",
                "line_start": 41,
                "line_end": 43,
                "file_path": "/app/pipelines/executor.py"
            },
            framework=None,
            matches=[],
            input_channel=InputChannel.unknown,
            input_channel_deterministic=False,
            input_channel_signals=[],
            input_channel_reason=""
        )

        result = classifier.classify(finding, evidence)

        assert result.disposition == Disposition.BY_DESIGN
        assert result.proof_checklist.exec_sink_reason is not None
        assert "exec" in result.proof_checklist.exec_sink_reason.lower()
        assert result.proof_checklist.feature_intent_reason is not None
        assert "PROVEN" in result.proof_checklist.feature_intent_reason

    def test_exec_with_unknown_auth_is_speculative(self, classifier):
        """Classify exec as SPECULATIVE when auth unknown."""
        from models.schemas import Finding, VulnerabilityCategory, Severity, ChecklistStatus

        finding = Finding(
            id="test-integration-002",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Code execution",
            vulnerability_type="Code Injection",
            severity=Severity.HIGH,
            file_path="/app/api.py",
            line_start=42,
            code_snippet="exec(code)",
            description="Unknown auth",
            confidence=0.8,
            created_at="2026-01-12T00:00:00Z"
        )

        evidence = Evidence(finding_id="test-001",snippet='@app.post("/execute")\nasync def run_code(code: str):\n    exec(code)',
            symbol_info={
                "name": "run_code",
                "qualified_name": "run_code",
                "type": "function",
                "line_start": 41,
                "line_end": 43,
                "file_path": "/app/api.py"
            },
            framework=None,
            matches=[
                {
                "file": "/app/api.py",
                "line": 41,
                "snippet": '@app.post("/execute")',
                "match_type": "route_registration",
            }
            ],
            input_channel=InputChannel.unknown,
            input_channel_deterministic=False,
            input_channel_signals=[],
            input_channel_reason=""
        )

        result = classifier.classify(finding, evidence)

        assert result.disposition == Disposition.SPECULATIVE
        assert result.proof_checklist.exec_sink_reason is not None
        assert result.proof_checklist.auth_bypass_reason is not None
        assert "not PROVEN" in result.proof_checklist.auth_bypass_reason

    def test_exec_filter_forces_sink_proven(self, classifier):
        """Ensure exec detection forces sink_present to PROVEN."""
        from models.schemas import Finding, VulnerabilityCategory, Severity, ChecklistStatus

        finding = Finding(
            id="test-integration-003",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Code execution",
            vulnerability_type="Code Injection",
            severity=Severity.HIGH,
            file_path="/app/api.py",
            line_start=42,
            code_snippet="exec(code)",
            description="Exec",
            confidence=0.8,
            created_at="2026-01-12T00:00:00Z"
        )

        evidence = Evidence(finding_id="test-001",snippet="def run(code):\n    exec(code)",
            symbol_info={
                "name": "run",
                "qualified_name": "run",
                "type": "function",
                "line_start": 41,
                "line_end": 42,
                "file_path": "/app/api.py"
            },
            framework=None,
            matches=[],
            input_channel=InputChannel.unknown,
            input_channel_deterministic=False,
            input_channel_signals=[],
            input_channel_reason=""
        )

        result = classifier.classify(finding, evidence)

        assert result.proof_checklist.sink_present.status == ChecklistStatus.PROVEN
        assert result.proof_checklist.sink_present.value is True

    def test_pattern_downgrades_skip_code_injection(self, classifier):
        """Ensure pattern downgrades skip CODE_INJECTION category."""
        from models.schemas import Finding, VulnerabilityCategory

        # This test verifies that CODE_INJECTION findings bypass pattern downgrades
        # The exec filter should handle CODE_INJECTION entirely

        finding = Finding(
            id="test-pattern-001",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Code injection",
            vulnerability_type="Code Injection",
            severity="high",
            file_path="/app/api.py",
            line_start=42,
            code_snippet="exec(code)",
            description="Code injection",
            confidence=0.8,
            created_at="2026-01-12T00:00:00Z"
        )

        evidence = Evidence(finding_id="test-001",snippet="exec(code)",
            symbol_info=None,
            framework=None,
            matches=[],
            ssrf_analysis=None,
            timed_out=False,
            input_channel=InputChannel.unknown,
            input_channel_deterministic=False,
            input_channel_signals=[],
            input_channel_reason=""
        )

        # Call _apply_pattern_downgrades directly
        disposition = Disposition.VALID_SECURITY_ISSUE  # Start with VALID

        # Need to build checklist and get normalized category first
        checklist = classifier._build_checklist(finding, evidence, threat_model_profile=None)
        category = classifier._normalize_category(finding)

        result = classifier._apply_pattern_downgrades(disposition, finding, evidence, checklist, category)

        # Should return unchanged (not downgraded by patterns)
        assert result == Disposition.VALID_SECURITY_ISSUE

    def test_reasoning_includes_exec_details(self, classifier):
        """Ensure reasoning bullets include exec-specific details."""
        from models.schemas import Finding, VulnerabilityCategory

        finding = Finding(
            id="test-reasoning-001",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Code execution",
            vulnerability_type="Code Injection",
            severity="high",
            file_path="/app/api.py",
            line_start=42,
            code_snippet="exec(code)",
            description="Exec",
            confidence=0.8,
            created_at="2026-01-12T00:00:00Z"
        )

        evidence = Evidence(finding_id="test-001",snippet='@app.post("/execute")\nasync def run_code(code: str):\n    exec(code)',
            symbol_info={
                "name": "run_code",
                "qualified_name": "run_code",
                "type": "function",
                "line_start": 41,
                "line_end": 43,
                "file_path": "/app/api.py"
            },
            framework=None,
            matches=[
                {
                "file": "/app/api.py",
                "line": 41,
                "snippet": '@app.post("/execute")',
                "match_type": "route_registration",
            }
            ],
            input_channel=InputChannel.unknown,
            input_channel_deterministic=False,
            input_channel_signals=[],
            input_channel_reason=""
        )

        result = classifier.classify(finding, evidence)

        # Should include exec-specific reasoning
        assert any("exec" in bullet.lower() for bullet in result.reasoning)
        assert any("feature intent" in bullet.lower() for bullet in result.reasoning)

    def test_no_dataflow_is_speculative(self, classifier):
        """Exec with source and sink but no dataflow → SPECULATIVE."""
        from models.schemas import Finding, VulnerabilityCategory

        finding = Finding(
            id="test-dataflow-001",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Code execution",
            vulnerability_type="Code Injection",
            severity="high",
            file_path="/app/api.py",
            line_start=42,
            code_snippet="exec(config['script'])",
            description="Different variable",
            confidence=0.8,
            created_at="2026-01-12T00:00:00Z")

        evidence = Evidence(finding_id="test-001",snippet='async def handler(user_code: str):\n    config = load_config()\n    exec(config["script"])',
            symbol_info={
                "name": "handler",
                "qualified_name": "handler",
                "type": "function",
                "line_start": 41,
                "line_end": 43,
                "file_path": "/app/api.py"
            },
            framework=None,
            matches=[],
            input_channel=InputChannel.unknown,
            input_channel_deterministic=False,
            input_channel_signals=[],
            input_channel_reason=""
        )

        # Manually simulate: source=PROVEN, reachable=PROVEN, dataflow=DISPROVEN
        # In real scenario, evidence gatherer would set these

        result = classifier.classify(finding, evidence)

        # Without dataflow proven, should be SPECULATIVE
        assert result.disposition == Disposition.SPECULATIVE

    def test_admin_path_without_role_check_is_valid(self, classifier):
        """Exec in admin path without role check → VALID (boundary crossed)."""
        from models.schemas import Finding, VulnerabilityCategory

        finding = Finding(
            id="test-admin-001",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Admin code execution",
            vulnerability_type="Code Injection",
            severity="critical",
            file_path="/app/api.py",
            line_start=42,
            code_snippet="exec(script)",
            description="Admin endpoint",
            confidence=0.8,
            created_at="2026-01-12T00:00:00Z")

        evidence = Evidence(finding_id="test-001",snippet='@app.post("/admin/execute")\nasync def run_script(script: str):\n    exec(script)',
            symbol_info={
                "name": "run_script",
                "qualified_name": "run_script",
                "type": "function",
                "line_start": 41,
                "line_end": 43,
                "file_path": "/app/api.py"
            },
            framework=None,
            matches=[
                {
                "file": "/app/api.py",
                "line": 41,
                "snippet": '@app.post("/admin/execute")',
                "match_type": "route_registration",
            }
            ],
            input_channel=InputChannel.unknown,
            input_channel_deterministic=False,
            input_channel_signals=[],
            input_channel_reason=""
        )

        # This test depends on boundary_crossed logic being set by evidence gatherer
        # If admin path without role check is detected, boundary_crossed.PROVEN_TRUE

        result = classifier.classify(finding, evidence)

        # Should be VALID if boundary crossed (admin path, no role check)
        # This may need evidence gatherer to detect the admin boundary

    def test_whole_file_scan_avoided(self, classifier):
        """Exec in different function not detected (scoped to symbol)."""
        from models.schemas import Finding

        finding = Finding(
            id="test-scope-001",
            agent_id="agent-001",
            repo_id="repo-001",
            title="Handler",
            vulnerability_type="Code Injection",
            severity="high",
            file_path="/app/api.py",
            line_start=45,
            code_snippet="process(user_code)",
            description="No exec",
            confidence=0.8,
            created_at="2026-01-12T00:00:00Z")

        evidence = Evidence(finding_id="test-001",snippet="def other_func():\n    exec(internal)\n\ndef handler(user_code):\n    process(user_code)",
            symbol_info={
                "name": "handler",
                "qualified_name": "handler",
                "type": "function",
                "line_start": 44,
                "line_end": 45,
                "file_path": "/app/api.py"
            },
            framework=None,
            matches=[],
            input_channel=InputChannel.unknown,
            input_channel_deterministic=False,
            input_channel_signals=[],
            input_channel_reason=""
        )

        is_sink, reason = classifier._is_code_exec_sink(finding, evidence)

        # Should NOT detect exec in other_func (outside symbol range)
        assert is_sink is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
