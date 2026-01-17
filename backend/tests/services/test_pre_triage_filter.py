"""Tests for pre-triage filtering."""
import pytest
from models.schemas import Finding, TriagePolicy, PathClassification, Severity
from services.pre_triage_filter import pre_filter_findings
from datetime import datetime


class TestPreFilterFindings:
    def test_filters_third_party_findings(self):
        """Test third_party findings are filtered when policy enabled."""
        policy = TriagePolicy(
            name="test_policy",
            filter_third_party=True
        )

        findings = [
            Finding(
                id="1",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                title="Finding in third party",
                description="Test",
                file_path="third_party/lib.py",
                line_start=10,
                vulnerability_type="sql_injection",
                confidence=0.9,
                created_at=datetime.utcnow()
            ),
            Finding(
                id="2",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                title="Finding in src",
                description="Test",
                file_path="src/main.py",
                line_start=20,
                vulnerability_type="sql_injection",
                confidence=0.9,
                created_at=datetime.utcnow()
            )
        ]

        filtered = pre_filter_findings(findings, policy)

        assert len(filtered) == 1
        assert filtered[0].file_path == "src/main.py"
        assert filtered[0].path_classification == PathClassification.runtime

    def test_filters_test_findings(self):
        """Test test findings are filtered when policy enabled."""
        policy = TriagePolicy(
            name="test_policy",
            filter_tests=True
        )

        findings = [
            Finding(
                id="1",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                title="Finding in test",
                description="Test",
                file_path="test/test_main.py",
                line_start=10,
                vulnerability_type="sql_injection",
                confidence=0.9,
                created_at=datetime.utcnow()
            ),
            Finding(
                id="2",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                title="Finding in src",
                description="Test",
                file_path="src/main.py",
                line_start=20,
                vulnerability_type="sql_injection",
                confidence=0.9,
                created_at=datetime.utcnow()
            )
        ]

        filtered = pre_filter_findings(findings, policy)

        assert len(filtered) == 1
        assert filtered[0].file_path == "src/main.py"
        assert filtered[0].path_classification == PathClassification.runtime

    def test_preserves_runtime_findings(self):
        """Test runtime findings are preserved."""
        policy = TriagePolicy(
            name="test_policy",
            filter_third_party=True,
            filter_tests=True
        )

        findings = [
            Finding(
                id="1",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                title="Finding in src",
                description="Test",
                file_path="src/main.py",
                line_start=10,
                vulnerability_type="sql_injection",
                confidence=0.9,
                created_at=datetime.utcnow()
            ),
            Finding(
                id="2",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                title="Finding in app",
                description="Test",
                file_path="app/server.py",
                line_start=20,
                vulnerability_type="command_injection",
                confidence=0.9,
                created_at=datetime.utcnow()
            )
        ]

        filtered = pre_filter_findings(findings, policy)

        assert len(filtered) == 2
        assert all(f.path_classification == PathClassification.runtime for f in filtered)

    def test_preserves_tooling_findings(self):
        """Test tooling findings are preserved (not auto-filtered)."""
        policy = TriagePolicy(
            name="test_policy",
            filter_third_party=True,
            filter_tests=True
        )

        findings = [
            Finding(
                id="1",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                title="Finding in tools",
                description="Test",
                file_path="tools/deploy.py",
                line_start=10,
                vulnerability_type="command_injection",
                confidence=0.9,
                created_at=datetime.utcnow()
            )
        ]

        filtered = pre_filter_findings(findings, policy)

        assert len(filtered) == 1
        assert filtered[0].path_classification == PathClassification.tooling

    def test_attaches_path_classification_to_findings(self):
        """Test path classification is attached to findings."""
        policy = TriagePolicy(
            name="test_policy",
            filter_third_party=False,
            filter_tests=False
        )

        findings = [
            Finding(
                id="1",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                title="Finding in src",
                description="Test",
                file_path="src/main.py",
                line_start=10,
                vulnerability_type="sql_injection",
                confidence=0.9,
                created_at=datetime.utcnow()
            ),
            Finding(
                id="2",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                title="Finding in tools",
                description="Test",
                file_path="tools/deploy.py",
                line_start=20,
                vulnerability_type="command_injection",
                confidence=0.9,
                created_at=datetime.utcnow()
            )
        ]

        filtered = pre_filter_findings(findings, policy)

        assert len(filtered) == 2
        assert filtered[0].path_classification == PathClassification.runtime
        assert filtered[1].path_classification == PathClassification.tooling

    def test_filters_ci_findings(self):
        """Test CI findings are filtered."""
        policy = TriagePolicy(
            name="test_policy",
            filter_ci=True
        )

        findings = [
            Finding(
                id="1",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                title="Finding in CI",
                description="Test",
                file_path=".github/workflows/ci.yml",
                line_start=10,
                vulnerability_type="command_injection",
                confidence=0.9,
                created_at=datetime.utcnow()
            ),
            Finding(
                id="2",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                title="Finding in src",
                description="Test",
                file_path="src/main.py",
                line_start=20,
                vulnerability_type="sql_injection",
                confidence=0.9,
                created_at=datetime.utcnow()
            )
        ]

        filtered = pre_filter_findings(findings, policy)

        assert len(filtered) == 1
        assert filtered[0].file_path == "src/main.py"

    def test_filters_docs_findings(self):
        """Test docs findings are filtered."""
        policy = TriagePolicy(
            name="test_policy",
            filter_docs=True
        )

        findings = [
            Finding(
                id="1",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                title="Finding in docs",
                description="Test",
                file_path="docs/readme.md",
                line_start=10,
                vulnerability_type="xss",
                confidence=0.9,
                created_at=datetime.utcnow()
            ),
            Finding(
                id="2",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                title="Finding in src",
                description="Test",
                file_path="src/main.py",
                line_start=20,
                vulnerability_type="sql_injection",
                confidence=0.9,
                created_at=datetime.utcnow()
            )
        ]

        filtered = pre_filter_findings(findings, policy)

        assert len(filtered) == 1
        assert filtered[0].file_path == "src/main.py"

    def test_filters_migration_findings(self):
        """Test migration findings are filtered."""
        policy = TriagePolicy(
            name="test_policy",
            filter_migrations=True
        )

        findings = [
            Finding(
                id="1",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                title="Finding in migrations",
                description="Test",
                file_path="migrations/001_init.sql",
                line_start=10,
                vulnerability_type="sql_injection",
                confidence=0.9,
                created_at=datetime.utcnow()
            ),
            Finding(
                id="2",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                title="Finding in src",
                description="Test",
                file_path="src/main.py",
                line_start=20,
                vulnerability_type="sql_injection",
                confidence=0.9,
                created_at=datetime.utcnow()
            )
        ]

        filtered = pre_filter_findings(findings, policy)

        assert len(filtered) == 1
        assert filtered[0].file_path == "src/main.py"

    def test_respects_filter_flags(self):
        """Test filter flags can be disabled."""
        policy = TriagePolicy(
            name="test_policy",
            filter_third_party=False,
            filter_tests=False
        )

        findings = [
            Finding(
                id="1",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                title="Finding in third party",
                description="Test",
                file_path="third_party/lib.py",
                line_start=10,
                vulnerability_type="sql_injection",
                confidence=0.9,
                created_at=datetime.utcnow()
            ),
            Finding(
                id="2",
                agent_id="agent1",
                repo_id="repo1",
                severity=Severity.HIGH,
                title="Finding in test",
                description="Test",
                file_path="test/test_main.py",
                line_start=20,
                vulnerability_type="sql_injection",
                confidence=0.9,
                created_at=datetime.utcnow()
            )
        ]

        filtered = pre_filter_findings(findings, policy)

        assert len(filtered) == 2
        assert filtered[0].path_classification == PathClassification.third_party
        assert filtered[1].path_classification == PathClassification.third_party
