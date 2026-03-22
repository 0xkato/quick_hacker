"""Unit tests for IssueService CRUD operations.

The DB session is fully mocked -- no real database required.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from models.campaign_enums import IssueDisposition, IssueSeverity
from models.campaign_schemas import IssueResponse, ProofChecklist
from services.issue_service import IssueService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_session_mock():
    """Return an AsyncMock that behaves like an async context-managed session."""
    session = AsyncMock()
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.refresh = AsyncMock()
    session.get = AsyncMock(return_value=None)
    session.execute = AsyncMock()
    return session


def _fake_get_session(session_mock):
    """Return an async context manager that yields *session_mock*."""
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _ctx():
        yield session_mock

    return _ctx


_ISSUE_ATTRS = (
    "id", "artifact_id", "severity", "title", "description", "category",
    "cwe_id", "disposition", "proof", "root_cause", "recommended_fix",
    "regression_test_id", "created_at",
)


def _make_db_issue(**overrides):
    """Build a minimal fake DBIssue-like object."""
    defaults = dict(
        id="iss00001",
        artifact_id="art00001",
        severity="high",
        title="SQL Injection in /api/users",
        description="User input is concatenated into SQL query",
        category="injection",
        cwe_id="CWE-89",
        disposition="confirmed_security_issue",
        proof={
            "target_real": True,
            "harness_validated": True,
            "real_code_reached": True,
            "external_input_controlled": True,
            "oracle_triggered_or_sanitizer_hit": True,
            "reproduced_cleanly": True,
            "artifact_minimization_attempted": True,
            "not_harness_artifact": True,
            "not_test_only": True,
            "security_impact_confirmed": True,
        },
        root_cause="String concatenation in SQL query builder",
        recommended_fix="Use parameterized queries",
        regression_test_id=None,
        created_at=datetime(2026, 3, 22, 12, 0, 0, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    obj = MagicMock()
    for k, v in defaults.items():
        setattr(obj, k, v)
    return obj


def _make_db_regression_test(**overrides):
    """Build a minimal fake DBRegressionTest-like object."""
    defaults = dict(
        id="reg00001",
        issue_id="iss00001",
        file_ref="tests/regression/test_sqli_users.py",
        created_at=datetime(2026, 3, 22, 12, 0, 0, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    obj = MagicMock()
    for k, v in defaults.items():
        setattr(obj, k, v)
    return obj


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCreateIssue:
    @pytest.fixture()
    def service(self):
        return IssueService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.issue_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_issue_response(self, service, session):
        """create_issue should return an IssueResponse with correct fields."""
        db_issue = _make_db_issue()

        async def _refresh(obj):
            for attr in _ISSUE_ATTRS:
                setattr(obj, attr, getattr(db_issue, attr))

        session.refresh.side_effect = _refresh

        with self._patch_session(session):
            resp = await service.create_issue(
                artifact_id="art00001",
                severity="high",
                title="SQL Injection in /api/users",
                description="User input is concatenated into SQL query",
                category="injection",
                cwe_id="CWE-89",
                disposition="confirmed_security_issue",
                proof=db_issue.proof,
                root_cause="String concatenation in SQL query builder",
                recommended_fix="Use parameterized queries",
            )

        assert isinstance(resp, IssueResponse)
        assert resp.artifact_id == "art00001"
        assert resp.severity == IssueSeverity.HIGH
        assert resp.title == "SQL Injection in /api/users"
        assert resp.disposition == IssueDisposition.CONFIRMED_SECURITY_ISSUE
        assert resp.proof is not None
        assert resp.proof.security_impact_confirmed is True
        session.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_generates_8_char_id(self, service, session):
        """The issue id stored via session.add must be 8 hex chars."""
        db_issue = _make_db_issue()

        async def _refresh(obj):
            for attr in _ISSUE_ATTRS:
                if attr == "id":
                    continue
                setattr(obj, attr, getattr(db_issue, attr))

        session.refresh.side_effect = _refresh

        with self._patch_session(session):
            await service.create_issue(
                artifact_id="art00001",
                severity="high",
                title="Test Issue",
            )

        added_obj = session.add.call_args[0][0]
        assert len(added_obj.id) == 8
        int(added_obj.id, 16)  # valid hex


class TestGetIssue:
    @pytest.fixture()
    def service(self):
        return IssueService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.issue_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_none_for_missing(self, service, session):
        """get_issue should return None when the issue does not exist."""
        session.get.return_value = None

        with self._patch_session(session):
            result = await service.get_issue("nonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_returns_issue_response(self, service, session):
        """get_issue should return an IssueResponse when found."""
        db_issue = _make_db_issue(id="iss00001")
        session.get.return_value = db_issue

        with self._patch_session(session):
            result = await service.get_issue("iss00001")

        assert isinstance(result, IssueResponse)
        assert result.id == "iss00001"
        assert result.severity == IssueSeverity.HIGH


class TestListIssues:
    @pytest.fixture()
    def service(self):
        return IssueService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.issue_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_returns_list_of_responses(self, service, session):
        """list_issues should return a list of IssueResponse objects."""
        db_i1 = _make_db_issue(id="iss00001", title="Issue 1")
        db_i2 = _make_db_issue(id="iss00002", title="Issue 2")
        scalars_mock = MagicMock()
        scalars_mock.all.return_value = [db_i1, db_i2]
        result_mock = MagicMock()
        result_mock.scalars.return_value = scalars_mock
        session.execute.return_value = result_mock

        with self._patch_session(session):
            results = await service.list_issues("camp0001")

        assert len(results) == 2
        assert all(isinstance(r, IssueResponse) for r in results)
        assert results[0].title == "Issue 1"
        assert results[1].title == "Issue 2"


class TestCreateRegressionTest:
    @pytest.fixture()
    def service(self):
        return IssueService()

    @pytest.fixture()
    def session(self):
        return _make_session_mock()

    def _patch_session(self, session):
        return patch(
            "services.issue_service.get_session",
            _fake_get_session(session),
        )

    @pytest.mark.asyncio
    async def test_creates_regression_test(self, service, session):
        """create_regression_test should persist and return a dict."""
        db_test = _make_db_regression_test()

        async def _refresh(obj):
            for attr in ("id", "issue_id", "file_ref", "created_at"):
                setattr(obj, attr, getattr(db_test, attr))

        session.refresh.side_effect = _refresh

        with self._patch_session(session):
            result = await service.create_regression_test(
                issue_id="iss00001",
                file_ref="tests/regression/test_sqli_users.py",
            )

        assert result["issue_id"] == "iss00001"
        assert result["file_ref"] == "tests/regression/test_sqli_users.py"
        session.add.assert_called_once()
