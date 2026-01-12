"""Tests for case builder functionality."""

import pytest
from agents.deep_audit.case_builder import build_case_file


def test_build_case_file_creates_markdown():
    """Test that build_case_file creates properly structured markdown."""
    signal = {
        "signal_id": "sig_001",
        "signal_type": "data_flow",
        "file_path": "/app/routes/user.py",
        "line_range": [45, 52],
        "sink_snippet": "db.execute(query)",
        "suspected_sources": ["request.args.get('id')", "user_input"],
        "confidence": "high",
        "scope_id": "scope_123",
        "next_steps": ["Trace user_input origin", "Check sanitization"]
    }

    code_excerpts = [
        {
            "file_path": "/app/routes/user.py",
            "line_range": [40, 55],
            "content": "def get_user():\n    user_id = request.args.get('id')\n    query = f'SELECT * FROM users WHERE id={user_id}'\n    result = db.execute(query)\n    return result"
        },
        {
            "file_path": "/app/db.py",
            "line_range": [10, 15],
            "content": "def execute(query):\n    cursor.execute(query)\n    return cursor.fetchall()"
        }
    ]

    case_file = build_case_file(signal, code_excerpts)

    # Check key sections exist
    assert "# Case: sig_001" in case_file
    assert "## Signal Details" in case_file
    assert "## Sink" in case_file
    assert "## Suspected Sources" in case_file
    assert "## Code Excerpts" in case_file
    assert "## Next Steps" in case_file
    assert "## Verification Questions" in case_file
    assert "## Decision" in case_file

    # Check signal details
    assert "**Type:** data_flow" in case_file
    assert "**File:** /app/routes/user.py" in case_file
    assert "**Lines:** 45-52" in case_file
    assert "**Confidence:** high" in case_file
    assert "**Scope:** scope_123" in case_file

    # Check sink snippet
    assert "db.execute(query)" in case_file

    # Check suspected sources
    assert "- request.args.get('id')" in case_file
    assert "- user_input" in case_file

    # Check next steps
    assert "- Trace user_input origin" in case_file
    assert "- Check sanitization" in case_file

    # Check code excerpts
    assert "/app/routes/user.py" in case_file
    assert "Lines 40-55" in case_file
    assert "def get_user():" in case_file

    # Check verification questions exist
    assert "Does the sink actually execute" in case_file
    assert "Are the suspected sources correct" in case_file
    assert "Are there any sanitization" in case_file
    assert "What is the actual severity" in case_file


def test_build_case_file_limits_code_excerpts():
    """Test that build_case_file limits code excerpts to 6."""
    signal = {
        "signal_id": "sig_002",
        "signal_type": "data_flow",
        "file_path": "/app/test.py",
        "line_range": [10, 15],
        "sink_snippet": "eval(code)",
        "confidence": "medium",
        "scope_id": "scope_456"
    }

    # Create 10 code excerpts
    code_excerpts = [
        {
            "file_path": f"/app/file{i}.py",
            "line_range": [i*10, i*10+5],
            "content": f"code_block_{i}"
        }
        for i in range(10)
    ]

    case_file = build_case_file(signal, code_excerpts)

    # Should only have first 6 excerpts
    for i in range(6):
        assert f"/app/file{i}.py" in case_file
        assert f"code_block_{i}" in case_file

    # Should NOT have excerpts 6-9
    for i in range(6, 10):
        assert f"/app/file{i}.py" not in case_file
        assert f"code_block_{i}" not in case_file
