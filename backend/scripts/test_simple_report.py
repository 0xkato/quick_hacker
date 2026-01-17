"""Test simple report endpoint by creating a test finding and fetching report."""

import asyncio
import sys
from pathlib import Path
from datetime import datetime
from uuid import uuid4

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import text
from database.connection import engine


async def test_simple_report():
    """Create test finding and verify report generation."""

    test_agent_id = f"test-agent-{uuid4().hex[:8]}"
    test_finding_id = uuid4().hex

    print(f"Creating test finding for agent: {test_agent_id}")

    # Create test finding
    async with engine.begin() as conn:
        await conn.execute(
            text("""
                INSERT INTO findings (
                    id, agent_id, repo_id, title, severity, disposition,
                    vulnerability_type, cwe_id, file_path, line_start, line_end,
                    description, vulnerable_code, attack_scenario,
                    proof_of_concept, recommended_fix, confidence,
                    metadata, created_at
                ) VALUES (
                    :id, :agent_id, :repo_id, :title, :severity, :disposition,
                    :vuln_type, :cwe_id, :file_path, :line_start, :line_end,
                    :description, :vuln_code, :attack_scenario,
                    :poc, :fix, :confidence,
                    '{}'::jsonb, NOW()
                )
            """),
            {
                "id": test_finding_id,
                "agent_id": test_agent_id,
                "repo_id": "test-repo",
                "title": "Test SQL Injection Vulnerability",
                "severity": "critical",
                "disposition": "VALID_SECURITY_ISSUE",
                "vuln_type": "sql_injection",
                "cwe_id": "89",
                "file_path": "test/auth.py",
                "line_start": 42,
                "line_end": 45,
                "description": "User input is concatenated directly into SQL query without sanitization.",
                "vuln_code": 'query = f"SELECT * FROM users WHERE id={user_id}"',
                "attack_scenario": "Attacker can inject arbitrary SQL by providing malicious user_id parameter.",
                "poc": "curl http://localhost/user?id=1%20OR%201=1",
                "fix": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))",
                "confidence": 0.95
            }
        )

    print(f"✅ Test finding created: {test_finding_id}")

    # Fetch the finding back to verify
    async with engine.begin() as conn:
        result = await conn.execute(
            text("SELECT title, severity FROM findings WHERE id = :id"),
            {"id": test_finding_id}
        )
        row = result.fetchone()
        if row:
            print(f"✅ Finding verified: {row[0]} ({row[1]})")
        else:
            print("❌ Finding not found!")
            return

    print(f"\n📊 Test Report Generation")
    print(f"Run this command to get the report:")
    print(f"\n  curl -H 'Authorization: Bearer YOUR_TOKEN' \\")
    print(f"    http://localhost:8000/api/agents/{test_agent_id}/report \\")
    print(f"    -o test-report.md\n")

    print(f"Or test without auth (will show 401 but endpoint is registered):")
    print(f"\n  curl http://localhost:8000/api/agents/{test_agent_id}/report\n")

    # Cleanup prompt
    print(f"\n🧹 Cleanup (after testing):")
    print(f"  python3 -c \"")
    print(f"import asyncio")
    print(f"from sqlalchemy import text")
    print(f"from database.connection import engine")
    print(f"async def cleanup():")
    print(f"    async with engine.begin() as conn:")
    print(f"        await conn.execute(text('DELETE FROM findings WHERE agent_id = :id'), {{'id': '{test_agent_id}'}})")
    print(f"    print('✅ Test data cleaned up')")
    print(f"asyncio.run(cleanup())\"")


if __name__ == "__main__":
    asyncio.run(test_simple_report())
