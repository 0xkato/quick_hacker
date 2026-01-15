from __future__ import annotations

from datetime import datetime

from models.schemas import Finding


def test_finding_redacts_private_keys_in_description_and_snippets() -> None:
    secret_block = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpgIBAAKCAQEAzvB5\n"
        "-----END RSA PRIVATE KEY-----\n"
    )

    finding = Finding(
        id="f1",
        agent_id="a1",
        repo_id="r1",
        severity="high",
        title="Hardcoded private key",
        description=f"Key material:\n{secret_block}",
        file_path="certs/server.key",
        line_start=1,
        vulnerability_type="hardcoded_secret",
        confidence=0.9,
        created_at=datetime.utcnow(),
        code_snippet=secret_block,
        vulnerable_code=secret_block,
    )

    assert "[REDACTED_PRIVATE_KEY]" in finding.description
    assert "MIIEpgIBAAKCAQEAzvB5" not in finding.description
    assert "[REDACTED_PRIVATE_KEY]" in (finding.code_snippet or "")
    assert "[REDACTED_PRIVATE_KEY]" in (finding.vulnerable_code or "")

