"""Tests for attack surface scan + triage service."""

import tempfile
from pathlib import Path

import pytest

from services.attack_surface_service import AttackSurfaceService


class SequenceProvider:
    provider_type = "dummy"
    model = "dummy"

    def __init__(self, outputs: list[str]):
        self._outputs = outputs
        self._idx = 0

    async def generate(self, messages, system_prompt=None):  # noqa: ANN001
        out = self._outputs[self._idx]
        self._idx = min(self._idx + 1, len(self._outputs) - 1)
        return out


@pytest.fixture
def tiny_fastapi_repo() -> str:
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = Path(tmpdir)
        (repo / "main.py").write_text(
            """
from fastapi import FastAPI
import os

app = FastAPI()

@app.get("/public")
async def public(q: str):
    return {"q": q}

def run(cmd: str):
    os.system(cmd)
"""
        )
        yield tmpdir


def test_scan_candidates_finds_routes_and_sinks(tiny_fastapi_repo: str):
    svc = AttackSurfaceService()
    candidates = svc.scan_candidates(repo_path=tiny_fastapi_repo, max_entry_points=10, max_sinks=10)
    kinds = {c.kind for c in candidates}
    assert "entry_point" in kinds
    assert "sink" in kinds


@pytest.mark.asyncio
async def test_triage_filters_and_scores(tiny_fastapi_repo: str):
    svc = AttackSurfaceService()
    candidates = svc.scan_candidates(repo_path=tiny_fastapi_repo, max_entry_points=10, max_sinks=10)

    entry = next(c for c in candidates if c.kind == "entry_point")
    sink = next(c for c in candidates if c.kind == "sink")

    provider = SequenceProvider(
        [
            # Initial triage response
            (
                "{"
                '"items":['
                f'{{"candidate_id":"{entry.id}","verdict":"investigate","confidence_score":0.91,"exposure":"A","reasoning":"Public FastAPI route; untrusted query input.","context_request":null}},'
                f'{{"candidate_id":"{sink.id}","verdict":"drop","confidence_score":0.2,"exposure":"unknown","reasoning":"Sink has no clear untrusted input in snippet.","context_request":null}}'
                "]"
                "}"
            )
        ]
    )

    triaged = await svc.triage(
        agent_id="test-agent",
        repo_path=tiny_fastapi_repo,
        threat_model="A",
        provider=provider,  # type: ignore[arg-type]
        candidates=candidates,
        min_investigate_confidence=0.6,
    )

    assert len(triaged) == 1
    assert triaged[0].candidate.id == entry.id
    assert triaged[0].confidence_score == pytest.approx(0.91)


@pytest.mark.asyncio
async def test_triage_followup_context_request(tiny_fastapi_repo: str):
    svc = AttackSurfaceService()
    candidates = svc.scan_candidates(repo_path=tiny_fastapi_repo, max_entry_points=10, max_sinks=10)
    entry = next(c for c in candidates if c.kind == "entry_point")

    provider = SequenceProvider(
        [
            # First pass: ask for context
            (
                "{"
                '"items":['
                f'{{"candidate_id":"{entry.id}","verdict":"needs_context","confidence_score":0.0,"exposure":"unknown","reasoning":"Need to see surrounding auth middleware.","context_request":{{"path":"main.py","start_line":1,"end_line":40,"reason":"Check for auth dependencies"}}}}'
                "]"
                "}"
            ),
            # Followup pass: decide investigate
            (
                "{"
                '"items":['
                f'{{"candidate_id":"{entry.id}","verdict":"investigate","confidence_score":0.8,"exposure":"A","reasoning":"No auth checks; public route."}}'
                "]"
                "}"
            ),
        ]
    )

    triaged = await svc.triage(
        agent_id="test-agent",
        repo_path=tiny_fastapi_repo,
        threat_model="A",
        provider=provider,  # type: ignore[arg-type]
        candidates=candidates,
        min_investigate_confidence=0.6,
    )

    assert len(triaged) == 1
    assert triaged[0].candidate.id == entry.id
    assert triaged[0].confidence_score == pytest.approx(0.8)

