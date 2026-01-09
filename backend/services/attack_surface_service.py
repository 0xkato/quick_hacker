"""Attack surface scan + conservative LLM triage.

This service is used to build an actionable investigation tree:
- Discover entry points (routes) and dangerous sinks (pattern-based).
- Use an LLM to conservatively decide what warrants deeper investigation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Optional

from cass.tools.framework_parsers import FrameworkParsers
from cass.tools.security_detectors import SecurityDetectors
from providers import BaseProvider, Message
from prompts.attack_surface_triage import ATTACK_SURFACE_TRIAGE_SYSTEM_PROMPT
from services.observability_service import observability_service


ThreatModel = Literal["A", "AB", "ABC"]
CandidateKind = Literal["entry_point", "sink"]
TriageVerdict = Literal["investigate", "drop", "needs_context"]
ExposureLevel = Literal["A", "B", "C", "unknown"]


@dataclass(frozen=True)
class AttackSurfaceCandidate:
    id: str
    kind: CandidateKind
    label: str
    file_path: str
    line_number: Optional[int]
    code_context: str
    metadata: dict[str, Any]


@dataclass(frozen=True)
class AttackSurfaceTriageItem:
    candidate: AttackSurfaceCandidate
    verdict: Literal["investigate", "drop"]
    confidence_score: float
    exposure: ExposureLevel
    reasoning: str


@dataclass(frozen=True)
class _ContextRequest:
    candidate_id: str
    path: str
    start_line: int
    end_line: int
    reason: str


def _stable_id(*parts: str) -> str:
    payload = "|".join(p.strip() for p in parts if p is not None)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


def _safe_resolve(repo_root: Path, rel_path: str) -> Path:
    full = (repo_root / rel_path).resolve()
    full.relative_to(repo_root.resolve())
    return full


def _read_snippet(
    repo_root: Path,
    rel_path: str,
    center_line: Optional[int],
    *,
    before: int = 10,
    after: int = 10,
    max_bytes: int = 1_000_000,
) -> str:
    try:
        file_path = _safe_resolve(repo_root, rel_path)
    except Exception:
        return ""

    try:
        if not file_path.exists() or not file_path.is_file():
            return ""
        if file_path.stat().st_size > max_bytes:
            return ""
        content = file_path.read_text(errors="replace")
    except Exception:
        return ""

    lines = content.splitlines()
    if not lines:
        return ""

    if center_line is None or center_line <= 0:
        start = 0
        end = min(len(lines), before + after + 1)
    else:
        start = max(0, (center_line - 1) - before)
        end = min(len(lines), (center_line - 1) + after + 1)

    snippet_lines = [f"{i + 1}: {lines[i]}" for i in range(start, end)]
    return "\n".join(snippet_lines)


def _extract_json_object(text: str) -> Any:
    """Best-effort extraction of a single top-level JSON object from model output."""
    if not text:
        raise ValueError("empty response")

    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("no JSON object found")

    raw = text[start : end + 1]
    return json.loads(raw)


def _clamp_int(value: Any, *, lo: int, hi: int, default: int) -> int:
    try:
        iv = int(value)
    except Exception:
        return default
    return max(lo, min(hi, iv))


def _clamp_float(value: Any, *, lo: float, hi: float, default: float) -> float:
    try:
        fv = float(value)
    except Exception:
        return default
    return max(lo, min(hi, fv))


def _normalize_exposure(value: Any) -> ExposureLevel:
    v = str(value or "").strip().upper()
    if v in ("A", "B", "C"):
        return v  # type: ignore[return-value]
    return "unknown"


def _candidate_to_prompt_obj(candidate: AttackSurfaceCandidate) -> dict[str, Any]:
    return {
        "candidate_id": candidate.id,
        "kind": candidate.kind,
        "label": candidate.label,
        "location": f"{candidate.file_path}:{candidate.line_number or ''}".rstrip(":"),
        "file_path": candidate.file_path,
        "line_number": candidate.line_number,
        "metadata": candidate.metadata,
        "code_context": candidate.code_context[:2500],
    }


def _build_triage_prompt(threat_model: ThreatModel, candidates: list[AttackSurfaceCandidate]) -> str:
    return (
        "Decide which items warrant deeper investigation.\n\n"
        f"Threat model: {threat_model}\n\n"
        "Return ONLY JSON with this schema:\n"
        "{\n"
        '  "items": [\n'
        "    {\n"
        '      "candidate_id": string,\n'
        '      "verdict": "investigate" | "drop" | "needs_context",\n'
        '      "confidence_score": number (0.0-1.0),\n'
        '      "exposure": "A" | "B" | "C" | "unknown",\n'
        '      "reasoning": string,\n'
        '      "context_request": {\n'
        '        "path": string,\n'
        '        "start_line": number,\n'
        '        "end_line": number,\n'
        '        "reason": string\n'
        "      } | null\n"
        "    }\n"
        "  ]\n"
        "}\n\n"
        "Rules:\n"
        "- Be skeptical; it is OK if everything is dropped.\n"
        "- Only use evidence in metadata/code_context.\n"
        "- You may set verdict='needs_context' for AT MOST 2 items total.\n"
        "- If verdict!='needs_context', set context_request=null.\n\n"
        "Candidates (JSON array):\n"
        + json.dumps([_candidate_to_prompt_obj(c) for c in candidates], ensure_ascii=False)
    )


def _build_followup_prompt(
    threat_model: ThreatModel,
    candidates: list[AttackSurfaceCandidate],
    contexts: dict[str, str],
) -> str:
    candidate_objs = []
    for c in candidates:
        candidate_objs.append(
            {
                **_candidate_to_prompt_obj(c),
                "additional_context": contexts.get(c.id, "")[:4000],
            }
        )

    return (
        "You requested additional context for some items. Make a FINAL decision.\n\n"
        f"Threat model: {threat_model}\n\n"
        "Return ONLY JSON with this schema:\n"
        "{\n"
        '  "items": [\n'
        "    {\n"
        '      "candidate_id": string,\n'
        '      "verdict": "investigate" | "drop",\n'
        '      "confidence_score": number (0.0-1.0),\n'
        '      "exposure": "A" | "B" | "C" | "unknown",\n'
        '      "reasoning": string\n'
        "    }\n"
        "  ]\n"
        "}\n\n"
        "Candidates (JSON array):\n"
        + json.dumps(candidate_objs, ensure_ascii=False)
    )


class AttackSurfaceService:
    def scan_candidates(
        self,
        *,
        repo_path: str,
        max_entry_points: int = 40,
        max_sinks: int = 80,
    ) -> list[AttackSurfaceCandidate]:
        repo_root = Path(repo_path).resolve()

        # Entry points (HTTP routes) via framework parsers.
        parsers = FrameworkParsers(str(repo_root))
        routes = parsers.parse_routes()

        entry_candidates: list[AttackSurfaceCandidate] = []
        for r in sorted(routes, key=lambda x: (str(x.get("file", "")), int(x.get("line") or 0), str(x.get("path", "")))):
            file_rel = str(r.get("file") or "")
            line = int(r.get("line") or 0) or None
            method = str(r.get("method") or "").upper()
            path = str(r.get("path") or "")
            handler = str(r.get("handler") or "")
            framework = str(r.get("framework") or "")

            label = f"{method} {path}".strip()
            if handler:
                label = f"{label} → {handler}()"

            entry_candidates.append(
                AttackSurfaceCandidate(
                    id=_stable_id("entry_point", file_rel, str(line or ""), label),
                    kind="entry_point",
                    label=label,
                    file_path=file_rel,
                    line_number=line,
                    code_context=_read_snippet(repo_root, file_rel, line, before=8, after=18),
                    metadata={
                        "framework": framework,
                        "method": method,
                        "route": path,
                        "handler": handler,
                    },
                )
            )

            if len(entry_candidates) >= max_entry_points:
                break

        # Dangerous sinks via pattern-based detectors.
        detectors = SecurityDetectors(str(repo_root))
        sinks = detectors.find_sinks()

        sink_candidates: list[AttackSurfaceCandidate] = []
        for s in sorted(sinks, key=lambda x: (str(x.get("file", "")), int(x.get("line") or 0), str(x.get("type", "")))):
            file_rel = str(s.get("file") or "")
            line = int(s.get("line") or 0) or None
            sink_type = str(s.get("type") or "")
            language = str(s.get("language") or "")
            code = str(s.get("code") or "")

            label = f"{sink_type} sink: {code}".strip()
            sink_candidates.append(
                AttackSurfaceCandidate(
                    id=_stable_id("sink", file_rel, str(line or ""), sink_type, code),
                    kind="sink",
                    label=label[:120],
                    file_path=file_rel,
                    line_number=line,
                    code_context=_read_snippet(repo_root, file_rel, line, before=12, after=12),
                    metadata={
                        "sink_type": sink_type,
                        "language": language,
                        "pattern": s.get("pattern"),
                    },
                )
            )

            if len(sink_candidates) >= max_sinks:
                break

        return entry_candidates + sink_candidates

    async def triage(
        self,
        *,
        agent_id: str,
        repo_path: str,
        threat_model: ThreatModel,
        provider: BaseProvider,
        candidates: list[AttackSurfaceCandidate],
        max_context_requests: int = 2,
        min_investigate_confidence: float = 0.6,
    ) -> list[AttackSurfaceTriageItem]:
        if not candidates:
            return []

        # Initial triage pass.
        prompt = _build_triage_prompt(threat_model, candidates)
        request_id = observability_service.log_llm_request(
            agent_id=agent_id,
            messages=[{"role": "system", "content": ATTACK_SURFACE_TRIAGE_SYSTEM_PROMPT}, {"role": "user", "content": prompt}],
            tools_available=None,
            model=getattr(provider, "model", None),
            provider=getattr(provider, "provider_type", None),
        )

        raw = await provider.generate([Message(role="user", content=prompt)], system_prompt=ATTACK_SURFACE_TRIAGE_SYSTEM_PROMPT)
        observability_service.log_llm_response(
            agent_id=agent_id,
            request_id=request_id,
            content=raw,
            tool_calls=None,
            usage=None,
            duration_ms=None,
            model=getattr(provider, "model", None),
            provider=getattr(provider, "provider_type", None),
        )

        parsed = _extract_json_object(raw)
        items = parsed.get("items", [])
        if not isinstance(items, list):
            return []

        by_id = {c.id: c for c in candidates}

        context_requests: list[_ContextRequest] = []
        provisional: dict[str, dict[str, Any]] = {}

        for item in items:
            if not isinstance(item, dict):
                continue
            candidate_id = str(item.get("candidate_id") or "")
            if candidate_id not in by_id:
                continue

            verdict = str(item.get("verdict") or "").strip().lower()
            if verdict not in ("investigate", "drop", "needs_context"):
                verdict = "drop"

            confidence_score = _clamp_float(item.get("confidence_score"), lo=0.0, hi=1.0, default=0.0)
            exposure = _normalize_exposure(item.get("exposure"))
            reasoning = str(item.get("reasoning") or "").strip()[:800]

            context_req_obj = item.get("context_request")
            if verdict == "needs_context" and isinstance(context_req_obj, dict) and len(context_requests) < max_context_requests:
                path = str(context_req_obj.get("path") or "").strip()
                start_line = _clamp_int(context_req_obj.get("start_line"), lo=1, hi=10_000_000, default=1)
                end_line = _clamp_int(context_req_obj.get("end_line"), lo=start_line, hi=10_000_000, default=start_line)
                reason = str(context_req_obj.get("reason") or "").strip()[:200]
                if path:
                    context_requests.append(
                        _ContextRequest(
                            candidate_id=candidate_id,
                            path=path,
                            start_line=start_line,
                            end_line=end_line,
                            reason=reason,
                        )
                    )

            provisional[candidate_id] = {
                "candidate_id": candidate_id,
                "verdict": verdict,
                "confidence_score": confidence_score,
                "exposure": exposure,
                "reasoning": reasoning,
            }

        # Follow-up pass if needed.
        if context_requests:
            repo_root = Path(repo_path).resolve()
            contexts: dict[str, str] = {}
            followup_candidates: list[AttackSurfaceCandidate] = []

            for req in context_requests:
                followup_candidates.append(by_id[req.candidate_id])
                snippet = _read_snippet(
                    repo_root,
                    req.path,
                    req.start_line,
                    before=0,
                    after=max(0, req.end_line - req.start_line),
                )
                contexts[req.candidate_id] = snippet

            followup_prompt = _build_followup_prompt(threat_model, followup_candidates, contexts)
            followup_request_id = observability_service.log_llm_request(
                agent_id=agent_id,
                messages=[
                    {"role": "system", "content": ATTACK_SURFACE_TRIAGE_SYSTEM_PROMPT},
                    {"role": "user", "content": followup_prompt},
                ],
                tools_available=None,
                model=getattr(provider, "model", None),
                provider=getattr(provider, "provider_type", None),
            )

            followup_raw = await provider.generate(
                [Message(role="user", content=followup_prompt)],
                system_prompt=ATTACK_SURFACE_TRIAGE_SYSTEM_PROMPT,
            )
            observability_service.log_llm_response(
                agent_id=agent_id,
                request_id=followup_request_id,
                content=followup_raw,
                tool_calls=None,
                usage=None,
                duration_ms=None,
                model=getattr(provider, "model", None),
                provider=getattr(provider, "provider_type", None),
            )

            followup_parsed = _extract_json_object(followup_raw)
            followup_items = followup_parsed.get("items", [])
            if isinstance(followup_items, list):
                for item in followup_items:
                    if not isinstance(item, dict):
                        continue
                    candidate_id = str(item.get("candidate_id") or "")
                    if candidate_id not in by_id:
                        continue
                    verdict = str(item.get("verdict") or "").strip().lower()
                    if verdict not in ("investigate", "drop"):
                        verdict = "drop"
                    confidence_score = _clamp_float(item.get("confidence_score"), lo=0.0, hi=1.0, default=0.0)
                    exposure = _normalize_exposure(item.get("exposure"))
                    reasoning = str(item.get("reasoning") or "").strip()[:800]
                    provisional[candidate_id] = {
                        "candidate_id": candidate_id,
                        "verdict": verdict,
                        "confidence_score": confidence_score,
                        "exposure": exposure,
                        "reasoning": reasoning,
                    }

        triaged: list[AttackSurfaceTriageItem] = []
        for candidate_id, item in provisional.items():
            verdict = item.get("verdict")
            if verdict != "investigate":
                continue

            confidence_score = float(item.get("confidence_score") or 0.0)
            if confidence_score < min_investigate_confidence:
                continue

            triaged.append(
                AttackSurfaceTriageItem(
                    candidate=by_id[candidate_id],
                    verdict="investigate",
                    confidence_score=confidence_score,
                    exposure=item.get("exposure", "unknown"),
                    reasoning=item.get("reasoning", ""),
                )
            )

        # Prefer highest confidence first, stable ordering otherwise.
        triaged.sort(key=lambda x: (-x.confidence_score, x.candidate.file_path, x.candidate.line_number or 0))
        return triaged


attack_surface_service = AttackSurfaceService()

