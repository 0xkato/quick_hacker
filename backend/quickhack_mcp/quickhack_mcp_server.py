from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

_BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from services.security_scanners.base import ScanLimits
from services.tool_core import ToolCore

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "quickhack"
SERVER_VERSION = "0.1.0"


def _json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def _text_result(text: str, *, is_error: bool) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": text}],
        "isError": bool(is_error),
    }


def _response(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, message: str, *, code: int = -32603) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]

    def to_mcp(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "inputSchema": self.input_schema}


class QuickHackMCPServer:
    def __init__(self, tool_core: ToolCore):
        self.tool_core = tool_core
        self._tools = self._build_tools()

    @staticmethod
    def _build_tools() -> list[ToolSpec]:
        return [
            ToolSpec(
                name="read_file",
                description="Read a file from the workspace (optionally by line range).",
                input_schema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "start_line": {"type": "integer"},
                        "end_line": {"type": "integer"},
                    },
                    "required": ["path"],
                },
            ),
            ToolSpec(
                name="list_directory",
                description="List workspace directory contents.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "recursive": {"type": "boolean"},
                        "pattern": {"type": "string"},
                        "max_items": {"type": "integer"},
                    },
                },
            ),
            ToolSpec(
                name="grep_semantic",
                description="ReDoS-safe semantic grep with context lines.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string"},
                        "context_lines": {"type": "integer"},
                        "file_glob": {"type": "string"},
                    },
                    "required": ["pattern"],
                },
            ),
            ToolSpec(
                name="scan_repo_for_secrets",
                description="Scan the repository for hardcoded secrets (offline-first).",
                input_schema={
                    "type": "object",
                    "properties": {"entropy_threshold": {"type": "number"}},
                },
            ),
            ToolSpec(
                name="dependency_audit",
                description="Audit dependencies for known vulnerabilities (offline-first).",
                input_schema={
                    "type": "object",
                    "properties": {"lockfile_path": {"type": "string"}},
                },
            ),
            ToolSpec(
                name="analyze_ast",
                description="Analyze a file using language-aware AST parsing (best-effort).",
                input_schema={
                    "type": "object",
                    "properties": {"file_path": {"type": "string"}},
                    "required": ["file_path"],
                },
            ),
            ToolSpec(
                name="trace_dataflow",
                description="Best-effort dataflow trace for a location (Python-only initially).",
                input_schema={
                    "type": "object",
                    "properties": {"file_path": {"type": "string"}, "line_number": {"type": "integer"}},
                    "required": ["file_path", "line_number"],
                },
            ),
            ToolSpec(
                name="track_file_analysis",
                description="Flow graph: record that a file is being analyzed (for investigation tree).",
                input_schema={
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string"},
                        "purpose": {"type": "string"},
                    },
                    "required": ["file_path"],
                },
            ),
            ToolSpec(
                name="track_function_discovered",
                description="Flow graph: record discovery of an interesting function.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "function_name": {"type": "string"},
                        "file_path": {"type": "string"},
                        "line_number": {"type": "integer"},
                        "signature": {"type": "string"},
                        "reason": {"type": "string"},
                    },
                    "required": ["function_name", "file_path", "line_number"],
                },
            ),
            ToolSpec(
                name="track_call_chain",
                description="Flow graph: record a call chain from a function to a list of targets.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "from_function": {"type": "string"},
                        "calls": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "target": {"type": "string"},
                                    "file": {"type": "string"},
                                },
                                "required": ["target"],
                            },
                        },
                    },
                    "required": ["from_function", "calls"],
                },
            ),
            ToolSpec(
                name="track_sink_identified",
                description="Flow graph: record that a dangerous sink was identified.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "sink_type": {"type": "string"},
                        "file_path": {"type": "string"},
                        "line_number": {"type": "integer"},
                        "code_snippet": {"type": "string"},
                    },
                    "required": ["sink_type", "file_path", "line_number"],
                },
            ),
            ToolSpec(
                name="track_entry_point",
                description="Flow graph: record an entry point (route/handler) for later analysis.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "entry_type": {"type": "string"},
                        "file_path": {"type": "string"},
                        "line_number": {"type": "integer"},
                        "route": {"type": "string"},
                        "method": {"type": "string"},
                    },
                    "required": ["entry_type", "file_path", "line_number"],
                },
            ),
            ToolSpec(
                name="upsert_sink_signal",
                description="Create or update a persistent sink signal (investigation lead).",
                input_schema={
                    "type": "object",
                    "properties": {
                        "kind": {"type": "string"},
                        "label": {"type": "string"},
                        "file_path": {"type": "string"},
                        "fingerprint": {"type": "string"},
                        "line_number": {"type": "integer"},
                        "status": {"type": "string"},
                        "llm_risk_tier": {"type": "string"},
                        "llm_score": {"type": "integer"},
                        "llm_reasoning": {"type": "string"},
                        "metadata": {"type": "object"},
                    },
                    "required": ["kind", "label", "file_path"],
                },
            ),
            ToolSpec(
                name="report_finding",
                description="Report a finding (creates a pending finding; triage stays authoritative).",
                input_schema={
                    "type": "object",
                    "properties": {
                        "severity": {"type": "string"},
                        "title": {"type": "string"},
                        "vulnerability_type": {"type": "string"},
                        "file_path": {"type": "string"},
                        "line_start": {"type": "integer"},
                        "line_end": {"type": "integer"},
                        "vulnerable_code": {"type": "string"},
                        "description": {"type": "string"},
                        "confidence": {"type": "number"},
                        "cwe_id": {"type": "string"},
                        "source_trace": {"type": "array", "items": {"type": "string"}},
                        "attack_scenario": {"type": "string"},
                        "proof_of_concept": {"type": "string"},
                        "recommended_fix": {"type": "string"},
                        "metadata": {"type": "object"},
                    },
                    "required": [
                        "severity",
                        "title",
                        "vulnerability_type",
                        "file_path",
                        "line_start",
                        "vulnerable_code",
                        "description",
                        "confidence",
                        "metadata",
                    ],
                },
            ),
            ToolSpec(
                name="promote_finding",
                description="Alias for report_finding (used once a candidate is verified).",
                input_schema={
                    "type": "object",
                    "properties": {"finding": {"type": "object"}},
                    "required": ["finding"],
                },
            ),
            ToolSpec(
                name="triage_finding",
                description="Triage a finding to determine if it's reportable (two-stage: production relevance + issue validation). Returns decision and reason.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "file_path": {"type": "string"},
                        "vulnerability_type": {"type": "string"},
                        "severity": {"type": "string"},
                        "description": {"type": "string"},
                    },
                    "required": ["title", "file_path", "vulnerability_type", "severity", "description"],
                },
            ),
        ]

    async def handle_request(self, request: dict[str, Any]) -> dict[str, Any] | None:
        request_id = request.get("id")
        method = request.get("method")
        params = request.get("params") or {}

        # Notifications have no id; acknowledge by returning None.
        if request_id is None:
            return None

        if method == "initialize":
            return _response(
                request_id,
                {
                    "protocolVersion": params.get("protocolVersion") or PROTOCOL_VERSION,
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                    "capabilities": {"tools": {"listChanged": False}},
                },
            )

        if method == "tools/list":
            return _response(request_id, {"tools": [t.to_mcp() for t in self._tools]})

        if method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments") or {}
            if not isinstance(arguments, dict):
                return _response(request_id, _text_result("arguments must be an object", is_error=True))

            try:
                result = await self._dispatch_tool(str(name), arguments)
                return _response(request_id, _text_result(_json_dumps(result), is_error=False))
            except Exception as exc:
                return _response(request_id, _text_result(str(exc), is_error=True))

        return _error(request_id, f"Method not found: {method}", code=-32601)

    async def _dispatch_tool(self, name: str, args: dict[str, Any]) -> Any:
        if name == "read_file":
            return await self.tool_core.read_file(
                path=str(args["path"]),
                start_line=args.get("start_line"),
                end_line=args.get("end_line"),
            )
        if name == "list_directory":
            return await self.tool_core.list_directory(
                path=str(args.get("path") or "."),
                recursive=bool(args.get("recursive") or False),
                pattern=args.get("pattern"),
                max_items=int(args.get("max_items") or 500),
            )
        if name == "grep_semantic":
            return await self.tool_core.grep_semantic(
                pattern=str(args["pattern"]),
                context_lines=int(args.get("context_lines") or 3),
                file_glob=str(args.get("file_glob") or "**/*"),
            )
        if name == "scan_repo_for_secrets":
            return await self.tool_core.scan_for_secrets(entropy_threshold=float(args.get("entropy_threshold") or 4.5))
        if name == "dependency_audit":
            return await self.tool_core.dependency_audit(lockfile_path=args.get("lockfile_path"))
        if name == "analyze_ast":
            return await self.tool_core.analyze_ast(file_path=str(args["file_path"]))
        if name == "trace_dataflow":
            return await self.tool_core.trace_dataflow(
                file_path=str(args["file_path"]),
                line_number=int(args["line_number"]),
            )
        if name == "track_file_analysis":
            return await self.tool_core.track_file_analysis(
                file_path=str(args["file_path"]),
                purpose=str(args.get("purpose") or "analyzing"),
            )
        if name == "track_function_discovered":
            return await self.tool_core.track_function_discovered(
                function_name=str(args["function_name"]),
                file_path=str(args["file_path"]),
                line_number=int(args["line_number"]),
                signature=args.get("signature"),
                reason=args.get("reason"),
            )
        if name == "track_call_chain":
            calls = args.get("calls") or []
            if not isinstance(calls, list):
                raise ValueError("calls must be an array")
            normalized_calls: list[dict[str, str]] = []
            for item in calls:
                if not isinstance(item, dict):
                    continue
                target = item.get("target")
                if not isinstance(target, str) or not target:
                    continue
                normalized: dict[str, str] = {"target": target}
                file_val = item.get("file")
                if isinstance(file_val, str) and file_val:
                    normalized["file"] = file_val
                normalized_calls.append(normalized)
            return await self.tool_core.track_call_chain(
                from_function=str(args["from_function"]),
                calls=normalized_calls,
            )
        if name == "track_sink_identified":
            return await self.tool_core.track_sink_identified(
                sink_type=str(args["sink_type"]),
                file_path=str(args["file_path"]),
                line_number=int(args["line_number"]),
                code_snippet=args.get("code_snippet"),
            )
        if name == "track_entry_point":
            return await self.tool_core.track_entry_point(
                entry_type=str(args["entry_type"]),
                file_path=str(args["file_path"]),
                line_number=int(args["line_number"]),
                route=args.get("route"),
                method=args.get("method"),
            )
        if name == "upsert_sink_signal":
            return await self.tool_core.upsert_sink_signal(
                kind=str(args["kind"]),
                label=str(args["label"]),
                file_path=str(args["file_path"]),
                fingerprint=args.get("fingerprint"),
                line_number=args.get("line_number"),
                status=args.get("status"),
                llm_risk_tier=args.get("llm_risk_tier"),
                llm_score=args.get("llm_score"),
                llm_reasoning=args.get("llm_reasoning"),
                metadata=args.get("metadata"),
            )
        if name == "report_finding":
            return await self.tool_core.report_finding(
                severity=str(args["severity"]),
                title=str(args["title"]),
                vulnerability_type=str(args["vulnerability_type"]),
                file_path=str(args["file_path"]),
                line_start=int(args["line_start"]),
                vulnerable_code=str(args["vulnerable_code"]),
                description=str(args["description"]),
                confidence=float(args["confidence"]),
                cwe_id=args.get("cwe_id"),
                line_end=args.get("line_end"),
                source_trace=args.get("source_trace"),
                attack_scenario=args.get("attack_scenario"),
                proof_of_concept=args.get("proof_of_concept"),
                recommended_fix=args.get("recommended_fix"),
                metadata=args.get("metadata"),
            )
        if name == "promote_finding":
            finding = args.get("finding")
            if not isinstance(finding, dict):
                raise ValueError("finding must be an object")
            # Accept either promote_finding({finding:{...}}) or direct report_finding-style keys.
            merged = dict(finding)
            return await self._dispatch_tool("report_finding", merged)
        if name == "triage_finding":
            return await self.tool_core.triage_finding(
                title=str(args["title"]),
                file_path=str(args["file_path"]),
                vulnerability_type=str(args["vulnerability_type"]),
                severity=str(args["severity"]),
                description=str(args["description"]),
            )

        raise ValueError(f"Unknown tool: {name}")


def _build_limits_reader(
    *,
    limits_path: str | None,
    cancel_path: str | None,
) -> Callable[[], ScanLimits]:
    limits_file = Path(limits_path) if limits_path else None
    cancel_file = Path(cancel_path) if cancel_path else None

    def cancelled() -> bool:
        return bool(cancel_file and cancel_file.exists())

    def get_limits() -> ScanLimits:
        max_runtime_s = 30.0
        if limits_file and limits_file.exists():
            try:
                raw = json.loads(limits_file.read_text(encoding="utf-8"))
                if isinstance(raw, dict) and isinstance(raw.get("max_runtime_s"), (int, float)):
                    max_runtime_s = float(raw["max_runtime_s"])
            except Exception:
                pass
        return ScanLimits(deadline=time.monotonic() + max(0.0, max_runtime_s), cancelled=cancelled)

    return get_limits


async def _stdio_loop(server: QuickHackMCPServer) -> None:
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    loop = asyncio.get_running_loop()
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)

    w_transport, w_protocol = await loop.connect_write_pipe(asyncio.streams.FlowControlMixin, sys.stdout)
    writer = asyncio.StreamWriter(w_transport, w_protocol, reader, loop)

    async def send(obj: dict[str, Any]) -> None:
        writer.write((_json_dumps(obj) + "\n").encode("utf-8"))
        await writer.drain()

    while True:
        line = await reader.readline()
        if not line:
            break
        try:
            req = json.loads(line)
        except Exception:
            continue

        if isinstance(req, list):
            for item in req:
                if isinstance(item, dict):
                    resp = await server.handle_request(item)
                    if resp is not None:
                        await send(resp)
            continue

        if isinstance(req, dict):
            resp = await server.handle_request(req)
            if resp is not None:
                await send(resp)


def main() -> None:
    repo_path = os.environ.get("QUICKHACK_REPO_PATH") or "."
    project_id = os.environ.get("QUICKHACK_PROJECT_ID") or "default"
    agent_id = os.environ.get("QUICKHACK_AGENT_ID")
    limits_path = os.environ.get("QUICKHACK_LIMITS_PATH")
    cancel_path = os.environ.get("QUICKHACK_CANCEL_PATH")

    get_limits = _build_limits_reader(limits_path=limits_path, cancel_path=cancel_path)

    tool_core = ToolCore(
        repo_path=repo_path,
        project_id=project_id,
        agent_id=agent_id,
        get_scan_limits=get_limits,
    )
    server = QuickHackMCPServer(tool_core)

    asyncio.run(_stdio_loop(server))


if __name__ == "__main__":
    main()
