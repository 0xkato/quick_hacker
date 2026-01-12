# backend/providers/mcp_tools.py
"""MCP tool server for exposing ToolCore methods to Claude SDK.

This module creates SDK MCP tools using the @tool decorator from claude_agent_sdk.
It wraps quick_hack's security research tools for use with Claude Agent SDK.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from services.tool_core import ToolCore

logger = logging.getLogger(__name__)

# Maximum output size before truncation (50KB)
MAX_OUTPUT_SIZE = 50_000

# Try to import Claude SDK, but provide fallback for testing
SDK_AVAILABLE = False
tool = None
create_sdk_mcp_server = None

try:
    from claude_agent_sdk import tool as _tool, create_sdk_mcp_server as _create_sdk_mcp_server
    tool = _tool
    create_sdk_mcp_server = _create_sdk_mcp_server
    SDK_AVAILABLE = True
except ImportError:
    logger.warning("Claude Agent SDK not installed. MCP tools will use fallback mode.")


# Legacy MCP_TOOLS list for backwards compatibility and testing
MCP_TOOLS: list[dict[str, Any]] = [
    {
        "name": "read_file",
        "description": "Read file contents from the repository. Supports optional line range selection.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Relative path from repository root"},
                "start_line": {"type": "integer", "description": "Starting line number (1-indexed, inclusive)"},
                "end_line": {"type": "integer", "description": "Ending line number (1-indexed, inclusive)"}
            },
            "required": ["path"]
        }
    },
    {
        "name": "search_code",
        "description": "Search for regex pattern across the codebase. Returns matching lines with file paths and line numbers.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Regex pattern to search for"},
                "file_pattern": {"type": "string", "description": "Optional glob pattern to filter files"},
                "max_results": {"type": "integer", "description": "Maximum number of results to return"}
            },
            "required": ["pattern"]
        }
    },
    {
        "name": "list_directory",
        "description": "List directory contents with optional recursive traversal and glob filtering.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Relative path from repository root"},
                "recursive": {"type": "boolean", "description": "If true, list all files recursively"},
                "pattern": {"type": "string", "description": "Optional glob pattern to filter items"},
                "max_items": {"type": "integer", "description": "Maximum items to return"}
            },
            "required": []
        }
    },
    {
        "name": "list_sink_signals",
        "description": "List sink signals (security-relevant code patterns) for the current project.",
        "input_schema": {
            "type": "object",
            "properties": {
                "status": {"type": "string", "description": "Filter by status"},
                "limit": {"type": "integer", "description": "Maximum signals to return"}
            },
            "required": []
        }
    },
    {
        "name": "upsert_sink_signal",
        "description": "Create or update a sink signal for tracking security-relevant code patterns.",
        "input_schema": {
            "type": "object",
            "properties": {
                "kind": {"type": "string", "description": "Signal kind: 'entry_point', 'sink', or 'other'"},
                "label": {"type": "string", "description": "Human-readable label describing the signal"},
                "file_path": {"type": "string", "description": "File path relative to repository root"},
                "fingerprint": {"type": "string", "description": "Optional explicit fingerprint"},
                "line_number": {"type": "integer", "description": "Line number in the file"},
                "status": {"type": "string", "description": "Signal status"},
                "llm_risk_tier": {"type": "string", "description": "Risk tier assessment (S, A, B, C, D, E)"},
                "llm_score": {"type": "integer", "description": "Risk score (0-100)"},
                "llm_reasoning": {"type": "string", "description": "Explanation of risk assessment"},
                "metadata": {"type": "object", "description": "Additional metadata"}
            },
            "required": ["kind", "label", "file_path"]
        }
    },
    {
        "name": "report_finding",
        "description": "Report a security vulnerability finding with full details.",
        "input_schema": {
            "type": "object",
            "properties": {
                "severity": {"type": "string", "description": "Severity level"},
                "title": {"type": "string", "description": "Brief title for the finding"},
                "vulnerability_type": {"type": "string", "description": "Type of vulnerability"},
                "file_path": {"type": "string", "description": "Path to the vulnerable file"},
                "line_start": {"type": "integer", "description": "Starting line number"},
                "vulnerable_code": {"type": "string", "description": "The vulnerable code snippet"},
                "description": {"type": "string", "description": "Detailed description"},
                "confidence": {"type": "number", "description": "Confidence score (0.0 to 1.0)"},
                "cwe_id": {"type": "string", "description": "CWE identifier"},
                "line_end": {"type": "integer", "description": "Ending line number"},
                "source_trace": {"type": "array", "items": {"type": "string"}, "description": "Data flow trace"},
                "attack_scenario": {"type": "string", "description": "Exploitation description"},
                "proof_of_concept": {"type": "string", "description": "Example exploit"},
                "recommended_fix": {"type": "string", "description": "Recommended remediation"}
            },
            "required": ["severity", "title", "vulnerability_type", "file_path", "line_start", "vulnerable_code", "description", "confidence"]
        }
    },
    {
        "name": "scan_repo_for_secrets",
        "description": "Scan the repository for hardcoded secrets, API keys, and credentials.",
        "input_schema": {
            "type": "object",
            "properties": {
                "entropy_threshold": {"type": "number", "description": "Minimum Shannon entropy for detection"}
            },
            "required": []
        }
    },
    {
        "name": "dependency_audit",
        "description": "Audit project dependencies for known vulnerabilities.",
        "input_schema": {
            "type": "object",
            "properties": {
                "lockfile_path": {"type": "string", "description": "Optional specific lockfile to audit"}
            },
            "required": []
        }
    },
    {
        "name": "grep_semantic",
        "description": "Search code with regex pattern and surrounding context lines.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Regex pattern to search for"},
                "context_lines": {"type": "integer", "description": "Number of context lines"},
                "file_glob": {"type": "string", "description": "Glob pattern to filter files"}
            },
            "required": ["pattern"]
        }
    },
    {
        "name": "generate_security_report",
        "description": "Generate a formatted security report from scan findings.",
        "input_schema": {
            "type": "object",
            "properties": {
                "findings": {"type": "array", "description": "List of ScanFinding objects", "items": {"type": "object"}},
                "output_format": {"type": "string", "description": "Output format: 'markdown', 'json', or 'sarif'"}
            },
            "required": ["findings"]
        }
    },
    {
        "name": "track_file_analysis",
        "description": "Record that you're analyzing a file to build investigation tree",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path relative to repository root"},
                "purpose": {"type": "string", "description": "Why analyzing this file (e.g., 'looking for entry points')"}
            },
            "required": ["file_path"]
        }
    },
    {
        "name": "track_function_discovered",
        "description": "Record a function you found interesting during analysis",
        "input_schema": {
            "type": "object",
            "properties": {
                "function_name": {"type": "string", "description": "Function name (e.g., 'handleUpload')"},
                "file_path": {"type": "string", "description": "File containing function"},
                "line_number": {"type": "integer", "description": "Line where function defined"},
                "signature": {"type": "string", "description": "Full function signature (optional)"},
                "reason": {"type": "string", "description": "Why it's interesting (optional)"}
            },
            "required": ["function_name", "file_path", "line_number"]
        }
    },
    {
        "name": "track_call_chain",
        "description": "Record a sequence of function calls discovered during tracing",
        "input_schema": {
            "type": "object",
            "properties": {
                "from_function": {"type": "string", "description": "Function making the calls"},
                "calls": {
                    "type": "array",
                    "description": "List of function calls",
                    "items": {
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "Function being called"},
                            "file": {"type": "string", "description": "File containing target (optional)"}
                        },
                        "required": ["target"]
                    }
                }
            },
            "required": ["from_function", "calls"]
        }
    },
    {
        "name": "track_sink_identified",
        "description": "Mark a dangerous sink discovered during investigation",
        "input_schema": {
            "type": "object",
            "properties": {
                "sink_type": {"type": "string", "description": "Type: sql, exec, file_write, deserialize, ssrf"},
                "file_path": {"type": "string", "description": "File containing sink"},
                "line_number": {"type": "integer", "description": "Line number of sink"},
                "code_snippet": {"type": "string", "description": "Code showing the sink (optional)"}
            },
            "required": ["sink_type", "file_path", "line_number"]
        }
    },
    {
        "name": "track_entry_point",
        "description": "Mark an entry point discovered (API route, CLI arg, etc.)",
        "input_schema": {
            "type": "object",
            "properties": {
                "entry_type": {"type": "string", "description": "Type: api_route, cli_arg, form_handler, websocket"},
                "file_path": {"type": "string", "description": "File containing entry point"},
                "line_number": {"type": "integer", "description": "Line number"},
                "route": {"type": "string", "description": "Route path like /api/upload (optional)"},
                "method": {"type": "string", "description": "HTTP method like POST (optional)"}
            },
            "required": ["entry_type", "file_path", "line_number"]
        }
    }
]


def _truncate_output(output: str) -> str:
    """Truncate output if it exceeds MAX_OUTPUT_SIZE."""
    if len(output) <= MAX_OUTPUT_SIZE:
        return output
    notice = "\n\n[OUTPUT TRUNCATED]"
    truncate_at = MAX_OUTPUT_SIZE - len(notice)
    return output[:truncate_at] + notice


def _make_response(text: str, is_error: bool = False) -> dict[str, Any]:
    """Create SDK tool response format."""
    response = {"content": [{"type": "text", "text": text}]}
    if is_error:
        response["is_error"] = True
    return response


def _make_error_response(error: Exception) -> dict[str, Any]:
    """Create error response for SDK tool."""
    return _make_response(
        json.dumps({"error": type(error).__name__, "details": str(error)}),
        is_error=True
    )


def create_quickhack_mcp_server(tool_core: ToolCore) -> tuple[dict[str, Any], Any]:
    """Create MCP server configuration and tools for quick_hack.

    This function creates SDK MCP tools using the @tool decorator from claude_agent_sdk.
    If SDK is not available, it returns a fallback configuration for testing.

    Args:
        tool_core: The ToolCore instance to wrap

    Returns:
        Tuple of (server_config, mcp_server_or_tools)
        - server_config: dict with allowed_tools list
        - mcp_server_or_tools: McpSdkServerConfig if SDK available, else list of tool definitions
    """
    if not SDK_AVAILABLE:
        # Fallback mode for testing without SDK
        return _create_fallback_server(tool_core)

    return _create_sdk_server(tool_core)


def _create_fallback_server(tool_core: ToolCore) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Create fallback server configuration for testing without SDK."""
    server_config = {
        "allowed_tools": [f"mcp__quickhack__{t['name']}" for t in MCP_TOOLS],
    }
    return server_config, MCP_TOOLS


def _create_sdk_server(tool_core: ToolCore) -> tuple[dict[str, Any], Any]:
    """Create SDK MCP server with @tool decorated functions."""

    # Define tools using SDK @tool decorator
    @tool("read_file", "Read file contents from the repository", {
        "path": str,
        "start_line": int,
        "end_line": int,
    })
    async def read_file(args: dict[str, Any]) -> dict[str, Any]:
        try:
            result = await tool_core.read_file(
                path=args["path"],
                start_line=args.get("start_line"),
                end_line=args.get("end_line"),
            )
            return _make_response(_truncate_output(result))
        except Exception as e:
            return _make_error_response(e)

    @tool("search_code", "Search for regex pattern across the codebase", {
        "pattern": str,
        "file_pattern": str,
        "max_results": int,
    })
    async def search_code(args: dict[str, Any]) -> dict[str, Any]:
        try:
            result = await tool_core.search_code(
                pattern=args["pattern"],
                file_pattern=args.get("file_pattern"),
                max_results=args.get("max_results", 50),
            )
            return _make_response(_truncate_output(json.dumps(result, indent=2)))
        except Exception as e:
            return _make_error_response(e)

    @tool("list_directory", "List directory contents with optional recursive traversal", {
        "path": str,
        "recursive": bool,
        "pattern": str,
        "max_items": int,
    })
    async def list_directory(args: dict[str, Any]) -> dict[str, Any]:
        try:
            result = await tool_core.list_directory(
                path=args.get("path", "."),
                recursive=args.get("recursive", False),
                pattern=args.get("pattern"),
                max_items=args.get("max_items", 500),
            )
            return _make_response(_truncate_output(json.dumps(result, indent=2)))
        except Exception as e:
            return _make_error_response(e)

    @tool("list_sink_signals", "List sink signals for the current project", {
        "status": str,
        "limit": int,
    })
    async def list_sink_signals(args: dict[str, Any]) -> dict[str, Any]:
        try:
            result = await tool_core.list_sink_signals(
                status=args.get("status"),
                limit=args.get("limit", 50),
            )
            return _make_response(_truncate_output(json.dumps(result, indent=2)))
        except Exception as e:
            return _make_error_response(e)

    @tool("upsert_sink_signal", "Create or update a sink signal", {
        "kind": str,
        "label": str,
        "file_path": str,
        "fingerprint": str,
        "line_number": int,
        "status": str,
        "llm_risk_tier": str,
        "llm_score": int,
        "llm_reasoning": str,
        "metadata": dict,
    })
    async def upsert_sink_signal(args: dict[str, Any]) -> dict[str, Any]:
        try:
            result = await tool_core.upsert_sink_signal(
                kind=args["kind"],
                label=args["label"],
                file_path=args["file_path"],
                fingerprint=args.get("fingerprint"),
                line_number=args.get("line_number"),
                status=args.get("status"),
                llm_risk_tier=args.get("llm_risk_tier"),
                llm_score=args.get("llm_score"),
                llm_reasoning=args.get("llm_reasoning"),
                metadata=args.get("metadata"),
            )
            return _make_response(_truncate_output(json.dumps(result, indent=2)))
        except Exception as e:
            return _make_error_response(e)

    @tool("report_finding", "Report a security vulnerability finding", {
        "severity": str,
        "title": str,
        "vulnerability_type": str,
        "file_path": str,
        "line_start": int,
        "vulnerable_code": str,
        "description": str,
        "confidence": float,
        "cwe_id": str,
        "line_end": int,
        "source_trace": list,
        "attack_scenario": str,
        "proof_of_concept": str,
        "recommended_fix": str,
    })
    async def report_finding(args: dict[str, Any]) -> dict[str, Any]:
        try:
            result = await tool_core.report_finding(
                severity=args["severity"],
                title=args["title"],
                vulnerability_type=args["vulnerability_type"],
                file_path=args["file_path"],
                line_start=args["line_start"],
                vulnerable_code=args["vulnerable_code"],
                description=args["description"],
                confidence=args["confidence"],
                cwe_id=args.get("cwe_id"),
                line_end=args.get("line_end"),
                source_trace=args.get("source_trace"),
                attack_scenario=args.get("attack_scenario"),
                proof_of_concept=args.get("proof_of_concept"),
                recommended_fix=args.get("recommended_fix"),
            )
            return _make_response(_truncate_output(json.dumps(result, indent=2)))
        except Exception as e:
            return _make_error_response(e)

    @tool("scan_repo_for_secrets", "Scan repository for hardcoded secrets", {
        "entropy_threshold": float,
    })
    async def scan_repo_for_secrets(args: dict[str, Any]) -> dict[str, Any]:
        try:
            result = await tool_core.scan_for_secrets(
                entropy_threshold=args.get("entropy_threshold", 4.5),
            )
            return _make_response(_truncate_output(json.dumps(result, indent=2)))
        except Exception as e:
            return _make_error_response(e)

    @tool("dependency_audit", "Audit project dependencies for vulnerabilities", {
        "lockfile_path": str,
    })
    async def dependency_audit(args: dict[str, Any]) -> dict[str, Any]:
        try:
            result = await tool_core.dependency_audit(
                lockfile_path=args.get("lockfile_path"),
            )
            return _make_response(_truncate_output(json.dumps(result, indent=2)))
        except Exception as e:
            return _make_error_response(e)

    @tool("grep_semantic", "Search code with context lines", {
        "pattern": str,
        "context_lines": int,
        "file_glob": str,
    })
    async def grep_semantic(args: dict[str, Any]) -> dict[str, Any]:
        try:
            result = await tool_core.grep_semantic(
                pattern=args["pattern"],
                context_lines=args.get("context_lines", 3),
                file_glob=args.get("file_glob", "**/*"),
            )
            return _make_response(_truncate_output(json.dumps(result, indent=2)))
        except Exception as e:
            return _make_error_response(e)

    @tool("generate_security_report", "Generate security report from findings", {
        "findings": list,
        "output_format": str,
    })
    async def generate_security_report(args: dict[str, Any]) -> dict[str, Any]:
        try:
            from services.security_scanners import ScanFinding

            findings = args["findings"]
            scan_findings = []
            for f in findings:
                if isinstance(f, dict):
                    try:
                        scan_findings.append(ScanFinding(**f))
                    except (TypeError, ValueError) as conv_err:
                        return _make_error_response(
                            ValueError(f"Failed to convert finding: {conv_err}")
                        )
                else:
                    scan_findings.append(f)

            result = await tool_core.generate_security_report(
                findings=scan_findings,
                output_format=args.get("output_format", "markdown"),
            )
            return _make_response(_truncate_output(result))
        except Exception as e:
            return _make_error_response(e)

    @tool("track_file_analysis", "Record that you're analyzing a file", {
        "file_path": str,
        "purpose": str,
    })
    async def track_file_analysis(args: dict[str, Any]) -> dict[str, Any]:
        try:
            result = await tool_core.track_file_analysis(
                file_path=args["file_path"],
                purpose=args.get("purpose", "analyzing")
            )
            return _make_response(json.dumps(result, indent=2))
        except Exception as e:
            return _make_error_response(e)

    @tool("track_function_discovered", "Record a function you found interesting", {
        "function_name": str,
        "file_path": str,
        "line_number": int,
        "signature": str,
        "reason": str,
    })
    async def track_function_discovered(args: dict[str, Any]) -> dict[str, Any]:
        try:
            result = await tool_core.track_function_discovered(
                function_name=args["function_name"],
                file_path=args["file_path"],
                line_number=args["line_number"],
                signature=args.get("signature"),
                reason=args.get("reason")
            )
            return _make_response(json.dumps(result, indent=2))
        except Exception as e:
            return _make_error_response(e)

    @tool("track_call_chain", "Record a sequence of function calls", {
        "from_function": str,
        "calls": list,
    })
    async def track_call_chain(args: dict[str, Any]) -> dict[str, Any]:
        try:
            result = await tool_core.track_call_chain(
                from_function=args["from_function"],
                calls=args["calls"]
            )
            return _make_response(json.dumps(result, indent=2))
        except Exception as e:
            return _make_error_response(e)

    @tool("track_sink_identified", "Mark a dangerous sink discovered", {
        "sink_type": str,
        "file_path": str,
        "line_number": int,
        "code_snippet": str,
    })
    async def track_sink_identified(args: dict[str, Any]) -> dict[str, Any]:
        try:
            result = await tool_core.track_sink_identified(
                sink_type=args["sink_type"],
                file_path=args["file_path"],
                line_number=args["line_number"],
                code_snippet=args.get("code_snippet")
            )
            return _make_response(json.dumps(result, indent=2))
        except Exception as e:
            return _make_error_response(e)

    @tool("track_entry_point", "Mark an entry point discovered", {
        "entry_type": str,
        "file_path": str,
        "line_number": int,
        "route": str,
        "method": str,
    })
    async def track_entry_point(args: dict[str, Any]) -> dict[str, Any]:
        try:
            result = await tool_core.track_entry_point(
                entry_type=args["entry_type"],
                file_path=args["file_path"],
                line_number=args["line_number"],
                route=args.get("route"),
                method=args.get("method")
            )
            return _make_response(json.dumps(result, indent=2))
        except Exception as e:
            return _make_error_response(e)

    # Create SDK MCP server with all tools
    sdk_tools = [
        read_file,
        search_code,
        list_directory,
        list_sink_signals,
        upsert_sink_signal,
        report_finding,
        scan_repo_for_secrets,
        dependency_audit,
        grep_semantic,
        generate_security_report,
        track_file_analysis,
        track_function_discovered,
        track_call_chain,
        track_sink_identified,
        track_entry_point,
    ]

    mcp_server = create_sdk_mcp_server(
        name="quickhack",
        version="1.0.0",
        tools=sdk_tools,
    )

    # Build allowed_tools list (MCP format: mcp__<server>__<tool>)
    server_config = {
        "allowed_tools": [f"mcp__quickhack__{t.name}" for t in sdk_tools],
    }

    return server_config, mcp_server
