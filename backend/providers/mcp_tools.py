# backend/providers/mcp_tools.py
"""MCP tool server for exposing ToolCore methods to Claude SDK.

This module defines MCP tool definitions and creates the server configuration
for integrating quick_hack's security research tools with Claude Agent SDK.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Coroutine

from services.tool_core import ToolCore


# Maximum output size before truncation (50KB)
MAX_OUTPUT_SIZE = 50_000


# MCP Tool Definitions
# Each tool has: name, description, input_schema (JSON Schema)
MCP_TOOLS: list[dict[str, Any]] = [
    {
        "name": "read_file",
        "description": "Read file contents from the repository. Supports optional line range selection.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path from repository root"
                },
                "start_line": {
                    "type": "integer",
                    "description": "Starting line number (1-indexed, inclusive)"
                },
                "end_line": {
                    "type": "integer",
                    "description": "Ending line number (1-indexed, inclusive)"
                }
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
                "pattern": {
                    "type": "string",
                    "description": "Regex pattern to search for"
                },
                "file_pattern": {
                    "type": "string",
                    "description": "Optional glob pattern to filter files (e.g., '*.py')"
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of results to return (default: 50)"
                }
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
                "path": {
                    "type": "string",
                    "description": "Relative path from repository root (use '.' for root)"
                },
                "recursive": {
                    "type": "boolean",
                    "description": "If true, list all files recursively"
                },
                "pattern": {
                    "type": "string",
                    "description": "Optional glob pattern to filter items"
                },
                "max_items": {
                    "type": "integer",
                    "description": "Maximum items to return (default: 500)"
                }
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
                "status": {
                    "type": "string",
                    "description": "Filter by status (e.g., 'unreviewed', 'confirmed', 'false_positive')"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum signals to return (default: 50, max: 200)"
                }
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
                "kind": {
                    "type": "string",
                    "description": "Signal kind: 'entry_point', 'sink', or 'other'"
                },
                "label": {
                    "type": "string",
                    "description": "Human-readable label describing the signal"
                },
                "file_path": {
                    "type": "string",
                    "description": "File path relative to repository root"
                },
                "fingerprint": {
                    "type": "string",
                    "description": "Optional explicit fingerprint (auto-generated if not provided)"
                },
                "line_number": {
                    "type": "integer",
                    "description": "Line number in the file"
                },
                "status": {
                    "type": "string",
                    "description": "Signal status (e.g., 'unreviewed', 'confirmed')"
                },
                "llm_risk_tier": {
                    "type": "string",
                    "description": "Risk tier assessment (S, A, B, C, D, E)"
                },
                "llm_score": {
                    "type": "integer",
                    "description": "Risk score (0-100)"
                },
                "llm_reasoning": {
                    "type": "string",
                    "description": "Explanation of risk assessment"
                },
                "metadata": {
                    "type": "object",
                    "description": "Additional metadata"
                }
            },
            "required": ["kind", "label", "file_path"]
        }
    },
    {
        "name": "report_finding",
        "description": "Report a security vulnerability finding with full details including severity, code location, and remediation.",
        "input_schema": {
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "description": "Severity level: 'critical', 'high', 'medium', 'low', or 'info'"
                },
                "title": {
                    "type": "string",
                    "description": "Brief title for the finding"
                },
                "vulnerability_type": {
                    "type": "string",
                    "description": "Type of vulnerability (e.g., 'SQL Injection', 'XSS')"
                },
                "file_path": {
                    "type": "string",
                    "description": "Path to the vulnerable file"
                },
                "line_start": {
                    "type": "integer",
                    "description": "Starting line number (1-indexed)"
                },
                "vulnerable_code": {
                    "type": "string",
                    "description": "The vulnerable code snippet"
                },
                "description": {
                    "type": "string",
                    "description": "Detailed description of the vulnerability"
                },
                "confidence": {
                    "type": "number",
                    "description": "Confidence score (0.0 to 1.0)"
                },
                "cwe_id": {
                    "type": "string",
                    "description": "CWE identifier (e.g., 'CWE-89')"
                },
                "line_end": {
                    "type": "integer",
                    "description": "Ending line number"
                },
                "source_trace": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Data flow trace from source to sink"
                },
                "attack_scenario": {
                    "type": "string",
                    "description": "Description of how the vulnerability could be exploited"
                },
                "proof_of_concept": {
                    "type": "string",
                    "description": "Example exploit code or payload"
                },
                "recommended_fix": {
                    "type": "string",
                    "description": "Recommended remediation"
                }
            },
            "required": [
                "severity", "title", "vulnerability_type", "file_path",
                "line_start", "vulnerable_code", "description", "confidence"
            ]
        }
    },
    {
        "name": "scan_repo_for_secrets",
        "description": "Scan the repository for hardcoded secrets, API keys, and credentials using entropy analysis and pattern matching.",
        "input_schema": {
            "type": "object",
            "properties": {
                "entropy_threshold": {
                    "type": "number",
                    "description": "Minimum Shannon entropy for detection (default: 4.5)"
                }
            },
            "required": []
        }
    },
    {
        "name": "dependency_audit",
        "description": "Audit project dependencies for known vulnerabilities using lockfiles.",
        "input_schema": {
            "type": "object",
            "properties": {
                "lockfile_path": {
                    "type": "string",
                    "description": "Optional specific lockfile to audit"
                }
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
                "pattern": {
                    "type": "string",
                    "description": "Regex pattern to search for"
                },
                "context_lines": {
                    "type": "integer",
                    "description": "Number of context lines around matches (default: 3)"
                },
                "file_glob": {
                    "type": "string",
                    "description": "Glob pattern to filter files (default: '**/*')"
                }
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
                "findings": {
                    "type": "array",
                    "description": "List of ScanFinding objects to include in report",
                    "items": {
                        "type": "object"
                    }
                },
                "output_format": {
                    "type": "string",
                    "description": "Output format: 'markdown', 'json', or 'sarif' (default: 'markdown')"
                }
            },
            "required": ["findings"]
        }
    }
]


@dataclass
class MCPTool:
    """Represents an MCP tool with its handler function.

    Attributes:
        name: Tool name (matches MCP_TOOLS definition)
        description: Human-readable description
        input_schema: JSON Schema for tool parameters
        handler: Async function that implements the tool
    """
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[..., Coroutine[Any, Any, Any]]


def _truncate_output(output: str) -> str:
    """Truncate output if it exceeds MAX_OUTPUT_SIZE.

    Args:
        output: The output string to potentially truncate

    Returns:
        Original string if under limit, or truncated with notice
    """
    if len(output) <= MAX_OUTPUT_SIZE:
        return output

    # Reserve space for truncation notice
    notice = "\n\n[OUTPUT TRUNCATED]"
    truncate_at = MAX_OUTPUT_SIZE - len(notice)
    return output[:truncate_at] + notice


def create_quickhack_mcp_server(
    tool_core: ToolCore,
) -> tuple[dict[str, Any], list[MCPTool]]:
    """Create MCP server configuration and tools for quick_hack.

    This function creates wrapped handlers for each tool that:
    1. Call the corresponding ToolCore method
    2. Truncate output if necessary
    3. Format results appropriately

    Args:
        tool_core: The ToolCore instance to wrap

    Returns:
        Tuple of (server_config, list of MCPTool instances)
        server_config contains:
            - allowed_tools: List of tool names in mcp__quickhack__<name> format
    """

    # Create handler wrappers for each tool
    async def read_file_handler(
        path: str,
        start_line: int | None = None,
        end_line: int | None = None,
        **kwargs: Any,
    ) -> str:
        try:
            result = await tool_core.read_file(
                path=path,
                start_line=start_line,
                end_line=end_line,
            )
            return _truncate_output(result)
        except Exception as e:
            return json.dumps({"error": type(e).__name__, "details": str(e)})

    async def search_code_handler(
        pattern: str,
        file_pattern: str | None = None,
        max_results: int = 50,
        **kwargs: Any,
    ) -> str:
        try:
            result = await tool_core.search_code(
                pattern=pattern,
                file_pattern=file_pattern,
                max_results=max_results,
            )
            return _truncate_output(json.dumps(result, indent=2))
        except Exception as e:
            return json.dumps({"error": type(e).__name__, "details": str(e)})

    async def list_directory_handler(
        path: str = ".",
        recursive: bool = False,
        pattern: str | None = None,
        max_items: int = 500,
        **kwargs: Any,
    ) -> str:
        try:
            result = await tool_core.list_directory(
                path=path,
                recursive=recursive,
                pattern=pattern,
                max_items=max_items,
            )
            return _truncate_output(json.dumps(result, indent=2))
        except Exception as e:
            return json.dumps({"error": type(e).__name__, "details": str(e)})

    async def list_sink_signals_handler(
        status: str | None = None,
        limit: int = 50,
        **kwargs: Any,
    ) -> str:
        try:
            result = await tool_core.list_sink_signals(
                status=status,
                limit=limit,
            )
            return _truncate_output(json.dumps(result, indent=2))
        except Exception as e:
            return json.dumps({"error": type(e).__name__, "details": str(e)})

    async def upsert_sink_signal_handler(
        kind: str,
        label: str,
        file_path: str,
        fingerprint: str | None = None,
        line_number: int | None = None,
        status: str | None = None,
        llm_risk_tier: str | None = None,
        llm_score: int | None = None,
        llm_reasoning: str | None = None,
        metadata: dict | None = None,
        **kwargs: Any,
    ) -> str:
        try:
            result = await tool_core.upsert_sink_signal(
                kind=kind,
                label=label,
                file_path=file_path,
                fingerprint=fingerprint,
                line_number=line_number,
                status=status,
                llm_risk_tier=llm_risk_tier,
                llm_score=llm_score,
                llm_reasoning=llm_reasoning,
                metadata=metadata,
            )
            return _truncate_output(json.dumps(result, indent=2))
        except Exception as e:
            return json.dumps({"error": type(e).__name__, "details": str(e)})

    async def report_finding_handler(
        severity: str,
        title: str,
        vulnerability_type: str,
        file_path: str,
        line_start: int,
        vulnerable_code: str,
        description: str,
        confidence: float,
        cwe_id: str | None = None,
        line_end: int | None = None,
        source_trace: list[str] | None = None,
        attack_scenario: str | None = None,
        proof_of_concept: str | None = None,
        recommended_fix: str | None = None,
        **kwargs: Any,
    ) -> str:
        try:
            result = await tool_core.report_finding(
                severity=severity,
                title=title,
                vulnerability_type=vulnerability_type,
                file_path=file_path,
                line_start=line_start,
                vulnerable_code=vulnerable_code,
                description=description,
                confidence=confidence,
                cwe_id=cwe_id,
                line_end=line_end,
                source_trace=source_trace,
                attack_scenario=attack_scenario,
                proof_of_concept=proof_of_concept,
                recommended_fix=recommended_fix,
            )
            return _truncate_output(json.dumps(result, indent=2))
        except Exception as e:
            return json.dumps({"error": type(e).__name__, "details": str(e)})

    async def scan_repo_for_secrets_handler(
        entropy_threshold: float = 4.5,
        **kwargs: Any,
    ) -> str:
        try:
            result = await tool_core.scan_for_secrets(
                entropy_threshold=entropy_threshold,
            )
            return _truncate_output(json.dumps(result, indent=2))
        except Exception as e:
            return json.dumps({"error": type(e).__name__, "details": str(e)})

    async def dependency_audit_handler(
        lockfile_path: str | None = None,
        **kwargs: Any,
    ) -> str:
        try:
            result = await tool_core.dependency_audit(
                lockfile_path=lockfile_path,
            )
            return _truncate_output(json.dumps(result, indent=2))
        except Exception as e:
            return json.dumps({"error": type(e).__name__, "details": str(e)})

    async def grep_semantic_handler(
        pattern: str,
        context_lines: int = 3,
        file_glob: str = "**/*",
        **kwargs: Any,
    ) -> str:
        try:
            result = await tool_core.grep_semantic(
                pattern=pattern,
                context_lines=context_lines,
                file_glob=file_glob,
            )
            return _truncate_output(json.dumps(result, indent=2))
        except Exception as e:
            return json.dumps({"error": type(e).__name__, "details": str(e)})

    async def generate_security_report_handler(
        findings: list[dict[str, Any]],
        output_format: str = "markdown",
        **kwargs: Any,
    ) -> str:
        try:
            # Convert dict findings to ScanFinding objects if needed
            from services.security_scanners import ScanFinding

            scan_findings = []
            for f in findings:
                if isinstance(f, dict):
                    try:
                        scan_findings.append(ScanFinding(**f))
                    except (TypeError, ValueError) as conv_err:
                        return json.dumps({
                            "error": "ScanFindingConversionError",
                            "details": f"Failed to convert finding: {conv_err}"
                        })
                else:
                    scan_findings.append(f)

            result = await tool_core.generate_security_report(
                findings=scan_findings,
                output_format=output_format,
            )
            return _truncate_output(result)
        except Exception as e:
            return json.dumps({"error": type(e).__name__, "details": str(e)})

    # Map tool names to handlers
    handler_map: dict[str, Callable[..., Coroutine[Any, Any, Any]]] = {
        "read_file": read_file_handler,
        "search_code": search_code_handler,
        "list_directory": list_directory_handler,
        "list_sink_signals": list_sink_signals_handler,
        "upsert_sink_signal": upsert_sink_signal_handler,
        "report_finding": report_finding_handler,
        "scan_repo_for_secrets": scan_repo_for_secrets_handler,
        "dependency_audit": dependency_audit_handler,
        "grep_semantic": grep_semantic_handler,
        "generate_security_report": generate_security_report_handler,
    }

    # Create MCPTool instances
    tools: list[MCPTool] = []
    for tool_def in MCP_TOOLS:
        name = tool_def["name"]
        handler = handler_map.get(name)
        if handler is None:
            raise ValueError(f"No handler defined for tool: {name}")

        tools.append(MCPTool(
            name=name,
            description=tool_def["description"],
            input_schema=tool_def["input_schema"],
            handler=handler,
        ))

    # Create server configuration
    server_config = {
        "allowed_tools": [f"mcp__quickhack__{t.name}" for t in tools],
    }

    return server_config, tools
