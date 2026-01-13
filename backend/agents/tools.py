"""
Tools available to the security research agent.

These tools allow the agent to explore and analyze a codebase
just like a human security researcher would.
"""

import os
import re
import time
from pathlib import Path
from typing import Any, Callable, Optional
from dataclasses import dataclass

from services.coverage_tracker import CoverageTracker, PathStatus
from models.sink_signals import RiskTier, SinkSignal, SinkSignalKind, SinkSignalStatus
from services.sink_signal_service import compute_signal_fingerprint, sink_signal_service
from services.tool_core import ToolCore
from services.security_scanners import (
    ScanFinding,
    ScanLimits,
    ScanResult,
    WorkspacePolicy,
    scan_for_secrets,
    audit_dependencies,
    semantic_grep,
    generate_report,
)


@dataclass
class ToolResult:
    """Result from executing a tool."""
    success: bool
    data: Any
    error: Optional[str] = None


# Coarse exclusions for tree views (matches file_service defaults at a high level).
TREE_EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".next",
    ".nuxt",
    "venv",
    ".venv",
    "env",
    "dist",
    "build",
    ".cache",
    ".idea",
    ".vscode",
    "coverage",
    ".nyc_output",
    "target",
}

TREE_EXCLUDED_FILES = {
    ".DS_Store",
    "Thumbs.db",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Cargo.lock",
    "poetry.lock",
}


# Tool definitions for LLM (OpenAI/Anthropic format)
AGENT_TOOLS = [
    {
        "name": "read_file",
        "description": "Read the contents of a file. Use this to examine source code, configs, or any file in the repository.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "File path relative to repository root (e.g., 'src/auth/login.py')"
                },
                "start_line": {
                    "type": "integer",
                    "description": "Optional: Start reading from this line number (1-indexed)"
                },
                "end_line": {
                    "type": "integer",
                    "description": "Optional: Stop reading at this line number"
                }
            },
            "required": ["path"]
        }
    },
    {
        "name": "search_code",
        "description": "Search for a regex pattern across the codebase. Returns matching lines with file paths and line numbers. Use this to find function definitions, variable usage, import statements, etc.",
        "parameters": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Regex pattern to search for (e.g., 'def authenticate', 'os\\.system', 'eval\\s*\\(')"
                },
                "file_pattern": {
                    "type": "string",
                    "description": "Optional: Glob pattern to filter files (e.g., '*.py', '*.js', 'src/**/*.ts')"
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
        "description": "List files and directories in a path. Use this to explore the repository structure.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory path relative to repository root (use '.' for root)"
                },
                "recursive": {
                    "type": "boolean",
                    "description": "If true, list all files recursively (default: false)"
                },
                "pattern": {
                    "type": "string",
                    "description": "Optional: Filter files by glob pattern (e.g., '*.py')"
                }
            },
            "required": ["path"]
        }
    },
    {
        "name": "get_repo_tree",
        "description": "Get a hierarchical directory tree starting at a path. Use this to understand the codebase layout and pick new areas to investigate.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory path relative to repository root (use '' or '.' for root)."
                },
                "max_depth": {
                    "type": "integer",
                    "description": "Maximum depth to traverse from the given path (default: 4, max: 10)."
                },
                "max_nodes": {
                    "type": "integer",
                    "description": "Maximum total nodes to return (default: 500, max: 2000)."
                },
            },
        },
    },
    {
        "name": "list_sink_signals",
        "description": "List persistent sink signals (investigation leads) for the current project. These are NOT findings.",
        "parameters": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["unreviewed", "queued", "reviewed", "dismissed", "promoted"],
                    "description": "Optional status filter."
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of signals to return (default: 50, max: 200)."
                },
            },
        },
    },
    {
        "name": "upsert_sink_signal",
        "description": "Create or update a persistent sink signal (investigation lead) for the current project. These are NOT findings. Provide LLM-assigned score/tier when possible.",
        "parameters": {
            "type": "object",
            "properties": {
                "fingerprint": {
                    "type": "string",
                    "description": "Optional deterministic signal ID to update. If omitted, computed from kind+file+line+label."
                },
                "kind": {
                    "type": "string",
                    "enum": ["entry_point", "sink", "other"],
                    "description": "What kind of lead this is."
                },
                "label": {
                    "type": "string",
                    "description": "Short human label for the lead."
                },
                "file_path": {
                    "type": "string",
                    "description": "File path relative to repo root."
                },
                "line_number": {
                    "type": "integer",
                    "description": "Optional line number."
                },
                "status": {
                    "type": "string",
                    "enum": ["unreviewed", "queued", "reviewed", "dismissed", "promoted"],
                    "description": "Lifecycle status for this lead."
                },
                "llm_risk_tier": {
                    "type": "string",
                    "enum": ["S", "A", "B", "C", "D", "E"],
                    "description": "Optional risk tier (S highest)."
                },
                "llm_score": {
                    "type": "integer",
                    "description": "Optional 0-100 priority score assigned by the LLM."
                },
                "llm_reasoning": {
                    "type": "string",
                    "description": "Optional brief reasoning for why this lead matters."
                },
                "metadata": {
                    "type": "object",
                    "description": "Optional extra metadata."
                },
            },
            "required": ["kind", "label", "file_path"],
        },
    },
    {
        "name": "find_definition",
        "description": "Find where a function, class, or variable is defined. Useful for tracing code flow.",
        "parameters": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Name of the function, class, or variable to find"
                },
                "type": {
                    "type": "string",
                    "enum": ["function", "class", "variable", "any"],
                    "description": "Type of definition to search for (default: 'any')"
                }
            },
            "required": ["name"]
        }
    },
    {
        "name": "find_usages",
        "description": "Find all places where a function, class, or variable is used/called. Essential for tracing data flow.",
        "parameters": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Name of the function, class, or variable"
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum results to return (default: 30)"
                }
            },
            "required": ["name"]
        }
    },
    {
        "name": "get_file_structure",
        "description": "Get an overview of a file's structure - classes, functions, imports. Useful for understanding a file before diving into details.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "File path relative to repository root"
                }
            },
            "required": ["path"]
        }
    },
    {
        "name": "trace_data_flow",
        "description": "Trace how data flows from a source to potential sinks. Provide a variable or function that handles user input.",
        "parameters": {
            "type": "object",
            "properties": {
                "source": {
                    "type": "string",
                    "description": "The source variable/function to trace (e.g., 'request.form', 'user_input')"
                },
                "file_path": {
                    "type": "string",
                    "description": "File where the source is located"
                },
                "sink_patterns": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional: Patterns of dangerous sinks to look for (e.g., ['execute', 'eval', 'system'])"
                }
            },
            "required": ["source", "file_path"]
        }
    },
    {
        "name": "report_finding",
        "description": "Report a CONFIRMED security vulnerability. Only use this when you have verified the vulnerability exists with concrete evidence. False positives waste time.",
        "parameters": {
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "Severity based on exploitability and impact"
                },
                "title": {
                    "type": "string",
                    "description": "Clear, concise title (e.g., 'SQL Injection in user search')"
                },
                "vulnerability_type": {
                    "type": "string",
                    "description": "Type of vulnerability (e.g., 'SQL Injection', 'Command Injection', 'XSS')"
                },
                "cwe_id": {
                    "type": "string",
                    "description": "CWE identifier (e.g., 'CWE-89' for SQL injection)"
                },
                "file_path": {
                    "type": "string",
                    "description": "Path to the vulnerable file"
                },
                "line_start": {
                    "type": "integer",
                    "description": "Starting line number of vulnerable code"
                },
                "line_end": {
                    "type": "integer",
                    "description": "Ending line number (optional)"
                },
                "vulnerable_code": {
                    "type": "string",
                    "description": "The exact vulnerable code snippet"
                },
                "description": {
                    "type": "string",
                    "description": "Detailed explanation of the vulnerability"
                },
                "source_trace": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Step-by-step trace from user input to sink"
                },
                "attack_scenario": {
                    "type": "string",
                    "description": "How an attacker would exploit this"
                },
                "proof_of_concept": {
                    "type": "string",
                    "description": "Example payload or exploit code"
                },
                "confidence": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 1,
                    "description": "Confidence level (0.0-1.0). Only report if >= 0.8"
                },
                "recommended_fix": {
                    "type": "string",
                    "description": "How to fix this vulnerability"
                }
            },
            "required": ["severity", "title", "vulnerability_type", "file_path", "line_start", "vulnerable_code", "description", "confidence"]
        }
    },
    {
        "name": "add_investigation_note",
        "description": "Add a note to your investigation log. Use this to track your analysis, hypotheses, and things to check.",
        "parameters": {
            "type": "object",
            "properties": {
                "note": {
                    "type": "string",
                    "description": "Your investigation note"
                },
                "category": {
                    "type": "string",
                    "enum": ["hypothesis", "confirmed", "ruled_out", "todo", "observation"],
                    "description": "Category of the note"
                }
            },
            "required": ["note", "category"]
        }
    },
    {
        "name": "get_entry_points",
        "description": "Find common entry points in the application - API routes, form handlers, CLI args, etc. Good starting point for finding attack surface.",
        "parameters": {
            "type": "object",
            "properties": {
                "framework": {
                    "type": "string",
                    "description": "Optional: Framework to look for (e.g., 'flask', 'django', 'express', 'fastapi')"
                }
            }
        }
    },
    {
        "name": "scan_repo_for_secrets",
        "description": "Scan the repository for hardcoded secrets, API keys, and credentials using pattern and entropy-based detection.",
        "parameters": {
            "type": "object",
            "properties": {
                "entropy_threshold": {
                    "type": "number",
                    "description": "Minimum Shannon entropy threshold for detecting high-randomness strings (default: 4.5)"
                }
            }
        }
    },
    {
        "name": "dependency_audit",
        "description": "Audit project dependencies for known vulnerabilities by scanning lockfiles (package-lock.json, yarn.lock, requirements.txt, etc.).",
        "parameters": {
            "type": "object",
            "properties": {
                "lockfile_path": {
                    "type": "string",
                    "description": "Optional: Specific lockfile path to audit. If not provided, auto-detects lockfiles."
                }
            }
        }
    },
    {
        "name": "grep_semantic",
        "description": "Search code using regex patterns with context lines. Validates patterns to prevent ReDoS.",
        "parameters": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Regex pattern to search for (e.g., 'eval\\s*\\(', 'subprocess\\.call')"
                },
                "context_lines": {
                    "type": "integer",
                    "description": "Number of context lines before and after match (default: 3)"
                },
                "file_glob": {
                    "type": "string",
                    "description": "Glob pattern to filter files (default: '**/*', e.g., '*.py', 'src/**/*.js')"
                }
            },
            "required": ["pattern"]
        }
    },
    {
        "name": "generate_security_report",
        "description": "Generate a security report from accumulated scan findings in the specified format.",
        "parameters": {
            "type": "object",
            "properties": {
                "output_format": {
                    "type": "string",
                    "enum": ["markdown", "json", "sarif"],
                    "description": "Output format for the report (default: 'markdown')"
                }
            }
        }
    }
]


# Tool schema for reporting trace path verdicts (used for coverage visibility)
TRACE_PATH_VERDICT_SCHEMA = {
    "name": "trace_path_verdict",
    "description": "Report the conclusion of tracing a data flow path from entry point to sink. Call this after investigating each potential vulnerability path.",
    "parameters": {
        "type": "object",
        "properties": {
            "entry_point_file": {
                "type": "string",
                "description": "File path of the entry point"
            },
            "entry_point_line": {
                "type": "integer",
                "description": "Line number of the entry point"
            },
            "sink_file": {
                "type": "string",
                "description": "File path of the dangerous sink"
            },
            "sink_line": {
                "type": "integer",
                "description": "Line number of the dangerous sink"
            },
            "verdict": {
                "type": "string",
                "enum": ["safe", "vulnerable", "blocked", "inconclusive"],
                "description": "Conclusion: safe (no vuln), vulnerable (finding reported), blocked (defenses prevent exploitation), inconclusive (need more context)"
            },
            "reasoning": {
                "type": "string",
                "description": "1-2 sentence explanation of why this verdict"
            },
            "files_examined": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of files read while tracing this path"
            },
            "finding_id": {
                "type": "string",
                "description": "If verdict is 'vulnerable', the ID of the reported finding"
            }
        },
        "required": ["entry_point_file", "entry_point_line", "sink_file", "sink_line", "verdict", "reasoning", "files_examined"]
    }
}

# Add trace_path_verdict to AGENT_TOOLS
AGENT_TOOLS.append({
    "name": TRACE_PATH_VERDICT_SCHEMA["name"],
    "description": TRACE_PATH_VERDICT_SCHEMA["description"],
    "parameters": TRACE_PATH_VERDICT_SCHEMA["parameters"]
})


# Tool schema for completing the audit (gated by coverage validation)
COMPLETE_AUDIT_SCHEMA = {
    "name": "complete_audit",
    "description": "Request to complete the security audit. This will be REJECTED if coverage thresholds are not met or investigation queue is not empty. Only call when you have thoroughly investigated all discovered paths.",
    "parameters": {
        "type": "object",
        "properties": {
            "outcome": {
                "type": "string",
                "enum": ["validated_findings", "no_findings", "insufficient_coverage"],
                "description": "Final outcome: 'validated_findings' if vulns found, 'no_findings' if clean, 'insufficient_coverage' if cannot meet thresholds"
            },
            "summary": {
                "type": "string",
                "description": "Brief summary of what was investigated and concluded"
            },
            "coverage_acknowledgment": {
                "type": "boolean",
                "description": "Set to true to acknowledge you have traced all discovered paths or deferred them with reason"
            },
            "findings_count": {
                "type": "integer",
                "description": "Number of validated findings reported"
            }
        },
        "required": ["outcome", "summary", "coverage_acknowledgment"]
    }
}

# Add complete_audit to AGENT_TOOLS
AGENT_TOOLS.append({
    "name": "complete_audit",
    "description": "Request to complete the security audit. This will be REJECTED if coverage thresholds are not met or investigation queue is not empty.",
    "parameters": COMPLETE_AUDIT_SCHEMA["parameters"]
})

# Build tool definition lookup for validation
TOOL_DEFINITIONS = {tool["name"]: tool for tool in AGENT_TOOLS}


class ToolExecutor:
    """Executes tools for the security research agent."""

    # Default time budget of 10 minutes if not specified
    DEFAULT_TIME_BUDGET_MS = 600_000

    def __init__(
        self,
        repo_path: str,
        project_id: Optional[str] = None,
        time_budget_ms: Optional[int] = None,
        cache: Optional["ToolCache"] = None,
    ):
        self.repo_path = Path(repo_path)
        self.project_id = project_id
        self.investigation_notes: list[dict] = []

        # Security scanner support
        self._session_start = time.monotonic()
        budget_ms = time_budget_ms if time_budget_ms is not None else self.DEFAULT_TIME_BUDGET_MS
        self._total_budget_s = budget_ms / 1000.0
        self._security_scan_findings: dict[str, ScanFinding] = {}
        self._findings_cap = 500

        # Shared ToolCore for delegated implementations
        self._tool_core = ToolCore(
            repo_path=str(self.repo_path),
            project_id=project_id or "",
            get_scan_limits=self._make_scan_limits,
            cache=cache,
        )

    def _safe_path(self, path: str) -> Path:
        """Ensure path doesn't escape repository."""
        full_path = (self.repo_path / path).resolve()
        repo_root = self.repo_path.resolve()
        try:
            full_path.relative_to(repo_root)
        except ValueError:
            raise ValueError(f"Path escapes repository: {path}")
        return full_path

    def _remaining_budget_s(self) -> float:
        """Calculate remaining time budget in seconds."""
        elapsed = time.monotonic() - self._session_start
        return max(0.0, self._total_budget_s - elapsed)

    def _make_scan_limits(self) -> ScanLimits:
        """Create ScanLimits with deadline based on remaining budget."""
        deadline = time.monotonic() + self._remaining_budget_s()
        return ScanLimits(deadline=deadline)

    def _accumulate_security_findings(self, findings: list[ScanFinding]) -> None:
        """Accumulate security findings, deduplicating by fingerprint and capping at limit."""
        for finding in findings:
            # Use fingerprint from details if available, otherwise create one from file+line
            fingerprint = finding.details.get("fingerprint")
            if not fingerprint:
                fingerprint = f"{finding.file_path}:{finding.line_start}:{finding.title}"

            # Skip if already accumulated
            if fingerprint in self._security_scan_findings:
                continue

            # Check cap
            if len(self._security_scan_findings) >= self._findings_cap:
                break

            self._security_scan_findings[fingerprint] = finding

    def _format_security_scan_result(self, result: ScanResult) -> dict:
        """Format a ScanResult into a data dict for ToolResult."""
        return {
            "success": result.success,
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            "bytes_scanned": result.bytes_scanned,
            "duration_ms": result.duration_ms,
            "cancelled": result.cancelled,
            "error": result.error,
            "findings": [f.to_dict() for f in result.findings],
            "total_accumulated": len(self._security_scan_findings),
        }

    def _make_workspace_policy(self) -> WorkspacePolicy:
        """Create a WorkspacePolicy for the repository."""
        return WorkspacePolicy(
            workspace_root=str(self.repo_path),
            max_file_size=10 * 1024 * 1024,  # 10MB
            excluded_dirs={
                ".git", "node_modules", "__pycache__", ".venv", "venv",
                "dist", "build", ".next", ".nuxt", "coverage", "target",
            },
        )

    async def execute(self, tool_name: str, arguments: dict) -> ToolResult:
        """Execute a tool and return the result."""
        try:
            method = getattr(self, f"_tool_{tool_name}", None)
            if not method:
                return ToolResult(False, None, f"Unknown tool: {tool_name}")

            # Validate required arguments
            tool_def = TOOL_DEFINITIONS.get(tool_name)
            if tool_def:
                required = tool_def.get("parameters", {}).get("required", [])
                missing = [arg for arg in required if arg not in arguments]
                if missing:
                    return ToolResult(
                        False, None,
                        f"Missing required argument(s): {', '.join(missing)}. "
                        f"Tool {tool_name} requires: {', '.join(required)}"
                    )

            return await method(**arguments)
        except Exception as e:
            return ToolResult(False, None, str(e))

    async def _tool_read_file(
        self,
        path: str,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None
    ) -> ToolResult:
        """Read file contents. Delegates to ToolCore."""
        try:
            result = await self._tool_core.read_file(path, start_line, end_line)
            content = result["content"]

            # ToolCore returns content without line numbers when no range is specified
            # Add line numbers for consistency with legacy behavior
            if start_line is None and end_line is None:
                lines = content.split('\n')
                numbered = [f"{i + 1}: {line}" for i, line in enumerate(lines)]
                return ToolResult(True, '\n'.join(numbered))

            return ToolResult(True, content)
        except FileNotFoundError:
            return ToolResult(False, None, f"File not found: {path}")
        except ValueError as e:
            return ToolResult(False, None, str(e))
        except Exception as e:
            return ToolResult(False, None, str(e))

    async def _tool_search_code(
        self,
        pattern: str,
        file_pattern: Optional[str] = None,
        max_results: int = 50
    ) -> ToolResult:
        """Search for pattern in codebase. Delegates to ToolCore."""
        try:
            result = await self._tool_core.search_code(pattern, file_pattern, max_results)
            return ToolResult(True, result)
        except ValueError as e:
            # ToolCore raises ValueError for invalid regex
            return ToolResult(False, None, f"Invalid regex: {e}")
        except Exception as e:
            return ToolResult(False, None, str(e))

    async def _tool_list_directory(
        self,
        path: str = ".",
        recursive: bool = False,
        pattern: Optional[str] = None
    ) -> ToolResult:
        """List directory contents. Delegates to ToolCore."""
        try:
            result = await self._tool_core.list_directory(path, recursive, pattern)
            return ToolResult(True, result)
        except NotADirectoryError:
            return ToolResult(False, None, f"Not a directory: {path}")
        except FileNotFoundError:
            return ToolResult(False, None, f"Directory not found: {path}")
        except ValueError as e:
            return ToolResult(False, None, str(e))
        except Exception as e:
            return ToolResult(False, None, str(e))

    async def _tool_get_repo_tree(
        self,
        path: str = ".",
        max_depth: int = 4,
        max_nodes: int = 500,
    ) -> ToolResult:
        """Return a hierarchical repo tree starting at `path`."""
        normalized = (path or ".").strip() or "."
        try:
            max_depth = int(max_depth)
        except Exception:
            max_depth = 4
        try:
            max_nodes = int(max_nodes)
        except Exception:
            max_nodes = 500

        max_depth = max(0, min(max_depth, 10))
        max_nodes = max(1, min(max_nodes, 2000))

        try:
            root_path = self._safe_path(normalized)
        except Exception as e:
            return ToolResult(False, None, str(e))

        if not root_path.exists():
            return ToolResult(False, None, f"Directory not found: {path}")
        if not root_path.is_dir():
            return ToolResult(False, None, f"Not a directory: {path}")
        if root_path.is_symlink():
            return ToolResult(False, None, f"Symlinks are not supported: {path}")

        repo_root = self.repo_path.resolve()
        nodes_used = 0
        truncated = False

        def build_tree(node_path: Path, depth: int) -> Optional[dict]:
            nonlocal nodes_used, truncated
            if nodes_used >= max_nodes:
                truncated = True
                return None

            try:
                rel = node_path.resolve().relative_to(repo_root)
            except Exception:
                return None

            rel_posix = rel.as_posix()
            rel_str = "" if rel_posix == "." else rel_posix
            name = node_path.name if rel_str else "."

            is_dir = node_path.is_dir()
            node: dict[str, Any] = {"name": name, "path": rel_str, "is_dir": is_dir}
            nodes_used += 1

            if not is_dir or depth >= max_depth:
                return node

            children: list[dict] = []
            try:
                entries = sorted(
                    list(node_path.iterdir()),
                    key=lambda p: (not p.is_dir(), p.name.lower()),
                )
            except Exception:
                entries = []

            for entry in entries:
                if nodes_used >= max_nodes:
                    truncated = True
                    break

                if entry.is_symlink():
                    continue

                if entry.is_dir():
                    if entry.name.startswith(".") or entry.name in TREE_EXCLUDED_DIRS:
                        continue
                else:
                    if entry.name.startswith(".") or entry.name in TREE_EXCLUDED_FILES:
                        continue

                child = build_tree(entry, depth + 1)
                if child is not None:
                    children.append(child)

            node["children"] = children
            return node

        tree = build_tree(root_path, 0)
        if tree is None:
            tree = {"name": ".", "path": "", "is_dir": True, "children": []}
            truncated = True

        return ToolResult(
            True,
            {
                "path": ("" if normalized in (".", "") else normalized),
                "max_depth": max_depth,
                "max_nodes": max_nodes,
                "nodes_returned": nodes_used,
                "truncated": truncated,
                "tree": tree,
            },
        )

    async def _tool_list_sink_signals(
        self,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> ToolResult:
        """List persistent sink signals for the current project."""
        if not self.project_id:
            return ToolResult(False, None, "No project_id is set for this tool executor.")

        try:
            limit = int(limit)
        except Exception:
            limit = 50
        limit = max(1, min(limit, 200))

        parsed_status: Optional[SinkSignalStatus] = None
        if status is not None:
            try:
                parsed_status = SinkSignalStatus(str(status))
            except Exception:
                return ToolResult(False, None, f"Invalid status: {status}")

        signals = await sink_signal_service.list_signals(
            project_id=self.project_id,
            status=parsed_status,
            limit=limit,
        )
        return ToolResult(
            True,
            {
                "count": len(signals),
                "signals": [s.model_dump(mode="json") for s in signals],
            },
        )

    async def _tool_upsert_sink_signal(
        self,
        kind: str,
        label: str,
        file_path: str,
        fingerprint: Optional[str] = None,
        line_number: Optional[int] = None,
        status: Optional[str] = None,
        llm_risk_tier: Optional[str] = None,
        llm_score: Optional[int] = None,
        llm_reasoning: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> ToolResult:
        """Create or update a persistent sink signal for the current project."""
        if not self.project_id:
            return ToolResult(False, None, "No project_id is set for this tool executor.")

        try:
            kind_enum = SinkSignalKind(str(kind))
        except Exception:
            return ToolResult(False, None, f"Invalid kind: {kind}")

        status_enum = SinkSignalStatus.UNREVIEWED
        if status is not None:
            try:
                status_enum = SinkSignalStatus(str(status))
            except Exception:
                return ToolResult(False, None, f"Invalid status: {status}")

        tier_enum: Optional[RiskTier] = None
        if llm_risk_tier is not None:
            try:
                tier_enum = RiskTier(str(llm_risk_tier).strip().upper())
            except Exception:
                return ToolResult(False, None, f"Invalid llm_risk_tier: {llm_risk_tier}")

        score_val: Optional[int] = None
        if llm_score is not None:
            try:
                score_val = int(llm_score)
            except Exception:
                return ToolResult(False, None, "Invalid llm_score (expected integer 0-100).")
            if score_val < 0 or score_val > 100:
                return ToolResult(False, None, "Invalid llm_score (expected integer 0-100).")

        signal_id = fingerprint or compute_signal_fingerprint(
            kind=kind_enum.value,
            file_path=str(file_path),
            line_number=int(line_number) if line_number is not None else None,
            label=str(label),
        )

        signal = SinkSignal(
            fingerprint=signal_id,
            kind=kind_enum,
            label=str(label),
            file_path=str(file_path),
            line_number=int(line_number) if line_number is not None else None,
            status=status_enum,
            source="llm",
            llm_risk_tier=tier_enum,
            llm_score=score_val,
            llm_reasoning=str(llm_reasoning).strip() if llm_reasoning else None,
            metadata=metadata or {},
        )

        updated = await sink_signal_service.upsert_signals(
            project_id=self.project_id,
            signals=[signal],
        )
        result_signal = updated[0] if updated else signal
        return ToolResult(True, {"signal": result_signal.model_dump(mode="json")})

    async def _tool_find_definition(
        self,
        name: str,
        type: str = "any"
    ) -> ToolResult:
        """Find where something is defined."""
        patterns = {
            'function': [
                rf'def\s+{re.escape(name)}\s*\(',  # Python
                rf'function\s+{re.escape(name)}\s*\(',  # JS
                rf'const\s+{re.escape(name)}\s*=\s*(?:async\s*)?\(',  # Arrow function
                rf'func\s+{re.escape(name)}\s*\(',  # Go
                rf'fn\s+{re.escape(name)}\s*\(',  # Rust
            ],
            'class': [
                rf'class\s+{re.escape(name)}[\s:(]',  # Python/JS
                rf'type\s+{re.escape(name)}\s+struct',  # Go
                rf'struct\s+{re.escape(name)}\s*{{',  # Rust
            ],
            'variable': [
                rf'{re.escape(name)}\s*=',
                rf'const\s+{re.escape(name)}\s*=',
                rf'let\s+{re.escape(name)}\s*=',
                rf'var\s+{re.escape(name)}\s*=',
            ]
        }

        if type == 'any':
            search_patterns = patterns['function'] + patterns['class'] + patterns['variable']
        else:
            search_patterns = patterns.get(type, [])

        combined_pattern = '|'.join(f'({p})' for p in search_patterns)
        return await self._tool_search_code(combined_pattern, max_results=20)

    async def _tool_find_usages(
        self,
        name: str,
        max_results: int = 30
    ) -> ToolResult:
        """Find all usages of a name."""
        # Match the name as a word (not part of another word)
        pattern = rf'\b{re.escape(name)}\b'
        return await self._tool_search_code(pattern, max_results=max_results)

    async def _tool_get_file_structure(self, path: str) -> ToolResult:
        """Get overview of file structure."""
        try:
            file_path = self._safe_path(path)
            if not file_path.exists():
                return ToolResult(False, None, f"File not found: {path}")

            content = file_path.read_text(errors='ignore')
            lines = content.split('\n')

            structure = {
                'imports': [],
                'classes': [],
                'functions': [],
                'routes': [],
                'line_count': len(lines)
            }

            for i, line in enumerate(lines, 1):
                stripped = line.strip()

                # Imports
                if stripped.startswith(('import ', 'from ')) or 'require(' in stripped:
                    structure['imports'].append({'line': i, 'content': stripped[:100]})

                # Classes
                if re.match(r'^class\s+\w+', stripped):
                    match = re.match(r'class\s+(\w+)', stripped)
                    if match:
                        structure['classes'].append({'line': i, 'name': match.group(1)})

                # Functions
                if re.match(r'^(async\s+)?def\s+\w+', stripped) or re.match(r'^(async\s+)?function\s+\w+', stripped):
                    match = re.search(r'(?:def|function)\s+(\w+)', stripped)
                    if match:
                        structure['functions'].append({'line': i, 'name': match.group(1)})

                # Routes/endpoints
                if re.search(r'@(app|router|blueprint)\.(get|post|put|delete|patch|route)', stripped, re.IGNORECASE):
                    structure['routes'].append({'line': i, 'content': stripped[:100]})
                if re.search(r'\.(get|post|put|delete|patch)\s*\([\'"]', stripped, re.IGNORECASE):
                    structure['routes'].append({'line': i, 'content': stripped[:100]})

            return ToolResult(True, structure)

        except Exception as e:
            return ToolResult(False, None, str(e))

    async def _tool_trace_data_flow(
        self,
        source: str,
        file_path: str,
        sink_patterns: Optional[list[str]] = None
    ) -> ToolResult:
        """Trace data flow from source to sinks."""
        default_sinks = [
            'execute', 'exec', 'eval', 'system', 'popen', 'subprocess',
            'query', 'raw', 'cursor', 'execute_sql',
            'render', 'innerHTML', 'document.write',
            'open', 'read', 'write', 'readFile', 'writeFile',
            'redirect', 'send', 'sendFile',
            'pickle', 'load', 'loads', 'yaml.load',
            'shell', 'spawn', 'fork'
        ]

        sinks = sink_patterns or default_sinks

        # Read the file
        file_result = await self._tool_read_file(file_path)
        if not file_result.success:
            return file_result

        content = file_result.data
        lines = content.split('\n')

        # Find source usages
        source_lines = []
        sink_lines = []

        source_pattern = re.compile(re.escape(source), re.IGNORECASE)
        sink_pattern = re.compile('|'.join(rf'\b{re.escape(s)}\b' for s in sinks), re.IGNORECASE)

        for line in lines:
            # Extract line number and content
            match = re.match(r'^(\d+):\s*(.*)$', line)
            if not match:
                continue
            line_num = int(match.group(1))
            line_content = match.group(2)

            if source_pattern.search(line_content):
                source_lines.append({'line': line_num, 'content': line_content.strip()[:150]})

            if sink_pattern.search(line_content):
                sink_lines.append({'line': line_num, 'content': line_content.strip()[:150]})

        # Look for potential flows (source and sink in proximity)
        potential_flows = []
        for src in source_lines:
            for sink in sink_lines:
                if abs(src['line'] - sink['line']) < 50:  # Within 50 lines
                    potential_flows.append({
                        'source': src,
                        'sink': sink,
                        'distance': abs(src['line'] - sink['line'])
                    })

        return ToolResult(True, {
            'source': source,
            'file': file_path,
            'source_occurrences': source_lines[:20],
            'sink_occurrences': sink_lines[:20],
            'potential_flows': sorted(potential_flows, key=lambda x: x['distance'])[:10],
            'needs_manual_review': len(potential_flows) > 0
        })

    async def _tool_report_finding(self, **kwargs) -> ToolResult:
        """Report a finding - this is handled specially by the agent."""
        # The agent loop will intercept this and create a proper Finding
        return ToolResult(True, {'reported': True, 'finding': kwargs})

    async def _tool_add_investigation_note(
        self,
        note: str,
        category: str = "observation"
    ) -> ToolResult:
        """Add investigation note."""
        self.investigation_notes.append({
            'note': note,
            'category': category
        })
        return ToolResult(True, f"Note added ({category}): {note[:50]}...")

    async def _tool_get_entry_points(
        self,
        framework: Optional[str] = None
    ) -> ToolResult:
        """Find application entry points."""
        entry_patterns = {
            'flask': [
                r'@app\.route\s*\([\'"]([^\'"]+)',
                r'@blueprint\.route\s*\([\'"]([^\'"]+)',
            ],
            'django': [
                r'path\s*\([\'"]([^\'"]+)',
                r'url\s*\([\'"]([^\'"]+)',
            ],
            'fastapi': [
                r'@app\.(get|post|put|delete|patch)\s*\([\'"]([^\'"]+)',
                r'@router\.(get|post|put|delete|patch)\s*\([\'"]([^\'"]+)',
            ],
            'express': [
                r'app\.(get|post|put|delete|patch)\s*\([\'"]([^\'"]+)',
                r'router\.(get|post|put|delete|patch)\s*\([\'"]([^\'"]+)',
            ],
            'generic': [
                r'@(Get|Post|Put|Delete|Patch)Mapping\s*\([\'"]?([^\'")\s]+)',  # Spring
                r'func\s+\w+Handler',  # Go handlers
                r'def\s+(get|post|put|delete|patch)_\w+',  # Common REST patterns
            ]
        }

        patterns_to_use = []
        if framework and framework in entry_patterns:
            patterns_to_use = entry_patterns[framework]
        else:
            for p_list in entry_patterns.values():
                patterns_to_use.extend(p_list)

        all_entries = []
        for pattern in patterns_to_use:
            result = await self._tool_search_code(pattern, max_results=100)
            if result.success and result.data.get('matches'):
                all_entries.extend(result.data['matches'])

        # Also find CLI argument parsing
        cli_result = await self._tool_search_code(
            r'(argparse|argv|getopt|click\.command|typer\.command)',
            max_results=20
        )
        if cli_result.success and cli_result.data.get('matches'):
            all_entries.extend([
                {**m, 'type': 'cli'} for m in cli_result.data['matches']
            ])

        # Find form handlers
        form_result = await self._tool_search_code(
            r'(request\.(form|data|json|args|files)|req\.body|FormData)',
            max_results=50
        )
        if form_result.success and form_result.data.get('matches'):
            all_entries.extend([
                {**m, 'type': 'user_input'} for m in form_result.data['matches']
            ])

        return ToolResult(True, {
            'entry_points': all_entries[:100],
            'count': len(all_entries),
            'truncated': len(all_entries) > 100
        })

    async def _tool_scan_repo_for_secrets(
        self,
        entropy_threshold: float = 4.5,
    ) -> ToolResult:
        """Scan repository for hardcoded secrets and credentials."""
        try:
            policy = self._make_workspace_policy()
            limits = self._make_scan_limits()

            result = await scan_for_secrets(
                policy=policy,
                limits=limits,
                entropy_threshold=entropy_threshold,
            )

            # Accumulate findings
            self._accumulate_security_findings(result.findings)

            return ToolResult(True, self._format_security_scan_result(result))
        except Exception as e:
            return ToolResult(False, None, str(e))

    async def _tool_dependency_audit(
        self,
        lockfile_path: Optional[str] = None,
    ) -> ToolResult:
        """Audit dependencies for known vulnerabilities."""
        try:
            policy = self._make_workspace_policy()
            limits = self._make_scan_limits()

            # Convert relative path to absolute if provided
            abs_lockfile_path = None
            if lockfile_path:
                abs_lockfile_path = str(self._safe_path(lockfile_path))

            result = await audit_dependencies(
                policy=policy,
                limits=limits,
                lockfile_path=abs_lockfile_path,
            )

            # Accumulate findings
            self._accumulate_security_findings(result.findings)

            return ToolResult(True, self._format_security_scan_result(result))
        except Exception as e:
            return ToolResult(False, None, str(e))

    async def _tool_grep_semantic(
        self,
        pattern: str,
        context_lines: int = 3,
        file_glob: str = "**/*",
    ) -> ToolResult:
        """Search code using regex patterns with context."""
        try:
            policy = self._make_workspace_policy()
            limits = self._make_scan_limits()

            result = await semantic_grep(
                policy=policy,
                pattern=pattern,
                limits=limits,
                context_lines=context_lines,
                file_glob=file_glob,
            )

            if not result.success:
                return ToolResult(False, None, result.error or "Grep failed")

            # Accumulate findings
            self._accumulate_security_findings(result.findings)

            return ToolResult(True, self._format_security_scan_result(result))
        except Exception as e:
            return ToolResult(False, None, str(e))

    async def _tool_generate_security_report(
        self,
        output_format: str = "markdown",
    ) -> ToolResult:
        """Generate a security report from accumulated findings."""
        try:
            # Get all accumulated findings
            findings = list(self._security_scan_findings.values())

            # Generate report
            report = generate_report(findings, output_format)

            return ToolResult(True, {
                "report": report,
                "format": output_format,
                "findings_count": len(findings),
            })
        except ValueError as e:
            return ToolResult(False, None, str(e))
        except Exception as e:
            return ToolResult(False, None, str(e))


def handle_trace_path_verdict(
    args: dict,
    coverage_tracker: CoverageTracker,
    broadcast_fn: Callable[[str, dict], None]
) -> str:
    """Handle trace_path_verdict tool call."""
    status_map = {
        "safe": PathStatus.TRACED_SAFE,
        "vulnerable": PathStatus.TRACED_VULN,
        "blocked": PathStatus.BLOCKED,
        "inconclusive": PathStatus.INCONCLUSIVE
    }

    # Find or auto-register the path
    record = coverage_tracker.find_path_by_locations(
        args["entry_point_file"],
        args["entry_point_line"],
        args["sink_file"],
        args["sink_line"]
    )

    if record is None:
        # Auto-register discovered path
        path_id = coverage_tracker.register_path(
            entry_point_file=args["entry_point_file"],
            entry_point_line=args["entry_point_line"],
            entry_point_name="discovered",
            sink_file=args["sink_file"],
            sink_line=args["sink_line"],
            sink_type="unknown",
            sink_function="unknown"
        )
        record = coverage_tracker.paths[path_id]

    # Update status
    coverage_tracker.update_status(
        record.id,
        status_map[args["verdict"]],
        reasoning=args["reasoning"],
        finding_id=args.get("finding_id"),
        files_in_path=args["files_examined"]
    )

    # Broadcast update
    stats = coverage_tracker.get_coverage_stats()
    broadcast_fn("COVERAGE_UPDATE", {
        "path_id": record.id,
        "entry_point": f"{args['entry_point_file']}:{args['entry_point_line']}",
        "sink": f"{args['sink_file']}:{args['sink_line']}",
        "status": args["verdict"],
        "stats": {
            "total": stats.total_paths,
            "traced": stats.traced_count,
            "remaining": stats.discovered_count + stats.inconclusive_count,
            "coverage_percent": stats.coverage_percent
        }
    })

    return f"Recorded verdict '{args['verdict']}' for path {args['entry_point_file']}:{args['entry_point_line']} -> {args['sink_file']}:{args['sink_line']}"
