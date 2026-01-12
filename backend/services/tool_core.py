"""Shared tool implementations for both MCP tools and legacy ToolExecutor.

This module provides the core logic for all agent tools, ensuring consistent
behavior between Claude SDK (MCP) and legacy ReAct providers.
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any, Callable, Optional

from models.sink_signals import RiskTier, SinkSignal, SinkSignalKind, SinkSignalStatus
from services.security_scanners import (
    ScanFinding,
    ScanResult,
    scan_for_secrets,
    audit_dependencies,
    semantic_grep,
    generate_report,
)
from services.security_scanners.base import WorkspacePolicy, ScanLimits
from services.sink_signal_service import compute_signal_fingerprint, sink_signal_service


class ToolCore:
    """Shared tool implementations for security research agents.

    This class contains the actual implementations of all tools, which are
    called by both:
    - MCP tool handlers (for Claude SDK provider)
    - ToolExecutor methods (for legacy ReAct providers)

    Attributes:
        repo_path: Resolved path to the repository root
        project_id: Project identifier for persistence
        workspace_policy: Policy enforcing security boundaries
    """

    # Valid severity values for report_finding
    VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})

    # Default excluded directories
    DEFAULT_EXCLUDED_DIRS = frozenset({
        ".git", "node_modules", "__pycache__", ".venv", "venv",
        "dist", "build", ".next", ".nuxt", "coverage", "target",
        ".idea", ".vscode", ".cache", ".nyc_output",
    })

    # Maximum file size for reads (10MB)
    MAX_FILE_SIZE = 10 * 1024 * 1024

    def __init__(
        self,
        repo_path: str,
        project_id: str,
        agent_id: str | None = None,
        get_scan_limits: Callable[[], ScanLimits] | None = None,
    ):
        """Initialize ToolCore.

        Args:
            repo_path: Path to the repository root
            project_id: Project identifier for persistence services
            agent_id: Optional agent identifier for flow tracking
            get_scan_limits: Factory function that returns fresh ScanLimits
                            with current remaining budget
        """
        self.repo_path = Path(repo_path).resolve()
        self.project_id = project_id
        self.agent_id = agent_id
        self._get_scan_limits = get_scan_limits or (lambda: ScanLimits())

        # Create workspace policy
        self.workspace_policy = WorkspacePolicy(
            workspace_root=str(self.repo_path),
            max_file_size=self.MAX_FILE_SIZE,
            excluded_dirs=set(self.DEFAULT_EXCLUDED_DIRS),
        )

    def _validate_path(self, path: str) -> Path:
        """Validate a file path and return resolved Path.

        Args:
            path: Relative path from repo root

        Returns:
            Resolved absolute Path

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If path escapes workspace or is in excluded dir
        """
        # Build candidate path WITHOUT resolving yet
        candidate = self.repo_path / path

        # Check path traversal BEFORE checking existence
        # (WorkspacePolicy checks existence first, which would mask traversal attacks)
        resolved = candidate.resolve()
        try:
            resolved.relative_to(self.repo_path)
        except ValueError:
            raise ValueError(f"Path escapes workspace: {path}")

        # Use WorkspacePolicy for remaining validation (existence, excluded dirs, size)
        ok, reason = self.workspace_policy.validate_path(candidate)
        if not ok:
            if reason and "not exist" in reason.lower():
                raise FileNotFoundError(f"File not found: {path}")
            if reason and "excluded" in reason.lower():
                raise ValueError(f"Path in excluded directory: {path}")
            raise ValueError(f"Path rejected: {reason}")

        return resolved

    def _validate_dir(self, path: str) -> Path:
        """Validate a directory path and return resolved Path.

        Args:
            path: Relative path from repo root (use "." for root)

        Returns:
            Resolved absolute Path

        Raises:
            NotADirectoryError: If path is not a directory
            ValueError: If path escapes workspace or is symlink
        """
        candidate = self.repo_path / path

        # Check symlink BEFORE resolving
        if candidate.is_symlink():
            raise ValueError(f"Symlink directories not allowed: {path}")

        resolved = candidate.resolve()

        # Must be within workspace
        try:
            resolved.relative_to(self.repo_path)
        except ValueError:
            raise ValueError(f"Path escapes workspace: {path}")

        # Must be a directory
        if not resolved.is_dir():
            raise NotADirectoryError(f"Not a directory: {path}")

        return resolved

    async def read_file(
        self,
        path: str,
        start_line: int | None = None,
        end_line: int | None = None,
    ) -> str:
        """Read file contents with optional line range.

        Args:
            path: Relative path from repo root
            start_line: Starting line (1-indexed, inclusive)
            end_line: Ending line (1-indexed, inclusive)

        Returns:
            File content as string, with line numbers if range specified

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If path is invalid
        """
        file_path = self._validate_path(path)

        # Read file in thread to avoid blocking
        content = await asyncio.to_thread(file_path.read_text, errors="ignore")
        lines = content.split("\n")

        # No line range specified - return full content
        if start_line is None and end_line is None:
            return content

        # Apply line slicing with clamping
        total_lines = len(lines)

        # Convert to 0-indexed and clamp
        start_idx = 0
        if start_line is not None:
            start_idx = max(0, min(start_line - 1, total_lines))

        end_idx = total_lines
        if end_line is not None:
            end_idx = max(0, min(end_line, total_lines))

        # Guard against start >= end
        if start_idx >= end_idx:
            return ""

        sliced = lines[start_idx:end_idx]

        # Add line numbers
        numbered = [f"{i + start_idx + 1}: {line}" for i, line in enumerate(sliced)]
        return "\n".join(numbered)

    async def list_directory(
        self,
        path: str = ".",
        recursive: bool = False,
        pattern: str | None = None,
        max_items: int = 500,
    ) -> dict[str, Any]:
        """List directory contents.

        Args:
            path: Relative path from repo root (use "." for root)
            recursive: If True, list all files recursively
            pattern: Optional glob pattern to filter files
            max_items: Maximum items to return

        Returns:
            Dict with items list and metadata
        """
        dir_path = self._validate_dir(path)

        # Check if starting path is an excluded directory
        if dir_path != self.repo_path:  # Don't check root
            rel_parts = dir_path.relative_to(self.repo_path).parts
            for part in rel_parts:
                if part in self.DEFAULT_EXCLUDED_DIRS:
                    raise ValueError(f"Path in excluded directory: {path}")

        items: list[str] = []

        def collect_items():
            nonlocal items
            if recursive:
                for root, dirs, files in os.walk(dir_path):
                    # Filter excluded dirs
                    dirs[:] = [d for d in dirs
                              if not d.startswith(".")
                              and d not in self.DEFAULT_EXCLUDED_DIRS]

                    for f in files:
                        if f.startswith("."):
                            continue
                        if pattern and not Path(f).match(pattern):
                            continue
                        rel = (Path(root) / f).relative_to(self.repo_path)
                        items.append(str(rel))
                        if len(items) >= max_items:
                            return
            else:
                for item in sorted(dir_path.iterdir()):
                    if item.name.startswith("."):
                        continue
                    if pattern and not item.match(pattern):
                        continue
                    rel = item.relative_to(self.repo_path)
                    suffix = "/" if item.is_dir() else ""
                    items.append(f"{rel}{suffix}")
                    if len(items) >= max_items:
                        return

        await asyncio.to_thread(collect_items)

        return {
            "path": path,
            "items": items[:max_items],
            "count": len(items),
            "truncated": len(items) >= max_items,
        }

    async def search_code(
        self,
        pattern: str,
        file_pattern: str | None = None,
        max_results: int = 50,
    ) -> dict[str, Any]:
        """Search for regex pattern across codebase.

        Args:
            pattern: Regex pattern to search for
            file_pattern: Optional glob to filter files
            max_results: Maximum matches to return

        Returns:
            Dict with matches list and metadata
        """
        import re

        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}")

        results: list[dict] = []
        files_searched = 0

        def search_files():
            nonlocal results, files_searched

            for root, dirs, files in os.walk(self.repo_path):
                # Skip excluded directories
                dirs[:] = [d for d in dirs
                          if not d.startswith(".")
                          and d not in self.DEFAULT_EXCLUDED_DIRS]

                for filename in files:
                    if filename.startswith("."):
                        continue
                    if file_pattern and not Path(filename).match(file_pattern.replace("**/", "")):
                        continue

                    file_path = Path(root) / filename
                    rel_path = file_path.relative_to(self.repo_path)

                    # Skip binary files
                    if file_path.suffix in {".png", ".jpg", ".gif", ".ico", ".woff",
                                           ".ttf", ".eot", ".pdf", ".zip", ".tar", ".gz"}:
                        continue

                    try:
                        content = file_path.read_text(errors="ignore")
                        files_searched += 1

                        for i, line in enumerate(content.split("\n"), 1):
                            if regex.search(line):
                                results.append({
                                    "file": str(rel_path),
                                    "line": i,
                                    "content": line.strip()[:200]
                                })
                                if len(results) >= max_results:
                                    return
                    except Exception:
                        continue

                if len(results) >= max_results:
                    return

        await asyncio.to_thread(search_files)

        return {
            "matches": results,
            "count": len(results),
            "files_searched": files_searched,
            "truncated": len(results) >= max_results,
        }

    async def scan_for_secrets(
        self,
        entropy_threshold: float = 4.5,
    ) -> dict[str, Any]:
        """Scan repository for hardcoded secrets.

        Args:
            entropy_threshold: Minimum Shannon entropy for detection

        Returns:
            Scan result dict with findings
        """
        limits = self._get_scan_limits()

        result = await scan_for_secrets(
            policy=self.workspace_policy,
            limits=limits,
            entropy_threshold=entropy_threshold,
        )

        return self._format_scan_result(result)

    async def dependency_audit(
        self,
        lockfile_path: str | None = None,
    ) -> dict[str, Any]:
        """Audit dependencies for known vulnerabilities.

        Args:
            lockfile_path: Optional specific lockfile to audit

        Returns:
            Audit result dict with findings
        """
        limits = self._get_scan_limits()

        # Convert relative path to absolute if provided
        abs_path = None
        if lockfile_path:
            abs_path = str(self._validate_path(lockfile_path))

        result = await audit_dependencies(
            policy=self.workspace_policy,
            limits=limits,
            lockfile_path=abs_path,
        )

        return self._format_scan_result(result)

    async def grep_semantic(
        self,
        pattern: str,
        context_lines: int = 3,
        file_glob: str = "**/*",
    ) -> dict[str, Any]:
        """Search code with regex pattern and context.

        Args:
            pattern: Regex pattern to search
            context_lines: Lines of context around matches
            file_glob: Glob pattern to filter files

        Returns:
            Search result dict with findings

        Raises:
            ValueError: If pattern is not a valid regex
        """
        import re
        try:
            re.compile(pattern)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}")

        limits = self._get_scan_limits()

        result = await semantic_grep(
            policy=self.workspace_policy,
            pattern=pattern,
            limits=limits,
            context_lines=context_lines,
            file_glob=file_glob,
        )

        return self._format_scan_result(result)

    async def generate_security_report(
        self,
        findings: list[ScanFinding],
        output_format: str = "markdown",
    ) -> str:
        """Generate security report from findings.

        Args:
            findings: List of ScanFinding objects
            output_format: Output format (markdown, json, sarif)

        Returns:
            Report string in requested format

        Raises:
            ValueError: If output_format is not valid
        """
        valid_formats = {"markdown", "json", "sarif"}
        if output_format.lower() not in valid_formats:
            raise ValueError(f"Invalid format '{output_format}'. Must be one of: {valid_formats}")
        return generate_report(findings, output_format)

    def _format_scan_result(self, result: ScanResult) -> dict[str, Any]:
        """Format ScanResult to dict."""
        return {
            "success": result.success,
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            "bytes_scanned": result.bytes_scanned,
            "duration_ms": result.duration_ms,
            "cancelled": result.cancelled,
            "error": result.error,
            "findings": [f.to_dict() for f in result.findings],
        }

    async def list_sink_signals(
        self,
        status: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """List sink signals for the project.

        Args:
            status: Optional status filter
            limit: Maximum signals to return

        Returns:
            Dict with signals list and count
        """
        limit = max(1, min(limit, 200))

        parsed_status = None
        if status is not None:
            try:
                parsed_status = SinkSignalStatus(status)
            except ValueError:
                raise ValueError(f"Invalid status: {status}")

        signals = await sink_signal_service.list_signals(
            project_id=self.project_id,
            status=parsed_status,
            limit=limit,
        )

        return {
            "count": len(signals),
            "signals": [s.model_dump(mode="json") for s in signals],
        }

    async def upsert_sink_signal(
        self,
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
    ) -> dict[str, Any]:
        """Create or update a sink signal.

        Args:
            kind: Signal kind (entry_point, sink, other)
            label: Human-readable label
            file_path: File path relative to repo
            fingerprint: Optional explicit fingerprint
            line_number: Optional line number
            status: Optional status
            llm_risk_tier: Optional risk tier (S-E)
            llm_score: Optional 0-100 score
            llm_reasoning: Optional reasoning text
            metadata: Optional extra metadata

        Returns:
            Dict with created/updated signal
        """
        try:
            kind_enum = SinkSignalKind(kind)
        except ValueError:
            raise ValueError(f"Invalid kind: {kind}")

        status_enum = SinkSignalStatus.UNREVIEWED
        if status is not None:
            try:
                status_enum = SinkSignalStatus(status)
            except ValueError:
                raise ValueError(f"Invalid status: {status}")

        tier_enum = None
        if llm_risk_tier is not None:
            try:
                tier_enum = RiskTier(llm_risk_tier.strip().upper())
            except ValueError:
                raise ValueError(f"Invalid risk tier: {llm_risk_tier}")

        if llm_score is not None:
            if llm_score < 0 or llm_score > 100:
                raise ValueError("llm_score must be 0-100")

        signal_id = fingerprint or compute_signal_fingerprint(
            kind=kind_enum.value,
            file_path=file_path,
            line_number=line_number,
            label=label,
        )

        signal = SinkSignal(
            fingerprint=signal_id,
            kind=kind_enum,
            label=label,
            file_path=file_path,
            line_number=line_number,
            status=status_enum,
            source="llm",
            llm_risk_tier=tier_enum,
            llm_score=llm_score,
            llm_reasoning=llm_reasoning.strip() if llm_reasoning else None,
            metadata=metadata or {},
        )

        updated = await sink_signal_service.upsert_signals(
            project_id=self.project_id,
            signals=[signal],
        )

        result_signal = updated[0] if updated else signal
        return {"signal": result_signal.model_dump(mode="json")}

    async def report_finding(
        self,
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
    ) -> dict[str, Any]:
        """Report a security finding.

        This returns the finding data; the actual persistence is handled
        by the orchestrator after validation.

        Args:
            severity: Severity level (critical/high/medium/low/info)
            title: Finding title
            vulnerability_type: Type of vulnerability
            file_path: Path to the vulnerable file
            line_start: Starting line number (must be positive integer)
            vulnerable_code: The vulnerable code snippet
            description: Description of the vulnerability
            confidence: Confidence score (0.0 to 1.0)
            cwe_id: Optional CWE identifier
            line_end: Optional ending line (must be >= line_start if provided)
            source_trace: Optional source trace list
            attack_scenario: Optional attack scenario description
            proof_of_concept: Optional PoC code
            recommended_fix: Optional fix recommendation

        Returns:
            Dict with reported finding data

        Raises:
            ValueError: If any input validation fails
        """
        # Validate severity
        severity_lower = severity.lower()
        if severity_lower not in self.VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity}. Must be one of: {sorted(self.VALID_SEVERITIES)}"
            )

        # Validate confidence (0.0-1.0 float)
        if not isinstance(confidence, (int, float)):
            raise ValueError("confidence must be a float")
        if confidence < 0.0 or confidence > 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")

        # Validate line_start (positive integer)
        if not isinstance(line_start, int) or line_start < 1:
            raise ValueError("line_start must be a positive integer")

        # Validate line_end >= line_start if provided
        if line_end is not None:
            if not isinstance(line_end, int) or line_end < 1:
                raise ValueError("line_end must be a positive integer")
            if line_end < line_start:
                raise ValueError("line_end must be >= line_start")

        finding = {
            "severity": severity,
            "title": title,
            "vulnerability_type": vulnerability_type,
            "file_path": file_path,
            "line_start": line_start,
            "line_end": line_end,
            "vulnerable_code": vulnerable_code,
            "description": description,
            "confidence": confidence,
            "cwe_id": cwe_id,
            "source_trace": source_trace,
            "attack_scenario": attack_scenario,
            "proof_of_concept": proof_of_concept,
            "recommended_fix": recommended_fix,
        }

        return {"reported": True, "finding": finding}

    async def track_file_analysis(
        self,
        file_path: str,
        purpose: str = "analyzing"
    ) -> dict[str, Any]:
        """Track file analysis in flow tree.

        Args:
            file_path: Path relative to repo root
            purpose: Why analyzing this file

        Returns:
            dict with node_id and status
        """
        from services.flow_service import flow_service

        if not self.agent_id:
            return {"node_id": None, "status": "no_agent"}

        # Update context to track current file
        flow_service.update_context(
            self.agent_id,
            current_file=file_path,
            current_function=None,  # Reset when switching files
            call_depth=0            # Reset depth
        )

        # Create file node
        node = flow_service.add_node(
            self.agent_id,
            node_type="file",
            label=file_path,
            data={
                "file_path": file_path,
                "purpose": purpose
            },
            auto_parent=True  # Parents to investigation root
        )

        return {"node_id": node.id, "status": "tracked"}

    async def track_function_discovered(
        self,
        function_name: str,
        file_path: str,
        line_number: int,
        signature: Optional[str] = None,
        reason: Optional[str] = None
    ) -> dict[str, Any]:
        """Track function discovery in flow tree.

        Args:
            function_name: Name of the function
            file_path: File containing function
            line_number: Line where defined
            signature: Full function signature
            reason: Why it's interesting

        Returns:
            dict with node_id
        """
        from services.flow_service import flow_service

        if not self.agent_id:
            return {"node_id": None}

        # Update context
        flow_service.update_context(
            self.agent_id,
            current_function=function_name,
            current_file=file_path
        )

        # Create function node
        node = flow_service.add_node(
            self.agent_id,
            node_type="function",
            label=function_name,
            data={
                "function_name": function_name,
                "file_path": file_path,
                "line_number": line_number,
                "signature": signature,
                "reason": reason
            },
            auto_parent=True  # Parents to current file
        )

        return {"node_id": node.id}

    async def track_call_chain(
        self,
        from_function: str,
        calls: list[dict[str, str]]
    ) -> dict[str, Any]:
        """Track function call chain in flow tree.

        Args:
            from_function: Function making the calls
            calls: List of calls with 'target' and optional 'file'

        Returns:
            dict with call_nodes list
        """
        from services.flow_service import flow_service

        if not self.agent_id:
            return {"call_nodes": []}

        flow = flow_service.get_flow(self.agent_id)
        if not flow:
            return {"call_nodes": []}

        context = flow.context
        call_node_ids = []

        for call in calls:
            target = call["target"]
            target_file = call.get("file")

            # Increment call depth
            new_depth = context.call_depth + 1

            # Respect max_call_depth
            if new_depth > context.max_call_depth:
                continue

            # Update context with new depth
            flow_service.update_context(self.agent_id, call_depth=new_depth)

            # Create call node
            node = flow_service.add_node(
                self.agent_id,
                node_type="call",
                label=f"→ {target}",
                data={
                    "target_function": target,
                    "target_file": target_file,
                    "from_function": from_function,
                    "call_depth": new_depth
                },
                auto_parent=True
            )

            call_node_ids.append(node.id)

        return {"call_nodes": call_node_ids}

    async def track_sink_identified(
        self,
        sink_type: str,
        file_path: str,
        line_number: int,
        code_snippet: Optional[str] = None
    ) -> dict[str, Any]:
        """Track dangerous sink in flow tree.

        Args:
            sink_type: Type of sink (sql, exec, etc.)
            file_path: File containing sink
            line_number: Line number
            code_snippet: Code showing sink

        Returns:
            dict with node_id and marked_dangerous flag
        """
        from services.flow_service import flow_service

        if not self.agent_id:
            return {"node_id": None, "marked_dangerous": False}

        # Create dangerous_sink node
        node = flow_service.add_node(
            self.agent_id,
            node_type="dangerous_sink",
            label=f"⚠️ {sink_type.upper()} sink",
            data={
                "sink_type": sink_type,
                "file_path": file_path,
                "line_number": line_number,
                "code_snippet": code_snippet,
                "severity": "high"
            },
            auto_parent=True
        )

        return {"node_id": node.id, "marked_dangerous": True}

    async def track_entry_point(
        self,
        entry_type: str,
        file_path: str,
        line_number: int,
        route: Optional[str] = None,
        method: Optional[str] = None
    ) -> dict[str, Any]:
        """Track entry point in flow tree.

        Args:
            entry_type: Type of entry point
            file_path: File location
            line_number: Line number
            route: Route path if applicable
            method: HTTP method if applicable

        Returns:
            dict with node_id
        """
        from services.flow_service import flow_service

        if not self.agent_id:
            return {"node_id": None}

        # Build label
        label = route if route else f"{entry_type} entry point"
        if method:
            label = f"{method} {label}"

        # Create entry_point node
        node = flow_service.add_node(
            self.agent_id,
            node_type="entry_point",
            label=label,
            data={
                "entry_type": entry_type,
                "file_path": file_path,
                "line_number": line_number,
                "route": route,
                "method": method
            },
            auto_parent=True
        )

        return {"node_id": node.id}

    async def track_triage_gate(
        self,
        batch_id: str,
        raw_count: int,
        triaged_count: int,
        reportable_count: int,
        by_disposition: dict[str, int],
        policy_version: str,
        finding_refs: list[tuple[str, str]]
    ) -> dict[str, Any]:
        """Track triage gateway in flow tree.

        Args:
            batch_id: Unique batch identifier
            raw_count: Number of raw findings input
            triaged_count: Number of findings triaged (should equal raw_count)
            reportable_count: Number of reportable findings (VALID/BUG)
            by_disposition: Count by disposition
            policy_version: Triage policy version used
            finding_refs: List of (finding_id, disposition) tuples (capped at 50)

        Returns:
            Dictionary with node_id
        """
        from services.flow_service import flow_service

        if not self.agent_id:
            return {"node_id": None}

        # Build label
        filtered_count = raw_count - reportable_count
        label = f"🔍 Triage Gateway: {reportable_count}/{raw_count} reportable ({filtered_count} filtered)"

        # Prepare finding refs for data (limit to 50)
        finding_data = [
            {"id": fid, "disposition": disp}
            for fid, disp in finding_refs[:50]
        ]

        node = flow_service.add_node(
            self.agent_id,
            node_type="triage_gateway",
            label=label,
            data={
                "batch_id": batch_id,
                "raw_count": raw_count,
                "triaged_count": triaged_count,
                "reportable_count": reportable_count,
                "filtered_count": filtered_count,
                "by_disposition": by_disposition,
                "policy_version": policy_version,
                "finding_refs": finding_data,
                "total_findings": triaged_count
            },
            auto_parent=True
        )

        return {"node_id": node.id}
