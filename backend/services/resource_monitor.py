"""Resource Monitor - Tracks system resources and enforces limits.

Provides memory and CPU monitoring to prevent scans from consuming
all system resources. Can pause or cancel scans when limits are exceeded.
"""
from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass
from typing import Callable, Optional

# Try to import psutil for resource monitoring
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("[ResourceMonitor] psutil not available - resource monitoring disabled")


@dataclass
class ResourceLimits:
    """Resource limits for scans."""
    # Memory limits (percentage of system memory)
    memory_warning_pct: float = 70.0  # Warn when above this
    memory_critical_pct: float = 85.0  # Cancel scan when above this

    # CPU limits (percentage)
    cpu_warning_pct: float = 90.0
    cpu_critical_pct: float = 95.0

    # File count limits
    max_files_warning: int = 100_000  # Warn when repo has more files
    max_files_critical: int = 500_000  # Refuse to scan without override

    # Check interval
    check_interval_s: float = 10.0


@dataclass
class ResourceStatus:
    """Current resource status."""
    memory_pct: float
    cpu_pct: float
    memory_available_mb: float
    is_warning: bool
    is_critical: bool
    message: Optional[str] = None


class ResourceMonitor:
    """Monitors system resources and enforces limits."""

    def __init__(self, limits: Optional[ResourceLimits] = None):
        self.limits = limits or ResourceLimits()
        self._monitoring = False
        self._monitor_task: Optional[asyncio.Task] = None
        self._on_warning: Optional[Callable[[ResourceStatus], None]] = None
        self._on_critical: Optional[Callable[[ResourceStatus], None]] = None
        self._last_status: Optional[ResourceStatus] = None

    def get_status(self) -> ResourceStatus:
        """Get current resource status."""
        if not PSUTIL_AVAILABLE:
            return ResourceStatus(
                memory_pct=0,
                cpu_pct=0,
                memory_available_mb=0,
                is_warning=False,
                is_critical=False,
                message="psutil not available"
            )

        # Get memory info
        mem = psutil.virtual_memory()
        memory_pct = mem.percent
        memory_available_mb = mem.available / (1024 * 1024)

        # Get CPU (non-blocking, use last interval)
        cpu_pct = psutil.cpu_percent(interval=None)

        # Check thresholds
        is_warning = (
            memory_pct >= self.limits.memory_warning_pct or
            cpu_pct >= self.limits.cpu_warning_pct
        )
        is_critical = (
            memory_pct >= self.limits.memory_critical_pct or
            cpu_pct >= self.limits.cpu_critical_pct
        )

        message = None
        if is_critical:
            if memory_pct >= self.limits.memory_critical_pct:
                message = f"Critical: Memory at {memory_pct:.1f}% (limit: {self.limits.memory_critical_pct}%)"
            else:
                message = f"Critical: CPU at {cpu_pct:.1f}% (limit: {self.limits.cpu_critical_pct}%)"
        elif is_warning:
            if memory_pct >= self.limits.memory_warning_pct:
                message = f"Warning: Memory at {memory_pct:.1f}%"
            else:
                message = f"Warning: CPU at {cpu_pct:.1f}%"

        return ResourceStatus(
            memory_pct=memory_pct,
            cpu_pct=cpu_pct,
            memory_available_mb=memory_available_mb,
            is_warning=is_warning,
            is_critical=is_critical,
            message=message,
        )

    def count_repo_files(self, repo_path: str) -> int:
        """Count files in a repository (fast, doesn't read content).

        Args:
            repo_path: Absolute path to the repository (must exist)

        Returns:
            Number of source files (excluding common non-source directories)
        """
        from pathlib import Path

        count = 0
        try:
            # Validate and resolve path
            path = Path(repo_path).resolve()
            if not path.exists():
                print(f"[ResourceMonitor] Path does not exist: {repo_path}")
                return 0
            if not path.is_dir():
                print(f"[ResourceMonitor] Path is not a directory: {repo_path}")
                return 0

            # Directories to skip (non-source, dependencies, build artifacts)
            skip_dirs = {
                '.git', 'node_modules', 'vendor', '__pycache__',
                '.venv', 'venv', 'dist', 'build', '.next',
                'target', 'out', 'coverage', '.cache', '.tox',
                'eggs', '*.egg-info', '.mypy_cache', '.pytest_cache',
                'bower_components', 'jspm_packages', '.nuxt', '.output',
            }

            for root, dirs, files in os.walk(str(path)):
                # Skip non-source directories (modifies dirs in-place)
                dirs[:] = [d for d in dirs if d not in skip_dirs and not d.endswith('.egg-info')]

                # Ensure we stay within the original path (prevent symlink escapes)
                current = Path(root).resolve()
                try:
                    current.relative_to(path)
                except ValueError:
                    # Path escaped the repo directory (via symlink)
                    dirs.clear()
                    continue

                count += len(files)
                # Early exit if way over limit (just for performance)
                if count > self.limits.max_files_critical * 2:
                    break
        except PermissionError as e:
            print(f"[ResourceMonitor] Permission denied: {e}")
        except Exception as e:
            print(f"[ResourceMonitor] Error counting files: {e}")
        return count

    def check_repo_size(self, repo_path: str) -> tuple[bool, str]:
        """Check repository size and return info message.

        Args:
            repo_path: Absolute path to the repository

        Returns:
            (is_ok, message) - is_ok is always True (we don't block large repos),
            but message contains warnings for very large repos.
        """
        if not repo_path:
            return True, "No repository path provided"

        file_count = self.count_repo_files(repo_path)

        if file_count > self.limits.max_files_critical:
            return True, (
                f"Warning: Repository has {file_count:,} files. "
                f"This is a very large codebase - scan may take significant time and resources. "
                f"Consider targeting specific directories for faster results."
            )
        elif file_count > self.limits.max_files_warning:
            return True, (
                f"Warning: Repository has {file_count:,} files. "
                f"Scan may take a long time and use significant resources."
            )
        return True, f"Repository has {file_count:,} files"

    async def start_monitoring(
        self,
        on_warning: Optional[Callable[[ResourceStatus], None]] = None,
        on_critical: Optional[Callable[[ResourceStatus], None]] = None,
    ) -> None:
        """Start background resource monitoring."""
        if self._monitoring:
            return

        self._monitoring = True
        self._on_warning = on_warning
        self._on_critical = on_critical
        self._monitor_task = asyncio.create_task(self._monitor_loop())

    async def stop_monitoring(self) -> None:
        """Stop background monitoring."""
        self._monitoring = False
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
            self._monitor_task = None

    async def _monitor_loop(self) -> None:
        """Background monitoring loop."""
        # Initial CPU reading to prime the counter
        if PSUTIL_AVAILABLE:
            psutil.cpu_percent(interval=None)

        while self._monitoring:
            try:
                status = self.get_status()
                self._last_status = status

                if status.is_critical and self._on_critical:
                    self._on_critical(status)
                elif status.is_warning and self._on_warning:
                    self._on_warning(status)

                await asyncio.sleep(self.limits.check_interval_s)
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[ResourceMonitor] Error in monitor loop: {e}")
                await asyncio.sleep(self.limits.check_interval_s)


# Global instance
_resource_monitor: Optional[ResourceMonitor] = None


def get_resource_monitor() -> ResourceMonitor:
    """Get the global resource monitor instance."""
    global _resource_monitor
    if _resource_monitor is None:
        _resource_monitor = ResourceMonitor()
    return _resource_monitor
