"""Tool execution orchestration for ReAct agent.

This module provides a wrapper around the core ToolExecutor,
adding ReAct-specific functionality for duplicate detection,
flow management, and observability integration.
"""

import hashlib
import json
from typing import Optional, Tuple


class ToolCallTracker:
    """Tracks tool calls to detect duplicates and loops."""

    def __init__(self, max_duplicate_calls: int = 2, max_consecutive_duplicates: int = 3):
        """
        Initialize tool call tracker.

        Args:
            max_duplicate_calls: Maximum times same call can be made
            max_consecutive_duplicates: Maximum consecutive duplicate iterations
        """
        self._recent_tool_calls: dict[str, int] = {}  # hash -> count
        self._max_duplicate_calls = max_duplicate_calls
        self._consecutive_duplicates = 0
        self._max_consecutive_duplicates = max_consecutive_duplicates

    def hash_tool_call(self, tool_name: str, arguments: dict) -> str:
        """
        Create a hash of tool call for duplicate detection.

        Args:
            tool_name: Name of the tool
            arguments: Tool arguments

        Returns:
            Hash string of the tool call
        """
        call_str = json.dumps({"tool": tool_name, "args": arguments}, sort_keys=True)
        return hashlib.md5(call_str.encode()).hexdigest()

    def is_duplicate_call(self, tool_name: str, arguments: dict) -> Tuple[bool, int]:
        """
        Check if this tool call is a duplicate.

        Args:
            tool_name: Name of the tool
            arguments: Tool arguments

        Returns:
            Tuple of (is_duplicate, call_count)
        """
        call_hash = self.hash_tool_call(tool_name, arguments)
        count = self._recent_tool_calls.get(call_hash, 0)
        is_duplicate = count >= self._max_duplicate_calls
        return is_duplicate, count

    def record_tool_call(self, tool_name: str, arguments: dict) -> None:
        """
        Record a tool call.

        Args:
            tool_name: Name of the tool
            arguments: Tool arguments
        """
        call_hash = self.hash_tool_call(tool_name, arguments)
        self._recent_tool_calls[call_hash] = self._recent_tool_calls.get(call_hash, 0) + 1

    def record_duplicate_iteration(self) -> bool:
        """
        Record a consecutive duplicate iteration.

        Returns:
            True if max consecutive duplicates reached
        """
        self._consecutive_duplicates += 1
        return self._consecutive_duplicates >= self._max_consecutive_duplicates

    def reset_consecutive_duplicates(self) -> None:
        """Reset consecutive duplicate counter."""
        self._consecutive_duplicates = 0

    def get_consecutive_duplicates(self) -> int:
        """Get current consecutive duplicate count."""
        return self._consecutive_duplicates


class ToolArgumentParser:
    """Parses tool call arguments from various formats."""

    @staticmethod
    def parse_arguments(call: dict, index: int) -> Tuple[str, str, dict]:
        """
        Parse tool call arguments.

        Args:
            call: Tool call dictionary
            index: Call index

        Returns:
            Tuple of (tool_name, tool_call_id, arguments)
        """
        tool_name = call.get("name") or call.get("function", {}).get("name")
        tool_call_id = call.get("id", f"call_{index}")

        # Parse arguments
        args_str = call.get("arguments") or call.get("function", {}).get("arguments", "{}")
        try:
            arguments = json.loads(args_str) if isinstance(args_str, str) else args_str
        except json.JSONDecodeError:
            arguments = {}

        return tool_name, tool_call_id, arguments
