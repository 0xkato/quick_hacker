"""File exploration tools for CASS agent."""

import os
import re
import fnmatch
from pathlib import Path
from typing import Optional


LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".swift": "swift",
    ".kt": "kotlin",
    ".scala": "scala",
    ".sol": "solidity",
}


class FileTools:
    """Tools for exploring the file system."""

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)

    def read_file(
        self,
        path: str,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
    ) -> str:
        """Read file contents, optionally a specific line range."""
        full_path = self.repo_path / path
        if not full_path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        content = full_path.read_text(errors="replace")

        if start_line is not None or end_line is not None:
            lines = content.split("\n")
            start = (start_line or 1) - 1
            end = end_line or len(lines)
            content = "\n".join(lines[start:end])

        return content

    def list_directory(
        self,
        path: str = ".",
        recursive: bool = False,
        include_hidden: bool = False,
    ) -> list[dict]:
        """List directory contents."""
        full_path = self.repo_path / path
        if not full_path.exists():
            raise FileNotFoundError(f"Directory not found: {path}")

        entries = []
        iterator = full_path.rglob("*") if recursive else full_path.iterdir()

        for entry in iterator:
            if not include_hidden and entry.name.startswith("."):
                continue

            rel_path = entry.relative_to(self.repo_path)
            entries.append({
                "name": entry.name,
                "path": str(rel_path),
                "is_dir": entry.is_dir(),
                "size": entry.stat().st_size if entry.is_file() else None,
                "extension": entry.suffix if entry.is_file() else None,
            })

        return sorted(entries, key=lambda x: (not x["is_dir"], x["name"]))

    def search_code(
        self,
        pattern: str,
        path: str = ".",
        file_pattern: Optional[str] = None,
        max_results: int = 100,
    ) -> list[dict]:
        """Search for regex pattern in files."""
        full_path = self.repo_path / path
        results = []
        regex = re.compile(pattern)

        for file_path in full_path.rglob("*"):
            if not file_path.is_file():
                continue
            if file_pattern and not fnmatch.fnmatch(file_path.name, file_pattern):
                continue
            if file_path.suffix not in LANGUAGE_EXTENSIONS:
                continue

            try:
                content = file_path.read_text(errors="replace")
                for i, line in enumerate(content.split("\n"), 1):
                    if regex.search(line):
                        results.append({
                            "file": str(file_path.relative_to(self.repo_path)),
                            "line": i,
                            "content": line.strip(),
                            "match": regex.search(line).group(0),
                        })
                        if len(results) >= max_results:
                            return results
            except Exception:
                continue

        return results

    def get_file_info(self, path: str) -> dict:
        """Get file metadata."""
        full_path = self.repo_path / path
        if not full_path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        stat = full_path.stat()
        content = full_path.read_text(errors="replace")

        return {
            "path": path,
            "name": full_path.name,
            "extension": full_path.suffix,
            "language": LANGUAGE_EXTENSIONS.get(full_path.suffix, "unknown"),
            "size": stat.st_size,
            "line_count": len(content.splitlines()),
            "modified": stat.st_mtime,
        }

    def find_files(
        self,
        pattern: str,
        path: str = ".",
    ) -> list[str]:
        """Find files matching a glob pattern."""
        full_path = self.repo_path / path
        matches = list(full_path.glob(pattern))
        return [str(m.relative_to(self.repo_path)) for m in matches if m.is_file()]
