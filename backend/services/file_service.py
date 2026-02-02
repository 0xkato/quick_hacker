"""File operations service for quick_hack."""

import asyncio
import os
from pathlib import Path
from typing import Optional

import aiofiles

from models.schemas import FileNode, FileContent


# Extensions to exclude from tree
EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".next",
    ".nuxt",
    "venv",
    ".venv",
    "env",
    ".env",
    "dist",
    "build",
    ".cache",
    ".idea",
    ".vscode",
    "coverage",
    ".nyc_output",
    "target",  # Rust/Java
}

# Files to exclude
EXCLUDED_FILES = {
    ".DS_Store",
    "Thumbs.db",
    ".gitignore",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Cargo.lock",
    "poetry.lock",
}

# Binary extensions to skip reading
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".wav", ".avi", ".mov",
    ".pyc", ".pyo", ".class",
}


# Extension to language mapping for syntax highlighting
EXTENSION_TO_LANGUAGE = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".json": "json",
    ".html": "html",
    ".htm": "html",
    ".css": "css",
    ".scss": "scss",
    ".sass": "sass",
    ".less": "less",
    ".md": "markdown",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".xml": "xml",
    ".sql": "sql",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin",
    ".scala": "scala",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
    ".r": "r",
    ".R": "r",
    ".lua": "lua",
    ".pl": "perl",
    ".ex": "elixir",
    ".exs": "elixir",
    ".erl": "erlang",
    ".hs": "haskell",
    ".clj": "clojure",
    ".vue": "vue",
    ".svelte": "svelte",
    ".sol": "solidity",
    ".toml": "toml",
    ".ini": "ini",
    ".cfg": "ini",
    ".conf": "ini",
    ".dockerfile": "dockerfile",
    ".graphql": "graphql",
    ".gql": "graphql",
    ".proto": "protobuf",
    ".tf": "terraform",
    ".hcl": "hcl",
}


def get_language(file_path: str) -> Optional[str]:
    """Get language identifier for a file path."""
    ext = Path(file_path).suffix.lower()

    # Check special file names
    name = Path(file_path).name.lower()
    if name == "dockerfile":
        return "dockerfile"
    if name == "makefile":
        return "makefile"
    if name in (".env", ".env.local", ".env.example"):
        return "shell"

    return EXTENSION_TO_LANGUAGE.get(ext)


def is_binary_file(file_path: str) -> bool:
    """Check if file is likely binary."""
    ext = Path(file_path).suffix.lower()
    return ext in BINARY_EXTENSIONS


def should_include_in_tree(name: str, is_dir: bool) -> bool:
    """Check if file/directory should be included in tree."""
    if is_dir:
        return name not in EXCLUDED_DIRS
    return name not in EXCLUDED_FILES and not name.startswith(".")


async def get_file_tree(
    repo_path: str,
    max_depth: int = 10,
    *,
    start_path: str = "",
    max_children: int = 1000,
    max_nodes: int = 20_000,
) -> FileNode:
    """Build a (possibly shallow) file tree for a repository.

    Notes:
      - This is used by the file explorer UI and must stay responsive even for huge repos.
      - For performance, we avoid stat() calls for every file (size is omitted by default)
        and we stop traversing at max_depth (children will be None for deeper dirs).
    """
    repo_root = Path(repo_path).resolve()
    start_dir = (repo_root / start_path).resolve()

    # Security check - prevent path traversal (and avoid scanning outside repo root)
    try:
        start_dir.relative_to(repo_root)
    except ValueError as e:
        raise ValueError("Invalid start_path - path traversal detected") from e

    if not start_dir.exists():
        raise FileNotFoundError(f"Path not found: {start_path}")

    if not start_dir.is_dir():
        raise ValueError(f"Not a directory: {start_path}")

    node_count = 0

    def build_tree(
        path: Path,
        depth: int = 0,
        *,
        name: str | None = None,
        is_dir: bool | None = None,
        is_symlink: bool | None = None,
    ) -> Optional[FileNode]:
        nonlocal node_count

        if depth > max_depth:
            return None

        if node_count >= max_nodes:
            return None

        # Do not traverse or expose symlinks (prevents escape + huge walks)
        if is_symlink is None:
            try:
                is_symlink = path.is_symlink()
            except OSError:
                return None
        if is_symlink:
            return None

        if name is None:
            name = path.name or path.as_posix()

        if is_dir is None:
            try:
                is_dir = path.is_dir()
            except OSError:
                return None

        if not should_include_in_tree(name, is_dir):
            return None

        node_count += 1

        # Calculate relative path from repo root
        try:
            rel_path = path.relative_to(repo_root).as_posix()
        except ValueError:
            # Should never happen because we never traverse outside repo_root.
            return None

        node = FileNode(
            name=name,
            path=rel_path if rel_path != "." else "",
            is_dir=is_dir,
        )

        if is_dir:
            # Stop traversing deeper. Leaving children unset tells the UI that this folder
            # can be lazily expanded with a follow-up request.
            if depth >= max_depth:
                return node

            children = []
            try:
                with os.scandir(path) as it:
                    # Gather entries first so we can sort (dirs first, then name).
                    entries: list[tuple[os.DirEntry, bool]] = []
                    for entry in it:
                        try:
                            entry_is_dir = entry.is_dir(follow_symlinks=False)
                        except OSError:
                            continue

                        if not should_include_in_tree(entry.name, entry_is_dir):
                            continue

                        entries.append((entry, entry_is_dir))
                        if len(entries) >= max_children:
                            break

                    entries.sort(key=lambda pair: (not pair[1], pair[0].name.lower()))

                    for entry, entry_is_dir in entries:
                        if node_count >= max_nodes:
                            break
                        child = build_tree(
                            Path(entry.path),
                            depth + 1,
                            name=entry.name,
                            is_dir=entry_is_dir,
                            is_symlink=entry.is_symlink(),
                        )
                        if child:
                            children.append(child)
            except (PermissionError, FileNotFoundError, NotADirectoryError):
                pass

            node.children = children
        else:
            node.extension = path.suffix.lower() if path.suffix else None

        return node

    # Building the full tree can be expensive for large repos and will block the event loop if run inline.
    # Run it in a worker thread to keep the API responsive.
    return await asyncio.to_thread(build_tree, start_dir)


async def read_file(repo_path: str, file_path: str) -> FileContent:
    """Read file content from repository."""
    full_path = Path(repo_path) / file_path

    # Security check - prevent path traversal
    full_path = full_path.resolve()
    repo_root = Path(repo_path).resolve()
    try:
        full_path.relative_to(repo_root)
    except ValueError:
        raise ValueError("Invalid file path - path traversal detected")

    if not full_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    if not full_path.is_file():
        raise ValueError(f"Not a file: {file_path}")

    if is_binary_file(file_path):
        raise ValueError(f"Binary file cannot be read: {file_path}")

    # Read file content
    try:
        async with aiofiles.open(full_path, "r", encoding="utf-8", errors="replace") as f:
            content = await f.read()
    except Exception as e:
        raise ValueError(f"Failed to read file: {e}")

    line_count = content.count("\n") + (1 if content and not content.endswith("\n") else 0)
    language = get_language(file_path)

    return FileContent(
        path=file_path,
        content=content,
        language=language,
        line_count=line_count,
    )


async def get_files_by_extension(
    repo_path: str,
    extensions: list[str],
    max_files: int = 1000,
) -> list[str]:
    """Get list of files with specific extensions."""
    root = Path(repo_path)
    files = []

    # Normalize extensions
    extensions = [ext.lower() if ext.startswith(".") else f".{ext.lower()}" for ext in extensions]

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Skip excluded directories (prune recursion)
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]

        for filename in filenames:
            if len(files) >= max_files:
                break

            if filename in EXCLUDED_FILES or filename.startswith("."):
                continue

            path = Path(dirpath) / filename
            if path.is_symlink() or not path.is_file():
                continue

            if path.suffix.lower() in extensions:
                try:
                    rel_path = path.relative_to(root).as_posix()
                    files.append(rel_path)
                except ValueError:
                    pass

    return files


async def search_files(
    repo_path: str,
    pattern: str,
    max_results: int = 100,
) -> list[dict]:
    """Search for pattern in files."""
    import re

    # Security: Limit pattern length to prevent ReDoS attacks
    MAX_PATTERN_LENGTH = 100
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise ValueError(f"Pattern too long. Max length is {MAX_PATTERN_LENGTH} characters.")

    # Security: Check for potentially dangerous regex patterns
    DANGEROUS_PATTERNS = [
        r'\(\?[^)]*\)\+',  # Nested quantifiers like (a+)+
        r'\(\[.*\]\+\)\+',  # [chars]+ inside group with +
        r'\(.*\|.*\)\+',   # Alternation inside group with +
    ]

    for dangerous in DANGEROUS_PATTERNS:
        if re.search(dangerous, pattern):
            # Fall back to literal search for potentially dangerous patterns
            pattern = re.escape(pattern)
            break

    root = Path(repo_path)
    results = []

    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error:
        # Treat as literal string if not valid regex
        regex = re.compile(re.escape(pattern), re.IGNORECASE)

    # Hard cap to avoid huge per-file reads from untrusted repos
    MAX_BYTES_PER_FILE = 2_000_000  # 2MB

    stop = False
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Skip excluded directories (prune recursion)
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]

        for filename in filenames:
            if len(results) >= max_results:
                stop = True
                break

            if filename in EXCLUDED_FILES:
                continue

            path = Path(dirpath) / filename
            if path.is_symlink() or not path.is_file():
                continue

            if is_binary_file(str(path)):
                continue

            try:
                if path.stat().st_size > MAX_BYTES_PER_FILE:
                    continue
            except OSError:
                continue

            try:
                async with aiofiles.open(path, "r", encoding="utf-8", errors="replace") as f:
                    line_no = 0
                    async for line in f:
                        line_no += 1
                        if regex.search(line):
                            rel_path = path.relative_to(root).as_posix()
                            results.append({
                                "file": rel_path,
                                "line": line_no,
                                "content": line.strip()[:200],
                            })

                            if len(results) >= max_results:
                                stop = True
                                break

                        if stop:
                            break
            except Exception:
                continue

        if stop:
            break

    return results
