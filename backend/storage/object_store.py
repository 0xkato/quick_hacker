"""Filesystem-backed artifact store.

Provides an abstract ``ObjectStore`` interface and a concrete
``LocalFileStore`` that persists binary blobs on the local filesystem.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional
from urllib.parse import quote
from urllib.request import pathname2url


class ObjectStore(ABC):
    """Abstract interface for binary key/value storage."""

    @abstractmethod
    def put(self, key: str, data: bytes) -> None:
        """Store *data* under *key*, overwriting if it already exists."""

    @abstractmethod
    def get(self, key: str) -> Optional[bytes]:
        """Return the bytes stored under *key*, or ``None`` if missing."""

    @abstractmethod
    def exists(self, key: str) -> bool:
        """Return ``True`` when *key* has been stored."""

    @abstractmethod
    def delete(self, key: str) -> None:
        """Remove *key*.  No-op when the key does not exist."""

    @abstractmethod
    def list_keys(self, prefix: str = "") -> list[str]:
        """Return every key whose path starts with *prefix*."""

    @abstractmethod
    def get_url(self, key: str) -> str:
        """Return a URL that can be used to retrieve the object."""


class LocalFileStore(ObjectStore):
    """Store objects as plain files under a root directory.

    Keys are interpreted as relative POSIX paths beneath *root*.
    Intermediate directories are created on demand.
    """

    def __init__(self, root: Path | str) -> None:
        self._root = Path(root).resolve()
        self._root.mkdir(parents=True, exist_ok=True)

    # -- helpers --------------------------------------------------------------

    def _resolve(self, key: str) -> Path:
        """Map a key to an absolute path, guarding against traversal."""
        resolved = (self._root / key).resolve()
        if not str(resolved).startswith(str(self._root)):
            raise ValueError(f"Key {key!r} resolves outside the store root")
        return resolved

    # -- public API -----------------------------------------------------------

    def put(self, key: str, data: bytes) -> None:
        path = self._resolve(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def get(self, key: str) -> Optional[bytes]:
        path = self._resolve(key)
        if not path.is_file():
            return None
        return path.read_bytes()

    def exists(self, key: str) -> bool:
        return self._resolve(key).is_file()

    def delete(self, key: str) -> None:
        path = self._resolve(key)
        if path.is_file():
            path.unlink()

    def list_keys(self, prefix: str = "") -> list[str]:
        search_root = self._resolve(prefix) if prefix else self._root
        if not search_root.is_dir():
            return []
        keys: list[str] = []
        for dirpath, _, filenames in os.walk(search_root):
            for fname in filenames:
                abs_path = Path(dirpath) / fname
                rel = abs_path.relative_to(self._root)
                keys.append(str(rel))
        return sorted(keys)

    def get_url(self, key: str) -> str:
        path = self._resolve(key)
        return Path(path).as_uri()
