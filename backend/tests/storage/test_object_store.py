"""Tests for the LocalFileStore artifact store."""

from __future__ import annotations

from pathlib import Path

import pytest

from storage.object_store import LocalFileStore


@pytest.fixture()
def store(tmp_path: Path) -> LocalFileStore:
    return LocalFileStore(tmp_path / "artifacts")


class TestPutAndGet:
    def test_round_trip(self, store: LocalFileStore) -> None:
        store.put("report.bin", b"hello world")
        assert store.get("report.bin") == b"hello world"

    def test_overwrite(self, store: LocalFileStore) -> None:
        store.put("key", b"v1")
        store.put("key", b"v2")
        assert store.get("key") == b"v2"


class TestGetMissing:
    def test_returns_none(self, store: LocalFileStore) -> None:
        assert store.get("no-such-key") is None


class TestExists:
    def test_true_after_put(self, store: LocalFileStore) -> None:
        store.put("a", b"x")
        assert store.exists("a") is True

    def test_false_when_missing(self, store: LocalFileStore) -> None:
        assert store.exists("nope") is False


class TestDelete:
    def test_removes_file(self, store: LocalFileStore) -> None:
        store.put("to-delete", b"data")
        store.delete("to-delete")
        assert store.exists("to-delete") is False
        assert store.get("to-delete") is None

    def test_noop_for_missing(self, store: LocalFileStore) -> None:
        store.delete("nonexistent")  # should not raise


class TestListKeys:
    def test_with_prefix(self, store: LocalFileStore) -> None:
        store.put("scans/1/a.json", b"{}")
        store.put("scans/1/b.json", b"{}")
        store.put("scans/2/c.json", b"{}")
        store.put("other/x.txt", b"")

        keys = store.list_keys("scans/1")
        assert keys == ["scans/1/a.json", "scans/1/b.json"]

    def test_all_keys(self, store: LocalFileStore) -> None:
        store.put("a", b"")
        store.put("b", b"")
        assert store.list_keys() == ["a", "b"]

    def test_empty_store(self, store: LocalFileStore) -> None:
        assert store.list_keys() == []

    def test_missing_prefix(self, store: LocalFileStore) -> None:
        assert store.list_keys("does/not/exist") == []


class TestGetUrl:
    def test_starts_with_file(self, store: LocalFileStore) -> None:
        store.put("doc.txt", b"content")
        url = store.get_url("doc.txt")
        assert url.startswith("file://")


class TestNestedDirectories:
    def test_put_creates_parents(self, store: LocalFileStore) -> None:
        store.put("deep/nested/dir/file.bin", b"\x00\x01")
        assert store.get("deep/nested/dir/file.bin") == b"\x00\x01"


class TestPathTraversal:
    def test_rejects_traversal(self, store: LocalFileStore) -> None:
        with pytest.raises(ValueError, match="outside the store root"):
            store.put("../../etc/passwd", b"bad")
