"""Tests for SQLAlchemy model declarations."""

import importlib

import pytest


def test_database_models_importable():
    """Models import without declarative mapping errors."""
    try:
        models = importlib.import_module("database.models")
    except Exception as exc:  # noqa: BLE001 - want full failure context
        pytest.fail(f"Importing database.models raised {exc!r}")

    Finding = getattr(models, "Finding", None)
    assert Finding is not None

    # Column name remains `metadata`, but python attribute must not be `metadata`
    # (reserved by SQLAlchemy declarative).
    assert "metadata" in Finding.__table__.columns
    assert "metadata_" in Finding.__mapper__.attrs
