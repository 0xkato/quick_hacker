"""Tests for the engine registry."""

import pytest

from execution.engines.registry import get_engine, list_engines


def test_list_engines():
    engines = list_engines()
    assert "schemathesis" in engines
    assert "aflpp" in engines
    assert "restler" in engines
    assert "atheris" in engines
    assert "hypothesis" in engines
    assert len(engines) >= 14


def test_get_engine():
    eng = get_engine("schemathesis")
    assert eng is not None
    assert hasattr(eng, "run")


def test_get_unknown_raises():
    with pytest.raises(ValueError):
        get_engine("nonexistent_engine")


def test_all_engines_have_run():
    for name in list_engines():
        eng = get_engine(name)
        assert hasattr(eng, "run"), f"{name} missing run method"
