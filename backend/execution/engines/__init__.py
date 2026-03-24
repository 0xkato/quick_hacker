"""Execution engines: pluggable fuzz/test runners."""

from execution.engines.engine_interface import EngineInterface, EngineResult
from execution.engines.registry import get_engine, list_engines, register_engine

__all__ = ["EngineInterface", "EngineResult", "get_engine", "list_engines", "register_engine"]
