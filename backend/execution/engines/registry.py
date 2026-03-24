"""Engine registry -- maps engine names to adapter classes."""

from __future__ import annotations

from execution.engines.engine_interface import EngineInterface


_ENGINES: dict[str, type[EngineInterface]] = {}


def register_engine(name: str, cls: type[EngineInterface]) -> None:
    _ENGINES[name] = cls


def get_engine(name: str) -> EngineInterface:
    cls = _ENGINES.get(name)
    if not cls:
        raise ValueError(f"Unknown engine: {name}. Available: {list(_ENGINES.keys())}")
    return cls()


def list_engines() -> list[str]:
    return list(_ENGINES.keys())


# ------------------------------------------------------------------
# Register built-in engines
# ------------------------------------------------------------------
from execution.engines.schemathesis_engine import SchemathesisEngine
from execution.engines.aflpp_engine import AFLPPEngine
from execution.engines.restler_engine import RESTlerEngine
from execution.engines.atheris_engine import AtherisEngine
from execution.engines.hypothesis_engine import HypothesisEngine
from execution.engines.jazzer_engine import JazzerEngine
from execution.engines.gofuzz_engine import GoFuzzEngine
from execution.engines.cargo_fuzz_engine import CargoFuzzEngine
from execution.engines.boofuzz_engine import BoofuzzEngine
from execution.engines.echidna_engine import EchidnaEngine
from execution.engines.radamsa_engine import RadamsaEngine
from execution.engines.grammarinator_engine import GrammarinatorEngine
from execution.engines.sqlsmith_engine import SQLsmithEngine
from execution.engines.foundry_engine import FoundryEngine

register_engine("schemathesis", SchemathesisEngine)
register_engine("aflpp", AFLPPEngine)
register_engine("restler", RESTlerEngine)
register_engine("atheris", AtherisEngine)
register_engine("hypothesis", HypothesisEngine)
register_engine("jazzer", JazzerEngine)
register_engine("go_fuzz", GoFuzzEngine)
register_engine("cargo_fuzz", CargoFuzzEngine)
register_engine("boofuzz", BoofuzzEngine)
register_engine("echidna", EchidnaEngine)
register_engine("radamsa", RadamsaEngine)
register_engine("grammarinator", GrammarinatorEngine)
register_engine("sqlsmith", SQLsmithEngine)
register_engine("foundry", FoundryEngine)
