from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any


def get_prompting_dir() -> Path:
    """Return absolute path to the repo-level `prompting/` directory."""
    return Path(__file__).resolve().parents[1] / "prompting"


def _resolve_prompt_path(relative_path: str) -> Path:
    if Path(relative_path).is_absolute():
        raise ValueError("Prompt path must be relative")

    prompting_root = get_prompting_dir().resolve()
    full_path = (prompting_root / relative_path).resolve()
    if not full_path.is_relative_to(prompting_root):
        raise ValueError("Prompt path escapes prompting root")

    return full_path


@lru_cache(maxsize=256)
def load_prompt(relative_path: str) -> str:
    """Load a prompt template from `prompting/` as UTF-8 text."""
    return _resolve_prompt_path(relative_path).read_text(encoding="utf-8")


def render_prompt(relative_path: str, **kwargs: Any) -> str:
    """Load + replace `{{placeholders}}` in a prompt template."""
    template = load_prompt(relative_path)
    for key, value in kwargs.items():
        replacement = "" if value is None else str(value)
        template = template.replace(f"{{{{{key}}}}}", replacement)
    return template
