"""Environment bootstrapper — provisions the right container for each engine.

Given an engine type and target metadata, determines:
1. Which Dockerfile to use
2. What dependencies to install
3. How to compile/instrument the target
4. How to verify the environment works
"""
from __future__ import annotations

import os
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class EnvironmentSpec:
    """Specification for a fuzzing environment."""
    engine: str
    dockerfile: str  # Path to engine-specific Dockerfile
    base_image: str  # Docker base image
    install_commands: list[str] = field(default_factory=list)  # Extra install commands
    build_commands: list[str] = field(default_factory=list)  # Target build commands
    env_vars: dict[str, str] = field(default_factory=dict)
    volumes: list[str] = field(default_factory=list)
    needs_docker_socket: bool = False
    needs_network: bool = False
    resource_profile: str = "medium"  # light/medium/heavy


DOCKERFILES_DIR = Path(__file__).parent / "dockerfiles"


ENGINE_SPECS: dict[str, dict] = {
    "schemathesis": {
        "dockerfile": "Dockerfile.worker",  # Uses the standard worker
        "base_image": "python:3.12-slim",
        "needs_network": True,
        "resource_profile": "light",
    },
    "aflpp": {
        "dockerfile": "Dockerfile.aflpp",
        "base_image": "aflplusplus/aflplusplus:latest",
        "needs_docker_socket": False,
        "resource_profile": "heavy",
    },
    "atheris": {
        "dockerfile": "Dockerfile.atheris",
        "base_image": "python:3.12-slim",
        "resource_profile": "medium",
    },
    "hypothesis": {
        "dockerfile": "Dockerfile.atheris",  # Same Python base
        "base_image": "python:3.12-slim",
        "resource_profile": "light",
    },
    "jazzer": {
        "dockerfile": "Dockerfile.jazzer",
        "base_image": "eclipse-temurin:21-jdk",
        "resource_profile": "heavy",
    },
    "go_fuzz": {
        "dockerfile": "Dockerfile.go",
        "base_image": "golang:1.22",
        "resource_profile": "medium",
    },
    "cargo_fuzz": {
        "dockerfile": "Dockerfile.rust",
        "base_image": "rust:latest",
        "resource_profile": "heavy",
    },
    "echidna": {
        "dockerfile": "Dockerfile.solidity",
        "base_image": "python:3.12-slim",
        "resource_profile": "medium",
    },
    "foundry": {
        "dockerfile": "Dockerfile.solidity",
        "base_image": "python:3.12-slim",
        "resource_profile": "medium",
    },
    "boofuzz": {
        "dockerfile": "Dockerfile.protocol",
        "base_image": "python:3.12-slim",
        "needs_network": True,
        "resource_profile": "light",
    },
    "restler": {
        "dockerfile": "Dockerfile.worker",
        "base_image": "python:3.12-slim",
        "needs_network": True,
        "resource_profile": "medium",
    },
    "grammarinator": {
        "dockerfile": "Dockerfile.atheris",
        "base_image": "python:3.12-slim",
        "resource_profile": "light",
    },
    "sqlsmith": {
        "dockerfile": "Dockerfile.protocol",
        "base_image": "python:3.12-slim",
        "needs_network": True,
        "resource_profile": "medium",
    },
    "radamsa": {
        "dockerfile": "Dockerfile.atheris",
        "base_image": "python:3.12-slim",
        "resource_profile": "light",
    },
}


def get_environment_spec(engine: str, target: dict = None) -> EnvironmentSpec:
    """Get the environment specification for an engine + target.

    Returns an EnvironmentSpec that describes what container to build,
    what to install, and how to compile the target.
    """
    spec = ENGINE_SPECS.get(engine)
    if not spec:
        raise ValueError(f"Unknown engine: {engine}")

    dockerfile = str(DOCKERFILES_DIR / spec["dockerfile"]) if not spec["dockerfile"].startswith("/") else spec["dockerfile"]

    env_spec = EnvironmentSpec(
        engine=engine,
        dockerfile=dockerfile,
        base_image=spec["base_image"],
        needs_docker_socket=spec.get("needs_docker_socket", False),
        needs_network=spec.get("needs_network", False),
        resource_profile=spec.get("resource_profile", "medium"),
    )

    # Add target-specific build commands if target metadata is available
    if target:
        language = target.get("language", "")
        if language == "python":
            env_spec.install_commands.append("pip install -r requirements.txt")
        elif language in ("c", "cpp"):
            env_spec.install_commands.append("apt-get update && apt-get install -y build-essential")
        elif language == "java":
            env_spec.install_commands.append("apt-get update && apt-get install -y default-jdk maven")
        elif language == "go":
            env_spec.build_commands.append("go mod download")
        elif language == "rust":
            env_spec.build_commands.append("cargo build")

    return env_spec


def list_supported_engines() -> list[str]:
    """List all engines with environment support."""
    return list(ENGINE_SPECS.keys())
