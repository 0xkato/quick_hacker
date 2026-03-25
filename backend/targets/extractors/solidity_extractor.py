"""Extract fuzzable targets from Solidity codebases."""
from __future__ import annotations

import re
from pathlib import Path


def extract_solidity_targets(repo_path: str | list[str]) -> list[dict]:
    """Extract fuzzable Solidity contract targets."""
    paths = [repo_path] if isinstance(repo_path, str) else repo_path
    targets = []

    for base_path in paths:
        p = Path(base_path)
        for f in p.rglob("*.sol"):
            rel = f.relative_to(p)
            if _should_skip(rel):
                continue
            try:
                content = f.read_text(errors="ignore")
                contracts = _extract_contracts(content, str(rel))
                targets.extend(contracts)
            except Exception:
                continue

    return targets


def _extract_contracts(content: str, file_path: str) -> list[dict]:
    """Extract contract names and their external/public functions."""
    targets = []

    # Find contract definitions
    contract_pattern = re.compile(r'contract\s+(\w+)')
    func_pattern = re.compile(r'function\s+(\w+)\s*\([^)]*\)\s*(?:external|public)')

    for contract_match in contract_pattern.finditer(content):
        contract_name = contract_match.group(1)

        # Skip test/mock contracts
        if any(skip in contract_name.lower() for skip in ["test", "mock", "dummy"]):
            continue

        # Count public/external functions
        funcs = func_pattern.findall(content)

        if funcs:
            targets.append({
                "kind": "native_function",
                "entrypoint": f"{file_path}:{contract_name}",
                "language": "solidity",
                "schemas": None,
                "stateful": True,  # Contracts are inherently stateful
                "actors": ["deployer", "user", "attacker"],
                "reset_strategy": "redeploy",
                "priority_score": 0.8,
            })

    return targets


def _should_skip(path: Path) -> bool:
    skip = ["test", "mock", "node_modules", ".git", "lib/forge-std", "lib/openzeppelin"]
    return any(s in str(path).lower() for s in skip)
