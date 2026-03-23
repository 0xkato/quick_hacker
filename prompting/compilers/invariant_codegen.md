# Invariant Codegen Compiler

## Purpose
Generate invariant check functions from oracle pack definitions. These functions are called after each request to detect violations.

## Input
- Oracle pack definition
- Target schema (for response shape validation)
- Baseline response samples

## Output
- Invariant check functions (Python)
- Expected response shape definitions
- Violation classification logic (severity, confidence)

## Notes
Invariants are the bridge between oracle packs and harness execution. Each oracle pack maps to one or more invariant functions.
