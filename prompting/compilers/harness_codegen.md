# Harness Codegen Compiler

## Purpose
Generate executable fuzz harness code from a target + methodology pack combination. Outputs runnable Python/JS test harnesses.

## Input
- Target definition (from extractor)
- Methodology pack configuration
- Oracle pack configuration

## Output
- Executable harness file (Python or JavaScript)
- Configuration for the fuzzing runtime
- Seed corpus entries (if methodology requires them)

## Notes
Core compiler. All other compilers (schemathesis_hooks, invariant_codegen, etc.) are specialized variants of this.
