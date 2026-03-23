# Dictionary Codegen Compiler

## Purpose
Generate fuzzing dictionaries and token lists from target analysis. Provides domain-specific tokens that improve mutation quality.

## Input
- Target source code (string literals, constants)
- API schema (field names, enum values)
- Known payload wordlists for the target vulnerability class

## Output
- Dictionary file (newline-delimited tokens)
- Weighted token list (higher weight = more frequent selection)

## Notes
Dictionaries dramatically improve fuzzer efficiency for text-based protocols. Auto-extracted from source + augmented with security-relevant tokens.
