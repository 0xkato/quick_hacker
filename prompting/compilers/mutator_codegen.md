# Mutator Codegen Compiler

## Purpose
Generate custom mutator plugins for grammar-aware and structure-aware fuzzing. Extends base mutation strategies with target-specific logic.

## Input
- Grammar definition (from grammar_generation methodology)
- Target format specification
- Corpus analysis results

## Output
- Custom mutator plugin (Python)
- Tree-level mutation operators
- Splice and recombination strategies

## Notes
Used by grammar_mutation methodology. Mutators operate on parsed AST nodes rather than raw bytes.
