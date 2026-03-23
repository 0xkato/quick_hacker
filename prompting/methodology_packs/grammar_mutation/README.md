# Grammar Mutation Methodology Pack

## Purpose
Mutate inputs while preserving grammar structure. Combines the depth of grammar generation with the exploration of mutation-based fuzzing.

## When to Use
- Same targets as grammar_generation, but when pure generation plateaus
- Structured formats where random byte mutation is wasteful

## Harness Strategy
- Parse existing corpus entries into AST/parse-tree
- Mutate at tree node level (swap subtrees, duplicate nodes, alter terminals)
- Maintain structural validity while exploring semantic edge cases

## Notes
Second-phase methodology: use after grammar_generation builds initial corpus. Pairs with mutator_codegen compiler.
