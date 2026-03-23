# Raw Mutation Methodology Pack

## Purpose
Byte-level and structure-level mutation of inputs without schema guidance. Effective for binary parsers, file format handlers, and custom protocols.

## When to Use
- Targets without formal schemas
- Binary format parsers, image decoders, archive handlers
- Looking for memory corruption, crashes, parsing errors

## Harness Strategy
- Seed corpus from real-world samples or generated valid inputs
- Apply bit-flip, byte-insert, boundary-value, and havoc mutations
- Track coverage feedback to guide mutation toward new code paths

## Notes
Classic coverage-guided fuzzing approach. Pairs with grammar_mutation for structured formats.
