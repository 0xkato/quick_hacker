# Grammar Generation Methodology Pack

## Purpose
Generate inputs from a formal grammar (BNF, ABNF, PEG). Ensures structurally valid inputs that reach deep parser logic.

## When to Use
- Targets that parse structured formats (SQL, HTML, CSS, config files)
- When raw mutation wastes cycles on syntactically invalid inputs

## Harness Strategy
- LM generates or refines grammar from format specification
- Grammar-based generator produces valid inputs
- Combine with targeted mutations at semantic boundaries

## Notes
Higher setup cost but much better depth for grammar-heavy parsers. dictionary_codegen compiler produces the grammar files.
