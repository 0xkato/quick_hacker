# Parser Surface Extractor

## Purpose
Identify file-parsing and deserialization surfaces: XML, JSON, YAML, protobuf, custom binary formats, image decoders, and archive handlers.

## Input
- Repository file tree
- Import/dependency analysis
- Function signatures referencing parse/decode/unmarshal

## Output (JSON)
```json
{
  "targets": [
    {
      "kind": "parser",
      "entrypoint": "parse_xml(data: bytes)",
      "format": "xml",
      "language": "python",
      "attacker_controlled_input": true
    }
  ]
}
```

## Notes
Critical for memory-safety languages. Pairs with grammar_generation and raw_mutation methodology packs.
