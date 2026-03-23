# Schema-Property Methodology Pack

## Purpose
Property-based testing driven by API schemas. Generates inputs from OpenAPI/JSON Schema definitions, then mutates properties to find constraint violations.

## When to Use
- Targets with well-defined schemas (OpenAPI, GraphQL SDL, protobuf)
- Looking for input validation bugs, type confusion, boundary violations

## Harness Strategy
- Generate valid baseline requests from schema
- Mutate individual properties (type, length, format, required/optional)
- Combine with Schemathesis hypothesis strategies

## Notes
Most effective methodology for schema-rich APIs. Pairs well with authz_diff and leak_diff oracles.
