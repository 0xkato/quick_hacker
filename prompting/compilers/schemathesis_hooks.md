# Schemathesis Hooks Compiler

## Purpose
Generate Schemathesis hook files that customize schema-driven API fuzzing. Adds custom authentication, state management, and oracle checks.

## Input
- OpenAPI/GraphQL schema
- Oracle pack configuration
- Authentication credentials

## Output
- Python hook file for Schemathesis
- Custom hypothesis strategies for specific fields
- Before/after request hooks for oracle evaluation

## Notes
Specialized compiler for schema_property methodology with Schemathesis runtime. Outputs conftest.py-style hooks.
