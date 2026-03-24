# Harness Code Generation

## Purpose
Generate a working fuzz harness that calls real functions from the target source code.

## Rules
1. ALWAYS import from the actual target module/package
2. NEVER use mocks, stubs, or fake implementations
3. Handle the target's actual data types
4. Include error handling for expected exceptions
5. The harness must compile/run without modification

## Per-Engine Guidelines

### AFL++ (C/C++)
- Include the target's actual headers
- Call the target's parsing/processing functions with AFL-provided input buf/len
- Use __AFL_FUZZ_INIT(), __AFL_INIT(), __AFL_LOOP() macros
- Link against the target's library

### Atheris (Python)
- Import the target module directly
- Use FuzzedDataProvider to generate typed inputs matching the target's API
- Catch expected exceptions (ValueError, TypeError, etc.)
- Let unexpected exceptions propagate (they're real bugs)

### Jazzer (Java)
- Import the target class
- Use FuzzedDataProvider for typed input generation
- Call the target's public methods
- Catch expected exceptions, propagate SecurityExceptions

### Go Fuzz
- Import the target package
- Use testing.F with appropriate seed corpus
- Call the target's exported functions

### Cargo Fuzz (Rust)
- Use the target crate as a dependency
- Call the target's public functions with arbitrary bytes
- Use the Arbitrary trait if the target supports it
