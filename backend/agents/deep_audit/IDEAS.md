# Deep Audit Ideas

## Specialized SinkHunters

Currently we have one generic SinkHunter that tries to find all vulnerability types. For better results, we could split into specialized hunters:

### Memory Safety SinkHunter
- Focus: Buffer overflow, use-after-free, integer overflow, format strings
- Languages: C, C++, Rust (unsafe blocks)
- Patterns: memcpy, strcpy, sprintf, malloc size calculations, free/delete patterns

### Injection SinkHunter
- Focus: SQL injection, command injection, template injection
- Languages: Python, JavaScript, Java, Go
- Patterns: string interpolation in queries, subprocess calls, eval/exec

### Web SinkHunter
- Focus: SSRF, XSS, open redirect, request smuggling
- Languages: Any with HTTP handling
- Patterns: HTTP client calls, URL construction, response headers

### Crypto SinkHunter
- Focus: Weak crypto, hardcoded secrets, insecure randomness
- Languages: All
- Patterns: MD5/SHA1 for passwords, Math.random(), hardcoded keys

### Benefits
- More focused prompts = better results
- Can run in parallel (different focus areas)
- Language-specific patterns per hunter

### Implementation
- Add new agent types: MemorySinkHunter, InjectionSinkHunter, etc.
- Or: Keep one SinkHunter but pass "focus" parameter in objective
- Orchestrator dispatches multiple hunters per wave

---

## Other Ideas

### Devil's Advocate for Quick Dismissals
- When a specialist dismisses a high-severity signal quickly
- Dispatch Devil's Advocate to challenge the dismissal
- Try to prove the specialist wrong before accepting dismissal

### Confidence Calibration
- Track specialist accuracy over time
- Weight verdicts by historical accuracy
- Flag specialists that dismiss too quickly

### Cross-Validation
- For critical findings, dispatch 2 specialists
- If they disagree, dispatch Arbiter
- Reduces false positives/negatives
