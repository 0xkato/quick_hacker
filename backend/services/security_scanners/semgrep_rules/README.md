# Semgrep Rules for QuickHack

Curated collection of high/critical severity security rules for multi-language vulnerability detection.

## Structure

```
semgrep_rules/
├── python/          # Python security rules
├── c/               # C/C++ security rules
├── javascript/      # JavaScript security rules
├── java/            # Java security rules
├── metadata.json    # Rule metadata and mappings
└── README.md        # This file
```

## Rule Curation Criteria

- **Severity:** High or Critical only
- **False Positives:** Low rate (< 20% based on testing)
- **Coverage:** Maps to OWASP Top 10 or CWE
- **Integration:** Aligns with QuickHack validity checklists
- **Maintenance:** Active (updated in last 12 months)

## Sources

- **C/C++:** [0xdea/semgrep-rules](https://github.com/0xdea/semgrep-rules)
- **Python/JS/Java:** Semgrep Registry + manual curation

## Usage

Rules are loaded automatically by SemgrepScanner. To run manually:

```bash
semgrep --config services/security_scanners/semgrep_rules/python app/
```

## Adding New Rules

1. Add YAML file to appropriate language directory
2. Update metadata.json with rule details
3. Create test fixture in tests/fixtures/vulnerable_code/
4. Run tests to verify detection

## Maintenance

Quarterly review process:
1. Check Semgrep Registry for new/updated rules
2. Review community feedback on false positives
3. Add rules meeting curation criteria
4. Update CHANGELOG
