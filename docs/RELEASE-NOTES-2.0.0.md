# Release Notes: v2.0.0 - Protocol-Aware Reportability Layer

**Release Date:** 2026-01-17

## Overview

This major release adds a protocol-aware submission evaluation system that determines if security findings are worth reporting to bug bounties, VRPs, or responsible disclosure programs.

## What's New

### Protocol Policies

5 pre-configured policies for different submission targets:
- **Internal (Permissive):** For dev/QA environments
- **Google VRP (Strict):** For OSS VRP submissions
- **HackerOne Standard:** For bug bounty programs
- **Bugcrowd Standard:** For VDP programs
- **Research Disclosure:** For academic/CVE documentation

### Quality Gates

Automated evaluation through 5 gates:
1. Disposition filtering
2. Proof checklist quality
3. Attacker model realism
4. Category-specific rules
5. Local boundary checks

### Evidence Quests

Autonomous LLM agents that:
- Gather missing evidence for high-signal findings
- Verify shell execution context
- Trace dataflow paths
- Find route registrations
- Check CI/CD for automation boundaries

### UI Enhancements

- Protocol selector in project settings
- Submission badges (✓/✗/?) in findings list
- Detailed submission panel in finding drawer
- Quest status and findings display
- Filters for submission decisions

## Breaking Changes

- `FindingTriageService.triage_findings()` replaced by `triage_with_protocol()`
- New required database migration (002_add_protocol_layer.sql)
- Requires ANTHROPIC_API_KEY for quest functionality

## Migration Guide

See [DEPLOYMENT.md](DEPLOYMENT.md) for full instructions.

Quick steps:
```bash
# 1. Backup database
cp backend/data/quickhack.db backend/data/quickhack.db.backup

# 2. Run migration
python backend/scripts/migrate_to_protocol_layer.py

# 3. Configure .env
echo "ANTHROPIC_API_KEY=your_key" >> .env

# 4. Restart server
```

## Known Limitations

- Quest playbooks simplified for MVP (no full LLM tool integration)
- SQLite JSON indexing may be slow for >10K findings
- Quest success rate varies by category (60-80%)

## Future Enhancements

- Additional quest playbooks (deserialization, SSRF, memory safety)
- Custom protocol policies (user-defined rules)
- Report generator for submittable findings
- Multi-protocol evaluation

## Contributors

- Claude Sonnet 4.5 (Implementation)
- 0xkato (Design & Review)

---

**Full Changelog:** See git log v1.0.0..v2.0.0
