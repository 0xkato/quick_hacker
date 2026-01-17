# QuickHack Documentation

## Primary Documentation

**[SYSTEM-SPECIFICATION.md](./SYSTEM-SPECIFICATION.md)** - THE SINGLE SOURCE OF TRUTH

This is the comprehensive system specification covering:
- System architecture
- Provider system (Claude SDK + Codex CLI)
- Threat modeling system
- Triage & classification
- Security issue vs bug classification
- Data models
- API reference
- Testing strategy
- Deployment guide

**Start here for all system information.**

---

## Supplementary Documentation

- **[CACHE_USAGE.md](./CACHE_USAGE.md)** - Cache system implementation details
- **[ultrathink.md](./ultrathink.md)** - Hierarchical verification cascade concept

---

## Archive

All historical plans, designs, and outdated documentation is in `archive/`:
- `archive/plans/` - Implementation plans (chronological)
- `archive/*.md` - Superseded architecture docs

**Note:** Archive documents may be outdated. Refer to SYSTEM-SPECIFICATION.md for current system.

---

## Documentation Philosophy

**One Source of Truth:** We maintain a single comprehensive specification (SYSTEM-SPECIFICATION.md) rather than multiple scattered documents. This ensures:
- No contradictions between docs
- Clear versioning
- Easier maintenance
- Single place to look for information

When the system evolves, we update SYSTEM-SPECIFICATION.md and move old versions to archive with timestamps.

---

## Contributing to Documentation

1. **For system changes:** Update SYSTEM-SPECIFICATION.md
2. **For new features:** Add to appropriate section in SYSTEM-SPECIFICATION.md
3. **For deprecations:** Update SYSTEM-SPECIFICATION.md and move old content to archive
4. **For supplementary topics:** Create standalone doc (like CACHE_USAGE.md)

---

## Version History

**Current:** v2.0.0 (2026-01-17)
- Phase 3 & 4 implementation
- Evidence model migration to Pydantic
- Input channel inference (2-signal minimum)
- Centralized threat model gating

**Previous:** v1.0.0 (2026-01-16)
- Threat modeling system
- Per-project profiles
- Frontend UI

See SYSTEM-SPECIFICATION.md for complete version history.
