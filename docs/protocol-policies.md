# Protocol Policies

## Overview

Protocol policies define quality gates for determining if security findings are worth submitting to bug bounty programs, vulnerability rewards programs (VRPs), or responsible disclosure channels.

## Default Policies

### Internal (Permissive)

**Use Case:** Internal security audits, dev/QA environments

**Philosophy:** Report everything worth fixing, even if not externally exploitable

**Requirements:**
- Min Disposition: HARDENING or above
- Threat Model: ABC (all attacker capabilities)
- Local bugs: Accepted without automation boundary
- Social engineering: Accepted for awareness
- Checklist: 3/6 items must be proven

**Best For:**
- Internal security reviews
- Development environments
- Comprehensive security hardening

---

### Google VRP (Strict)

**Use Case:** Submitting to Google's Open Source Vulnerability Rewards Program

**Philosophy:** High-quality, realistic security issues only

**Requirements:**
- Min Disposition: VALID_SECURITY_ISSUE only
- Threat Model: AB (remote/web/file only)
- Local bugs: Must have automation boundary
- Social engineering: Rejected
- Checklist: 6/6 items must be proven (no unknowns)

**Category Rules:**
- Command Injection: Requires shell=True (rejects argv injection)
- SQL Injection: Requires structure-taint (rejects parameterized queries)
- Hardcoded Secrets: Rejects test/example/vendored files

**Best For:**
- OSS projects seeking Google VRP bounties
- Strict quality requirements
- Established open source projects

---

### HackerOne Standard

**Use Case:** Bug bounty programs on HackerOne platform

**Philosophy:** Triaged, validated findings with clear impact

**Requirements:**
- Min Disposition: VALID_SECURITY_ISSUE or BUG
- Threat Model: AB (can include repo/CI if shown)
- Local bugs: Need automation boundary
- Social engineering: Rejected
- Checklist: 5/6 items proven (allow 1 unknown)

**Best For:**
- Bug bounty programs
- Commercial software security
- Moderate quality bar

---

### Bugcrowd Standard

**Use Case:** Vulnerability disclosure programs

**Philosophy:** Valid security issues with demonstrable impact

**Requirements:**
- Similar to HackerOne
- Slightly more permissive on category rules

---

### Research Disclosure

**Use Case:** Academic research, CVE requests, coordinated disclosure

**Philosophy:** Documented security issues for public benefit

**Requirements:**
- Min Disposition: VALID_SECURITY_ISSUE, BUG, or HARDENING
- Threat Model: ABC (all capabilities)
- Local bugs: Accepted
- Social engineering: Accepted and documented
- Checklist: 4/6 items proven

**Best For:**
- Security research papers
- CVE documentation
- Public security awareness
- Defense-in-depth issues

## Choosing a Protocol

Consider:

1. **Submission Target:** Where will you report findings?
   - Google VRP → osvrp_strict
   - HackerOne → hackerone_strict
   - Internal only → internal

2. **Threat Model:** What attackers do you care about?
   - Remote only → AB protocols (osvrp_strict, hackerone_strict)
   - Local + remote → ABC protocols (internal, research_disclosure)

3. **Quality Bar:** How strict should evaluation be?
   - Very strict → osvrp_strict (6/6 checklist items)
   - Moderate → hackerone_strict (5/6 items)
   - Permissive → internal (3/6 items)

## Evidence Quests

When a high-signal finding has evidence gaps, the system can automatically trigger an **evidence quest** - an autonomous LLM agent that gathers missing proof.

**When Quests Run:**
- Decision: needs_more_info
- Finding disposition: VALID or BUG
- Protocol has quests enabled

**What Quests Do:**
- Verify shell execution context (command injection)
- Trace dataflow from source to sink
- Find route registration / entry points
- Check CI/CD for automation boundaries

**After Quest Completes:**
- New evidence updates the Evidence object
- Finding is re-triaged automatically
- Submission decision is re-evaluated

**Manual Quest Triggering:**
You can manually retry a quest from the Submission panel in the UI.
