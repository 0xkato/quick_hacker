# Stage: Triage

**Goal:** Final classification and prioritization based on complete checklist

**No Tools Used** - This stage uses accumulated evidence only

**Output Required:**
- Final disposition: VALID_SECURITY_ISSUE | BUG | HARDENING | MISCONFIGURATION | BY_DESIGN | SPECULATIVE
- Complete proof checklist with all items marked PROVEN_TRUE/PROVEN_FALSE/UNKNOWN
- Confidence score (0.0-1.0)
- Reasoning (2-4 bullet points)

**Approach:**
1. Review complete proof checklist
2. Apply StrictClassifier rules:
   - Rule 2: not_only_misconfig == PROVEN_FALSE → MISCONFIGURATION
   - Rule 3b: For exec/eval, security_control_bypassed can replace boundary_crossed
   - Rule 4: ALL items PROVEN_TRUE → VALID_SECURITY_ISSUE
3. Assign disposition
4. Compute confidence based on checklist completeness

**Disposition Decision Tree:**
- ALL 6 items PROVEN_TRUE → VALID_SECURITY_ISSUE
- source/sink/dataflow PROVEN_TRUE but boundary/reachable UNKNOWN → BUG
- Some items PROVEN_FALSE (e.g., dataflow blocked by sanitization) → BY_DESIGN
- not_only_misconfig PROVEN_FALSE → MISCONFIGURATION
- Multiple items UNKNOWN → SPECULATIVE
