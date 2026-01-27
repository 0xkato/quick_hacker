# Manual Testing Checklist for LLM Validation

This checklist provides comprehensive testing procedures for the LLM validation system.

## Overview

The LLM validation system consists of:
1. **Pre-Validation Gates** - Fast rule-based filters
2. **LLM Validator** - Agentic investigation with tool use
3. **Triage Pipeline Integration** - Wiring validation into triage flow
4. **Frontend UI** - Validation badges, filters, and reasoning display

## Backend Testing

### Pre-Validation Gates

#### Disposition Gate
- [ ] **HARDENING findings are rejected**
  - Create finding with `disposition=HARDENING`
  - Verify pre-validation gate rejects it
  - Check rejection reasoning mentions disposition filter

- [ ] **BY_DESIGN findings are rejected**
  - Create finding with `disposition=BY_DESIGN`
  - Verify gate rejects it

- [ ] **VALID_SECURITY_ISSUE findings pass gate**
  - Create finding with `disposition=VALID_SECURITY_ISSUE`
  - Verify gate allows it through

- [ ] **BUG findings pass gate**
  - Create finding with `disposition=BUG`
  - Verify gate allows it through

#### Checklist Quality Gate
- [ ] **Findings with insufficient PROVEN items are rejected**
  - Create finding with only 2 PROVEN checklist items
  - Protocol requires min 4 PROVEN items
  - Verify gate rejects it

- [ ] **Findings with sufficient PROVEN items pass gate**
  - Create finding with 4+ PROVEN checklist items
  - Verify gate allows it through

- [ ] **UNKNOWN items are rejected when not allowed**
  - Protocol sets `allow_unknown_in_checklist=False`
  - Finding has 1+ UNKNOWN checklist items
  - Verify gate rejects it

- [ ] **UNKNOWN items pass when allowed**
  - Protocol sets `allow_unknown_in_checklist=True`
  - Finding has UNKNOWN items
  - Verify gate allows it through

#### Social Engineering Gate
- [ ] **Social engineering keywords are detected**
  - Finding description contains "social engineering"
  - No technical sink present
  - Verify gate rejects it

- [ ] **Phishing keywords are detected**
  - Finding title contains "phishing"
  - No PROVEN sink
  - Verify gate rejects it

- [ ] **Technical sink overrides SE detection**
  - Finding mentions "user must click"
  - But has PROVEN sink (XSS, SQLI)
  - Verify gate allows it through

- [ ] **Policy controls SE filtering**
  - Protocol sets `reject_social_engineering_only=False`
  - Finding is SE-only
  - Verify gate allows it through

### LLM Validator

#### Initialization
- [ ] **Validator initializes with correct API key**
  - Set `ANTHROPIC_API_KEY` environment variable
  - Create validator instance
  - Verify no errors

- [ ] **Validator rejects without API key**
  - Unset `ANTHROPIC_API_KEY`
  - Attempt to create validator
  - Verify graceful error message

- [ ] **Validator accepts custom model**
  - Initialize with `model="claude-opus-4-20250514"`
  - Verify model is set correctly

- [ ] **Validator accepts repo_root path**
  - Initialize with valid repo path
  - Verify path is stored and resolved

#### Tool: read_file
- [ ] **File read works for valid paths**
  - Read file: `src/api/routes.py`
  - Verify file contents returned

- [ ] **Path traversal attempts are blocked**
  - Try: `../../../etc/passwd`
  - Verify error: "Access denied - path outside repository"

- [ ] **Absolute paths outside repo are blocked**
  - Try: `/etc/passwd`
  - Verify error: "Access denied"

- [ ] **Symlinks outside repo are blocked**
  - Create symlink to `/etc/passwd`
  - Try to read it
  - Verify error

- [ ] **File size limit is enforced**
  - Read file larger than 100KB
  - Verify content is truncated at 100KB

- [ ] **Non-existent files return error**
  - Try: `nonexistent/file.py`
  - Verify error: "File not found"

- [ ] **Directories return error**
  - Try: `src/`
  - Verify error: "Not a file"

#### Tool: grep_code
- [ ] **Grep works for simple patterns**
  - Pattern: `def execute_command`
  - Verify matching lines returned

- [ ] **Grep works with glob filter**
  - Pattern: `import subprocess`
  - Glob: `**/*.py`
  - Verify only Python files searched

- [ ] **Grep handles no matches**
  - Pattern: `nonexistent_function_xyz`
  - Verify: "No matches found for pattern"

- [ ] **Grep output is limited to 5000 chars**
  - Pattern matches many files
  - Verify output truncated at 5000 chars

- [ ] **Grep timeout works**
  - Very broad pattern (e.g., `.*`)
  - Verify times out after 10 seconds

- [ ] **Grep handles ripgrep not installed**
  - Temporarily rename `rg` binary
  - Verify error: "ripgrep (rg) not found"

#### Tool: glob_files
- [ ] **Glob works for simple patterns**
  - Pattern: `**/*.py`
  - Verify Python files returned

- [ ] **Glob works for specific patterns**
  - Pattern: `**/test_*.py`
  - Verify only test files returned

- [ ] **Glob rejects parent directory patterns**
  - Pattern: `../**/*`
  - Verify error: "Pattern must be relative"

- [ ] **Glob rejects absolute paths**
  - Pattern: `/etc/*`
  - Verify error: "Pattern must be relative"

- [ ] **Glob filters paths outside repo**
  - Symlink to outside directory
  - Pattern matches it
  - Verify symlink is filtered out

- [ ] **Glob limits results to 100 files**
  - Pattern matches >100 files
  - Verify only first 100 returned
  - Verify message: "... (N more files)"

- [ ] **Glob handles no matches**
  - Pattern: `*.nonexistent`
  - Verify: "No files found matching"

#### Validation Prompt
- [ ] **Prompt includes finding details**
  - Verify title, file path, line number present

- [ ] **Prompt includes checklist items**
  - Verify all 6-7 checklist items included
  - Verify PROVEN/UNKNOWN/DISPROVEN status shown

- [ ] **Prompt reflects criticism level**
  - HIGH: "Assume NOT exploitable unless..."
  - MEDIUM: "Accept strong evidence..."
  - LOW: "Trust initial classification..."

- [ ] **Prompt includes investigation tasks**
  - Task 1: Validate attacker control
  - Task 2: Validate reachability
  - Task 3: Differentiate security vs bug

#### Agentic Loop
- [ ] **Multi-turn investigation works**
  - LLM uses 2-3 tool calls
  - Verify multiple API calls made

- [ ] **Tool execution is sequential**
  - LLM calls `read_file`
  - Then calls `grep_code` based on result
  - Verify sequential execution

- [ ] **Response parsing handles VALID decision**
  - LLM returns "DECISION: VALID"
  - Verify `is_valid=True`

- [ ] **Response parsing handles INVALID decision**
  - LLM returns "DECISION: INVALID"
  - Verify `is_valid=False`

- [ ] **Response parsing extracts reasoning**
  - LLM returns reasoning bullets
  - Verify bullets parsed into list

- [ ] **Response parsing extracts category**
  - LLM returns "CATEGORY: command_injection"
  - Verify category extracted

- [ ] **Malformed responses fail safely**
  - LLM returns response without "DECISION:"
  - Verify returns INVALID (conservative)

- [ ] **Timeout protection works**
  - Set very short timeout (1 second)
  - Verify validation times out
  - Verify returns INVALID with timeout reasoning

- [ ] **Max turns limit works**
  - LLM uses >10 tool calls
  - Verify investigation stops at 10 turns
  - Verify returns INVALID (inconclusive)

- [ ] **Error handling works**
  - API returns error (e.g., rate limit)
  - Verify error caught
  - Verify returns INVALID with error reasoning

### Triage Pipeline Integration

- [ ] **Pre-gates run before LLM validator**
  - Finding fails disposition gate
  - Verify LLM validator never called (check logs)

- [ ] **LLM validator runs if pre-gates pass**
  - Finding passes all pre-gates
  - Verify LLM validator called

- [ ] **Validation results are stored on findings**
  - Finding goes through validation
  - Query finding from database
  - Verify `validation_result` field populated

- [ ] **INVALID findings are rejected early**
  - LLM returns INVALID
  - Verify finding doesn't reach protocol evaluator
  - Verify submission_decision is set appropriately

- [ ] **VALID findings continue to protocol evaluation**
  - LLM returns VALID
  - Verify finding reaches protocol evaluator
  - Verify protocol gates still apply

- [ ] **Backward compatibility works**
  - Finding without validation result
  - Verify triage pipeline handles it
  - Verify no errors

- [ ] **Validation can be disabled per protocol**
  - Protocol sets `enable_llm_validation=False`
  - Verify LLM validator not called
  - Verify pre-gates still run

## Frontend Testing

### Validation Badge Component

- [ ] **Badge appears for validated findings**
  - Finding has `validation_result`
  - Verify badge displays in findings list

- [ ] **Badge shows correct status for VALID**
  - `validation_result.is_valid=true`
  - Verify badge shows ✓ and "LLM Validated"

- [ ] **Badge shows correct status for INVALID**
  - `validation_result.is_valid=false`
  - Verify badge shows ✗ and "LLM Rejected"

- [ ] **Badge shows confidence percentage**
  - `validation_result.confidence=95`
  - Verify badge shows "95%"

- [ ] **Badge shows reasoning on hover/click**
  - Hover or click badge
  - Verify reasoning list displays

- [ ] **Badge handles null validation results**
  - Finding has no `validation_result`
  - Verify badge doesn't render (no errors)

- [ ] **Badge handles undefined fields gracefully**
  - `validation_result.reasoning` is undefined
  - Verify badge shows "No reasoning provided"

### Filter Toggle

- [ ] **Filter toggle appears in findings view**
  - Open findings panel
  - Verify toggle is visible

- [ ] **Toggle label is clear**
  - Label: "Show only LLM validated findings"
  - Verify label is readable

- [ ] **Toggling filter shows only validated findings**
  - Enable toggle
  - Verify only findings with `is_valid=true` shown

- [ ] **Count display updates correctly**
  - 20 findings total, 12 validated
  - Enable filter
  - Verify displays "12 of 20 findings"

- [ ] **Filter persists during session**
  - Enable filter
  - Navigate away and back
  - Verify filter still enabled

- [ ] **Filter works with other filters**
  - Enable disposition filter (VALID only)
  - Enable LLM filter
  - Verify both filters apply (AND logic)

- [ ] **Filter works with search**
  - Search for "SQL"
  - Enable LLM filter
  - Verify both search and filter apply

- [ ] **Disabling filter shows all findings**
  - Enable filter (12 shown)
  - Disable filter
  - Verify all 20 findings shown

### Finding Drawer (Detail View)

- [ ] **Validation badge appears in drawer**
  - Open finding detail drawer
  - Verify badge displays

- [ ] **Badge is positioned correctly**
  - Badge near top or header
  - Doesn't overlap other content

- [ ] **Badge styling matches theme**
  - Check light and dark mode
  - Verify colors are consistent

- [ ] **Reasoning is readable and well-formatted**
  - Expand reasoning
  - Verify bullets are formatted
  - Verify no overflow issues

- [ ] **Long reasoning doesn't break layout**
  - Finding has 10+ reasoning bullets
  - Verify scrollable or truncated appropriately

- [ ] **Category badge displays**
  - `validation_result.categories=["command_injection"]`
  - Verify category badge shows

## Integration Testing

### End-to-End Workflow

- [ ] **Complete workflow: finding creation to UI display**
  1. Create finding in backend
  2. Run triage with validation enabled
  3. Check validation result in database
  4. Verify badge appears in UI
  5. Verify reasoning displays correctly

- [ ] **Validation for reachable vulnerability returns VALID**
  - Create finding: command injection in Flask route
  - Route is registered and reachable
  - Verify LLM returns VALID
  - Verify reasoning mentions route registration

- [ ] **Validation for unreachable code returns INVALID**
  - Create finding: exec() in unused function
  - Function never called
  - Verify LLM returns INVALID
  - Verify reasoning mentions "no callers found"

- [ ] **Validation reasoning is clear and accurate**
  - Review LLM reasoning for several findings
  - Verify reasoning makes sense
  - Verify mentions specific files, lines, patterns

- [ ] **Cost tracking: verify reasonable API usage**
  - Process 10 findings
  - Check Anthropic API console
  - Verify ~20-30 API calls (2-3 per finding)
  - Verify token usage is reasonable (~40k tokens)

### Error Handling

- [ ] **API timeout is handled gracefully**
  - Set very short timeout (1s)
  - Verify timeout error caught
  - Verify UI shows rejected badge
  - Verify reasoning explains timeout

- [ ] **API errors don't crash system**
  - Simulate API error (invalid key)
  - Verify error caught and logged
  - Verify returns INVALID safely

- [ ] **Missing files are handled correctly**
  - LLM tries to read non-existent file
  - Verify tool returns error message
  - Verify LLM handles error gracefully

- [ ] **Invalid file paths are rejected**
  - LLM tries path traversal
  - Verify security check blocks it
  - Verify error message returned to LLM

- [ ] **Network errors don't crash system**
  - Disconnect network during validation
  - Verify error caught
  - Verify system continues functioning

## Performance Testing

- [ ] **Pre-gates reduce LLM calls significantly**
  - Process 100 findings
  - Check how many reach LLM validator
  - Verify ~30-50% filtered by pre-gates

- [ ] **Average validation completes in <60s**
  - Process 10 findings
  - Measure time per finding
  - Verify average is <60 seconds

- [ ] **No memory leaks during extended use**
  - Process 100+ findings
  - Monitor memory usage
  - Verify no unbounded growth

- [ ] **Concurrent validations work correctly**
  - Trigger validation of 5 findings simultaneously
  - Verify all complete successfully
  - Verify no race conditions

## Security Testing

### Path Traversal Protection

- [ ] **Path traversal via ../ is blocked**
  - Try: `../../../etc/passwd`
  - Verify: "Access denied"

- [ ] **Path traversal via absolute paths is blocked**
  - Try: `/etc/passwd`
  - Verify: "Access denied"

- [ ] **Path traversal via symlinks is blocked**
  - Create symlink: `link -> /etc/passwd`
  - Try: `link`
  - Verify: access denied or symlink filtered

- [ ] **Path traversal in glob is blocked**
  - Try glob: `../**/*`
  - Verify: "Pattern must be relative"

### Resource Limits

- [ ] **File size limit prevents DoS**
  - Create 10MB file
  - Try to read it
  - Verify only first 100KB read

- [ ] **Grep output limit prevents DoS**
  - Pattern matches thousands of lines
  - Verify output limited to 5000 chars

- [ ] **Glob result limit prevents DoS**
  - Pattern matches thousands of files
  - Verify only first 100 returned

- [ ] **Timeout prevents infinite loops**
  - LLM gets stuck in loop
  - Verify timeout terminates validation

### API Key Security

- [ ] **API key not leaked in logs**
  - Check application logs
  - Verify API key never appears

- [ ] **API key not exposed in errors**
  - Trigger validation error
  - Check error message
  - Verify API key not included

- [ ] **API key not in validation results**
  - Check `validation_result` in database
  - Verify no API key in JSON

### Data Leakage

- [ ] **No sensitive file contents in validation results**
  - LLM reads file with secrets
  - Check validation_result.reasoning
  - Verify secrets are not copied verbatim

- [ ] **No sensitive data sent to frontend**
  - Check API responses to frontend
  - Verify no raw file contents
  - Only reasoning summaries

## Documentation Testing

- [ ] **README instructions are accurate**
  - Follow README setup instructions
  - Verify all steps work
  - Verify examples are correct

- [ ] **Configuration examples work correctly**
  - Copy configuration from docs
  - Apply to protocol
  - Verify validation works

- [ ] **Code examples run without errors**
  - Copy Python code examples from docs
  - Run in Python REPL
  - Verify no syntax errors

- [ ] **API documentation matches implementation**
  - Check Swagger UI at `/docs`
  - Verify validation fields present
  - Verify types match implementation

- [ ] **Threat modeling guide is clear and useful**
  - Read threat modeling guide
  - Follow examples
  - Verify examples work

## Automated Test Suite

- [ ] **All backend tests pass**
  ```bash
  cd backend
  pytest tests/
  ```
  - Verify 59+ tests pass
  - No failures or errors

- [ ] **Pre-validation gate tests pass**
  ```bash
  pytest tests/services/validation/test_pre_validation_gates.py -v
  ```
  - All gate tests pass

- [ ] **LLM validator tests pass**
  ```bash
  pytest tests/integration/test_llm_validation_pipeline.py -v
  ```
  - Integration tests pass

- [ ] **Frontend builds without errors**
  ```bash
  cd frontend
  npm run build
  ```
  - Build succeeds
  - No TypeScript errors

## Sign-Off Checklist

Before marking validation system as production-ready:

- [ ] All backend tests pass (59+ tests)
- [ ] All frontend tests pass (build succeeds)
- [ ] Manual testing checklist complete
- [ ] Documentation is up to date and accurate
- [ ] Security review complete (path traversal, resource limits)
- [ ] Performance is acceptable (<60s per finding)
- [ ] Cost estimates are documented
- [ ] API key security verified
- [ ] Error handling tested and graceful
- [ ] UI is polished and user-friendly

## Notes

### Manual Testing Best Practices

1. **Use Real Repositories**
   - Test with actual codebases
   - Include diverse languages (Python, JavaScript, Go)
   - Include various vulnerability types

2. **Test Edge Cases**
   - Empty files
   - Very large files
   - Non-UTF8 files
   - Binary files

3. **Test Error Conditions**
   - Network failures
   - API errors
   - Invalid inputs
   - Resource exhaustion

4. **Review LLM Reasoning**
   - Check reasoning makes sense
   - Verify accuracy of statements
   - Look for hallucinations

5. **Monitor Costs**
   - Track API usage during testing
   - Estimate costs for production
   - Adjust settings if needed

### Known Limitations

1. **Context Window**
   - LLM has limited context
   - Very large files may be truncated
   - Complex call chains may be missed

2. **Tool Use Limits**
   - Max 10 tool use rounds
   - May not complete very complex investigations
   - Timeout after configured duration

3. **False Negatives**
   - Some valid issues may be filtered
   - Conservative filtering on uncertainty
   - Manual review still recommended

4. **Language Support**
   - Best for Python, JavaScript, Go
   - May struggle with obscure languages
   - Framework-specific knowledge varies

## Reporting Issues

If you find issues during manual testing:

1. **Document the issue**:
   - What you were testing
   - Expected behavior
   - Actual behavior
   - Steps to reproduce

2. **Check logs**:
   - Backend logs: `backend/logs/`
   - LLM validator logs: Look for "LLM validation" entries
   - API errors: Check Anthropic dashboard

3. **Gather evidence**:
   - Screenshots of UI issues
   - API responses (redact API keys!)
   - Validation results from database

4. **File a bug report**:
   - Include all documentation
   - Tag with "llm-validation"
   - Priority based on severity

## Testing Recommendations

### Priority Testing (Must Do)
1. Pre-validation gates (all 3 gates)
2. Tool security (path traversal, resource limits)
3. End-to-end workflow (finding → triage → UI)
4. Error handling (timeouts, API errors)

### Secondary Testing (Should Do)
1. Tool functionality (read_file, grep_code, glob_files)
2. Agentic loop (multi-turn, response parsing)
3. UI components (badge, filter, drawer)
4. Performance (timing, concurrency)

### Optional Testing (Nice to Have)
1. Edge cases (empty files, binary files)
2. Multiple protocols
3. Different criticism levels
4. Cost optimization

---

**Note:** Actual manual UI testing can be performed interactively and is not blocking for documentation completion. This checklist serves as a comprehensive guide for when manual testing is conducted.
