# Flow Tree Visualization - Verification Checklist

## Backend Verification

### FlowService
- [ ] FlowContext added to InvestigationFlow
- [ ] New node types (file, function, call, external, auth_boundary) work
- [ ] update_context() preserves existing fields
- [ ] get_or_create_file_node() returns existing or None
- [ ] auto_parent=True uses context correctly
- [ ] Explicit parent_id overrides auto_parent

### Agent Integration
- [ ] read_file creates file node
- [ ] read_file extracts functions
- [ ] Function nodes are children of file
- [ ] Context updates on file read
- [ ] Multiple file reads create separate nodes

## Frontend Verification

### Layout
- [ ] Multiple investigation trees display side-by-side
- [ ] No overlapping nodes
- [ ] Trees with more branches get more width
- [ ] Parent nodes centered over children
- [ ] Deep trees don't overflow viewport

### Visual
- [ ] File nodes show blue FileText icon
- [ ] Function nodes show purple Code icon
- [ ] Call nodes show green ArrowRight icon
- [ ] Legend displays new node types
- [ ] Tooltips show node details

## Integration Testing

### End-to-End Flow
- [ ] Start scan creates root node
- [ ] Triage creates candidate nodes
- [ ] Reading file creates tree structure
- [ ] Multiple candidates create parallel trees
- [ ] Clicking node shows details in popover

### Performance
- [ ] Layout calculates quickly for 100+ nodes
- [ ] No UI lag when adding nodes
- [ ] ReactFlow viewport smooth with multiple trees

## Manual Testing Steps

### Test 1: Basic Tree Creation
1. Start backend: `./run-local.sh`
2. Create agent in UI
3. Select file to audit
4. Verify flow visualization shows:
   - Scan root
   - Entry points/sinks as children
   - Files as children of candidates
   - Functions as children of files

### Test 2: Multiple Investigation Trees
1. Run scan that finds 3+ candidates
2. Verify each candidate starts its own tree
3. Verify trees don't overlap
4. Verify trees are visually distinct

### Test 3: Deep Investigation
1. Investigate one candidate deeply (read multiple files)
2. Verify tree grows vertically
3. Verify function nodes appear
4. Verify no performance issues

## Known Limitations

- Function extraction limited to 10 per file
- Only Python and JavaScript function patterns supported
- Call extraction depends on LLM output format
- No collapsible subtrees yet

## Future Enhancements

- [ ] Add call node creation when tracing calls
- [ ] Support more languages for function extraction
- [ ] Add subtree collapse/expand
- [ ] Add filtering by node type
- [ ] Add search/highlight in tree
