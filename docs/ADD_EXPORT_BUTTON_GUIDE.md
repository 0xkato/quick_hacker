# How to Add Export Button to Findings Panel

## Quick Integration Guide

This guide shows you exactly how to add the Export Report button to your findings panel.

## Step 1: Locate the FindingsList Component

File: `frontend/components/FindingsPanel/FindingsList.tsx`

## Step 2: Add Import

At the top of the file, add the import (around line 16):

```typescript
import ProofChecklistView from './ProofChecklistView';
import { ExportReportButton } from './ExportReportButton';  // ADD THIS LINE
```

## Step 3: Find the Header Section

Look for the header section with filters (around line 235-250):

```typescript
<div className="px-3 py-2 border-b border-vsc-border-subtle">
  <div className="flex items-center justify-between mb-2">
    <span className="text-vsc-xs text-vsc-text-muted">
      {filteredFindings.length} of {findings.length}
      {triageFilteredCount > 0 && !showFiltered && (
        <span className="ml-1 text-vsc-text-muted">
          ({triageFilteredCount} filtered)
        </span>
      )}
    </span>
    {/* Show Filtered toggle */}
    {triageFilteredCount > 0 && (
      <button
        onClick={() => {
          // ...existing code...
        }}
      >
        {/* ...existing button content... */}
      </button>
    )}
  </div>
```

## Step 4: Modify the Header Structure

Replace the header section with this updated version that includes the export button:

```typescript
<div className="px-3 py-2 border-b border-vsc-border-subtle">
  <div className="flex items-center justify-between mb-2">
    <span className="text-vsc-xs text-vsc-text-muted">
      {filteredFindings.length} of {findings.length}
      {triageFilteredCount > 0 && !showFiltered && (
        <span className="ml-1 text-vsc-text-muted">
          ({triageFilteredCount} filtered)
        </span>
      )}
    </span>

    {/* RIGHT SIDE BUTTONS - UPDATED */}
    <div className="flex items-center gap-2">
      {/* ADD EXPORT BUTTON HERE */}
      <ExportReportButton agentId={agentId} className="text-xs" />

      {/* Existing Show Filtered toggle */}
      {triageFilteredCount > 0 && (
        <button
          onClick={() => {
            setUserToggledShowFiltered(true);
            setShowFiltered(!showFiltered);
          }}
          className="flex items-center gap-1 text-vsc-xs text-vsc-textLink hover:underline"
          title={showFiltered ? 'Hide filtered findings' : 'Show filtered findings'}
        >
          {showFiltered ? (
            <>
              <EyeOff className="w-3 h-3" />
              <span>Hide filtered</span>
            </>
          ) : (
            <>
              <Eye className="w-3 h-3" />
              <span>Show filtered ({triageFilteredCount})</span>
            </>
          )}
        </button>
      )}
    </div>
  </div>
```

## Step 5: Get Agent ID

The `ExportReportButton` needs an `agentId` prop. This should be the same ID used to fetch findings.

**Option A**: If you already have `agentId` in props, use it directly:
```typescript
interface FindingsListProps {
  findings: Finding[];
  onFindingClick: (finding: Finding) => void;
  onNavigateToFile?: (path: string, line?: number) => void;
  agentId: string;  // ADD THIS
}

export function FindingsList({
  findings,
  onFindingClick,
  onNavigateToFile,
  agentId  // ADD THIS
}: FindingsListProps) {
  // ... rest of component
}
```

**Option B**: If findings have a common `agent_id` field:
```typescript
// At the top of the component, extract it from first finding
const agentId = findings[0]?.agent_id || 'unknown';
```

**Option C**: If using project context:
```typescript
// If you have a project context, use that
import { useProject } from '@/context/ProjectContext';

// Inside component
const { currentProject } = useProject();
const agentId = currentProject?.id || 'unknown';
```

## Complete Example

Here's what the modified section looks like in full context:

```typescript
export function FindingsList({
  findings,
  onFindingClick,
  onNavigateToFile,
  agentId  // NEW PROP
}: FindingsListProps) {
  const [filterSeverity, setFilterSeverity] = useState<Severity | 'all'>('all');

  // ... existing state and logic ...

  return (
    <div className="h-full flex flex-col">
      {/* Header with filters */}
      <div className="px-3 py-2 border-b border-vsc-border-subtle">
        <div className="flex items-center justify-between mb-2">
          <span className="text-vsc-xs text-vsc-text-muted">
            {filteredFindings.length} of {findings.length}
            {triageFilteredCount > 0 && !showFiltered && (
              <span className="ml-1 text-vsc-text-muted">
                ({triageFilteredCount} filtered)
              </span>
            )}
          </span>

          {/* Right side controls */}
          <div className="flex items-center gap-2">
            {/* EXPORT BUTTON - NEW */}
            <ExportReportButton agentId={agentId} className="text-xs" />

            {/* Show Filtered toggle - EXISTING */}
            {triageFilteredCount > 0 && (
              <button
                onClick={() => {
                  setUserToggledShowFiltered(true);
                  setShowFiltered(!showFiltered);
                }}
                className="flex items-center gap-1 text-vsc-xs text-vsc-textLink hover:underline"
              >
                {showFiltered ? (
                  <>
                    <EyeOff className="w-3 h-3" />
                    <span>Hide filtered</span>
                  </>
                ) : (
                  <>
                    <Eye className="w-3 h-3" />
                    <span>Show filtered ({triageFilteredCount})</span>
                  </>
                )}
              </button>
            )}
          </div>
        </div>

        {/* Severity filter tabs - EXISTING */}
        <div className="flex gap-1">
          {/* ...existing severity tabs... */}
        </div>
      </div>

      {/* Findings list - EXISTING */}
      <div className="flex-1 overflow-y-auto">
        {/* ...existing findings list... */}
      </div>
    </div>
  );
}
```

## Visual Result

After integration, users will see:
- **Export Report** button in the top right of the findings panel
- Clicking it opens a dropdown with format options
- Options to group findings, include/exclude metadata
- Preview and Export actions

## Testing

1. **Start the backend**:
   ```bash
   cd backend
   uvicorn main:app --reload
   ```

2. **Start the frontend**:
   ```bash
   cd frontend
   npm run dev
   ```

3. **Test the button**:
   - Navigate to a project with findings
   - Click "Export Report"
   - Try different formats (Markdown, HTML, JSON)
   - Test grouping options
   - Click "Preview" to see report in browser
   - Click "Export" to download file

## Troubleshooting

### Button doesn't appear
- Check that you imported `ExportReportButton` correctly
- Verify `agentId` prop is being passed
- Check browser console for errors

### Export fails
- Verify backend is running on port 8000
- Check network tab for API errors
- Ensure authentication token is valid

### No findings to export
- Verify the `agentId` matches your project
- Check that findings exist in database
- Use `/api/reports/findings/stats?agent_id=X` to verify

## Alternative Placements

### Option 1: As a Standalone Button

```typescript
<div className="p-2 border-b border-vsc-border-subtle">
  <ExportReportButton agentId={agentId} />
</div>
```

### Option 2: In a Toolbar

```typescript
<div className="flex items-center justify-between p-2 border-b">
  <h3>Findings</h3>
  <div className="flex gap-2">
    <ExportReportButton agentId={agentId} />
    <button>Other Action</button>
  </div>
</div>
```

### Option 3: Floating Button

```typescript
<div className="relative">
  {/* Findings list */}

  {/* Floating export button */}
  <div className="absolute bottom-4 right-4">
    <ExportReportButton agentId={agentId} />
  </div>
</div>
```

---

**That's it!** Your findings panel now has comprehensive report export functionality.
