# InvestigationFlow Component

**Active production component** - React Flow-based visualization for AI security audit investigation traces.

## Overview

The InvestigationFlow component is the **default investigation visualization** system, rendering investigation spans as an interactive tree/DAG with:
- Outcome-based coloring (confirmed, refuted, inconclusive)
- Collapse/expand functionality for hypothesis nodes
- Event and artifact count display
- Focus gap indicators
- Artifact provenance tracking with evidence edges
- Real-time reconstruction from agent events
- Feature flag-controlled activation (SPAN_BASED_FLOW: enabled by default)

## Components

### TreeLayout

Main component that renders the investigation tree.

```tsx
import { TreeLayout } from '@/components/InvestigationFlow';

<TreeLayout
  spans={spansRecord}
  edges={edgesArray}
/>
```

**Props:**
- `spans`: Record<string, Span> - Map of span_id to Span objects
- `edges`: Edge[] - Array of edge objects connecting spans

### HypothesisNode

Custom node component for rendering hypothesis spans with outcome-based styling.

## Data Types

### Span

```typescript
interface Span {
  span_id: string;
  span_type: 'hypothesis' | 'hypothesis_visit' | 'critic_pass' | 'placeholder';
  hypothesis_id: string | null;
  label: string;
  state: 'open' | 'completed' | 'discarded';
  outcome: 'confirmed' | 'refuted' | 'inconclusive' | null;
  parent_span_id: string | null;
  created_turn_id: number;
  completed_at: number | null;
  focus_gap: string | null;
  focus_note: string | null;
  stage: string | null;
  event_ids: number[];
  artifact_ids: number[];
  is_collapsed: boolean;
}
```

### Edge

```typescript
interface Edge {
  id: string;
  source: string;
  target: string;
  edge_type: 'parent_child' | 'evidence_link';
  label?: string;
  style?: 'dashed' | 'solid';
  hidden?: boolean;
}
```

## Styling

### Outcome Colors

- **Confirmed**: Green border and background
- **Refuted**: Red border and background
- **Inconclusive**: Yellow border and background
- **Open**: Blue border and background
- **Discarded**: Gray border and background

### Edge Types

- **parent_child**: Default straight lines
- **evidence_link**: Smooth step lines
- **dashed style**: Dotted lines

## Usage Example

```tsx
import React from 'react';
import { TreeLayout, Span, Edge } from '@/components/InvestigationFlow';

const ExampleInvestigationTree: React.FC = () => {
  const spans: Record<string, Span> = {
    'span-1': {
      span_id: 'span-1',
      span_type: 'hypothesis',
      hypothesis_id: 'hyp-1',
      label: 'Root Hypothesis: Investigate authentication flow',
      state: 'completed',
      outcome: 'confirmed',
      parent_span_id: null,
      created_turn_id: 1,
      completed_at: 1234567890,
      focus_gap: null,
      focus_note: null,
      stage: 'initial',
      event_ids: [1, 2, 3],
      artifact_ids: [10, 11],
      is_collapsed: false,
    },
    'span-2': {
      span_id: 'span-2',
      span_type: 'hypothesis',
      hypothesis_id: 'hyp-2',
      label: 'Check JWT validation',
      state: 'completed',
      outcome: 'refuted',
      parent_span_id: 'span-1',
      created_turn_id: 2,
      completed_at: 1234567900,
      focus_gap: 'Token expiry check',
      focus_note: null,
      stage: 'validation',
      event_ids: [4, 5],
      artifact_ids: [12],
      is_collapsed: false,
    },
  };

  const edges: Edge[] = [
    {
      id: 'edge-1-2',
      source: 'span-1',
      target: 'span-2',
      edge_type: 'parent_child',
    },
  ];

  return (
    <div style={{ width: '100%', height: '600px' }}>
      <TreeLayout spans={spans} edges={edges} />
    </div>
  );
};

export default ExampleInvestigationTree;
```

## Features

### Collapse/Expand

Nodes with events can be collapsed/expanded using the ▶/▼ button. When collapsed:
- Child spans are hidden
- Edges to/from hidden spans are filtered out

### Empty State

When no spans are provided, displays: "No investigation data available"

### Interactive Controls

- **Zoom**: Mouse wheel or controls
- **Pan**: Click and drag
- **Fit View**: Automatically fits all nodes in view
- **MiniMap**: Overview of entire tree in bottom-right corner

## Integration

This component is **fully integrated** with the investigation trace system:

### Backend Integration
- **Reconstruction Service** (`backend/services/reconstruction_service.py`): Transforms flat event streams into structured DAG
- **API Endpoint**: `POST /api/agents/{agent_id}/reconstruct` - Processes events and returns spans/edges
- **Artifact Service**: Tracks artifact provenance for evidence edges
- **Feature Flags**: `SPAN_BASED_FLOW` flag controls activation (enabled by default)

### Frontend Integration
- **useInvestigationFlow Hook** (`hooks/useInvestigationFlow.ts`): Fetches and manages span data
- **Page Integration** (`app/page.tsx`): Conditional rendering based on feature flag
- **API Client** (`lib/api.ts`): `agents.reconstruct()` method for backend calls

### Data Flow
```
ReactAgent emits events
  ↓
FlowService tracks events
  ↓
Frontend polls/receives events
  ↓
useInvestigationFlow calls POST /reconstruct
  ↓
ReconstructionService processes events
  ↓
Returns spans + edges + event_to_span
  ↓
TreeLayout renders interactive visualization
```

## Current Status

**Production Ready**: This system is active by default and handles all investigation visualization.

To revert to legacy FlowVisualization:
```python
# backend/services/feature_flags.py
FeatureFlag.SPAN_BASED_FLOW: False  # Change from True
```

## Architecture Notes

**Layout**: Uses simple vertical stacking for performance. Advanced tree layout (dagre) can be added if complex hierarchies require better positioning.

**Performance**: Optimized with React.memo, useMemo, and O(1) lookups for hidden span detection.

**Error Handling**: Wrapped in ErrorBoundary to prevent crashes from ReactFlow errors.

## Future Enhancements

- Advanced tree layout algorithm (dagre/hierarchical) for complex DAGs
- Search and filter functionality
- Node detail popovers with event/artifact drill-down
- Export to PNG/SVG
- Timeline view toggle
- Progressive loading for large investigation trees
