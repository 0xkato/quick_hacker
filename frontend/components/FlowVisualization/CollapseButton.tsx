import { ChevronRight, ChevronDown } from 'lucide-react';

interface CollapseButtonProps {
  nodeId: string;
  isCollapsed: boolean;
  descendantCount: number;
  onToggle: (nodeId: string) => void;
}

/**
 * Collapse/expand button for tree nodes with children.
 *
 * Displays:
 * - ▶ +count when collapsed (shows number of hidden descendants)
 * - ▼ when expanded
 * - Nothing if node has no children
 *
 * @param nodeId - Node identifier
 * @param isCollapsed - Whether subtree is currently collapsed
 * @param descendantCount - Number of descendants (children, grandchildren, etc.)
 * @param onToggle - Callback when button is clicked
 */
export function CollapseButton({
  nodeId,
  isCollapsed,
  descendantCount,
  onToggle
}: CollapseButtonProps) {
  if (descendantCount === 0) {
    return null; // No children, no button
  }

  return (
    <button
      onClick={(e) => {
        e.stopPropagation();
        onToggle(nodeId);
      }}
      className="absolute top-1 right-1 p-1 hover:bg-vsc-hover rounded transition-colors"
      title={isCollapsed ? `Expand ${descendantCount} nodes` : 'Collapse subtree'}
      aria-label={isCollapsed ? `Expand ${descendantCount} nodes` : 'Collapse subtree'}
      aria-expanded={!isCollapsed}
      type="button"
    >
      {isCollapsed ? (
        <div className="flex items-center gap-1">
          <ChevronRight className="w-3 h-3" />
          <span className="text-xs">+{descendantCount}</span>
        </div>
      ) : (
        <ChevronDown className="w-3 h-3" />
      )}
    </button>
  );
}
