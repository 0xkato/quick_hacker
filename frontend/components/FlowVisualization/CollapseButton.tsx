import { ChevronRight, ChevronDown } from 'lucide-react';

interface CollapseButtonProps {
  nodeId: string;
  isCollapsed: boolean;
  descendantCount: number;
  onToggle: (nodeId: string) => void;
}

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
