'use client';

import { useState, useCallback } from 'react';
import {
  ChevronRight,
  File,
  Folder,
  FolderOpen,
} from 'lucide-react';
import clsx from 'clsx';
import type { FileNode } from '@/types';

interface FileTreeProps {
  tree: FileNode | null;
  selectedPath: string | null;
  onFileSelect: (path: string) => void;
  onDirectoryExpand?: (path: string) => Promise<void>;
}

// File type icons with VSCode-like colors
const FILE_ICON_COLORS: Record<string, string> = {
  '.py': 'text-[#3572A5]',
  '.js': 'text-[#f1e05a]',
  '.jsx': 'text-[#61dafb]',
  '.ts': 'text-[#3178c6]',
  '.tsx': 'text-[#3178c6]',
  '.json': 'text-[#cbcb41]',
  '.md': 'text-[#083fa1]',
  '.yml': 'text-[#cb171e]',
  '.yaml': 'text-[#cb171e]',
  '.go': 'text-[#00ADD8]',
  '.rs': 'text-[#dea584]',
  '.java': 'text-[#b07219]',
  '.rb': 'text-[#701516]',
  '.php': 'text-[#4F5D95]',
  '.c': 'text-[#555555]',
  '.cpp': 'text-[#f34b7d]',
  '.h': 'text-[#555555]',
  '.sol': 'text-[#AA6746]',
  '.css': 'text-[#563d7c]',
  '.scss': 'text-[#c6538c]',
  '.html': 'text-[#e34c26]',
  '.vue': 'text-[#41b883]',
  '.svelte': 'text-[#ff3e00]',
};

function getFileIconColor(extension: string | undefined): string {
  if (!extension) return 'text-vsc-text-muted';
  return FILE_ICON_COLORS[extension] || 'text-vsc-text-muted';
}

interface TreeNodeProps {
  node: FileNode;
  depth: number;
  selectedPath: string | null;
  onFileSelect: (path: string) => void;
  expandedPaths: Set<string>;
  onToggleExpand: (path: string) => void;
  onDirectoryExpand?: (path: string) => Promise<void>;
}

function TreeNode({
  node,
  depth,
  selectedPath,
  onFileSelect,
  expandedPaths,
  onToggleExpand,
  onDirectoryExpand,
}: TreeNodeProps) {
  const isExpanded = expandedPaths.has(node.path);
  const isSelected = selectedPath === node.path;

  const handleClick = async () => {
    if (node.is_dir) {
      // Lazy-load children on first expand (huge repos like chromium cannot be fully preloaded).
      if (!isExpanded && !Array.isArray(node.children) && onDirectoryExpand) {
        await onDirectoryExpand(node.path);
      }
      onToggleExpand(node.path);
    } else {
      onFileSelect(node.path);
    }
  };

  return (
    <div>
      <div
        className={clsx('file-tree-item', isSelected && 'selected')}
        style={{ paddingLeft: `${depth * 16 + 8}px` }}
        onClick={handleClick}
      >
        {node.is_dir ? (
          <>
            <span
              className="text-vsc-text-muted"
              style={{
                transition: 'transform 150ms ease-out',
                transform: isExpanded ? 'rotate(90deg)' : 'rotate(0deg)'
              }}
            >
              <ChevronRight className="w-4 h-4" />
            </span>
            <span className="text-[#dcb67a]">
              {isExpanded ? (
                <FolderOpen className="w-4 h-4" />
              ) : (
                <Folder className="w-4 h-4" />
              )}
            </span>
          </>
        ) : (
          <>
            <span className="w-4" />
            <File className={clsx('w-4 h-4', getFileIconColor(node.extension))} />
          </>
        )}
        <span className="truncate text-vsc-sm">{node.name}</span>
      </div>

      {node.is_dir && isExpanded && node.children && (
        <div>
          {node.children.map((child) => (
            <TreeNode
              key={child.path}
              node={child}
              depth={depth + 1}
              selectedPath={selectedPath}
              onFileSelect={onFileSelect}
              expandedPaths={expandedPaths}
              onToggleExpand={onToggleExpand}
              onDirectoryExpand={onDirectoryExpand}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export function FileTree({ tree, selectedPath, onFileSelect, onDirectoryExpand }: FileTreeProps) {
  const [expandedPaths, setExpandedPaths] = useState<Set<string>>(new Set(['']));

  const handleToggleExpand = useCallback((path: string) => {
    setExpandedPaths((prev) => {
      const next = new Set(prev);
      if (next.has(path)) {
        next.delete(path);
      } else {
        next.add(path);
      }
      return next;
    });
  }, []);

  if (!tree) {
    return (
      <div className="empty-state">
        <Folder className="empty-state-icon" />
        <p className="empty-state-text">No repository loaded</p>
        <p className="text-vsc-xs mt-1">Clone a repository to get started</p>
      </div>
    );
  }

  return (
    <div className="overflow-auto h-full py-1">
      {tree.children?.map((node) => (
        <TreeNode
          key={node.path}
          node={node}
          depth={0}
          selectedPath={selectedPath}
          onFileSelect={onFileSelect}
          expandedPaths={expandedPaths}
          onToggleExpand={handleToggleExpand}
          onDirectoryExpand={onDirectoryExpand}
        />
      ))}
    </div>
  );
}
