'use client';

import { useState, useCallback } from 'react';
import type { FileNode, FileContent } from '@/types';
import { files, type Project } from '@/lib/api';

export interface UseProjectWorkspaceOptions {
  currentProject: Project | null;
}

export interface UseProjectWorkspaceResult {
  fileTree: FileNode | null;
  currentFile: FileContent | null;
  selectedPath: string | null;
  setFileTree: React.Dispatch<React.SetStateAction<FileNode | null>>;
  setCurrentFile: React.Dispatch<React.SetStateAction<FileContent | null>>;
  setSelectedPath: React.Dispatch<React.SetStateAction<string | null>>;
  loadFileTree: () => Promise<void>;
  expandDirectory: (path: string) => Promise<void>;
  selectFile: (path: string) => Promise<void>;
  clearFile: () => void;
}

export function useProjectWorkspace({
  currentProject,
}: UseProjectWorkspaceOptions): UseProjectWorkspaceResult {
  const [fileTree, setFileTree] = useState<FileNode | null>(null);
  const [currentFile, setCurrentFile] = useState<FileContent | null>(null);
  const [selectedPath, setSelectedPath] = useState<string | null>(null);

  const setDirectoryChildren = useCallback((path: string, children: FileNode[] | null | undefined) => {
    setFileTree((prev) => {
      if (!prev) return prev;

      const updateNode = (node: FileNode): FileNode => {
        if (node.path === path) {
          return { ...node, children: children ?? [] };
        }

        if (!Array.isArray(node.children)) {
          return node;
        }

        let changed = false;
        const nextChildren = node.children.map((child) => {
          const updated = updateNode(child);
          if (updated !== child) changed = true;
          return updated;
        });

        return changed ? { ...node, children: nextChildren } : node;
      };

      return updateNode(prev);
    });
  }, []);

  const loadFileTree = useCallback(async () => {
    if (!currentProject) return;

    // Skip only if definitely no repo info at all
    if (!currentProject.repo_name && !currentProject.is_cloned) return;

    try {
      // Load a shallow tree initially; directories are lazily expanded on demand.
      const tree = await files.getTree(currentProject.id, 1, '', { maxChildren: 200, maxNodes: 5000 });
      setFileTree(tree);
    } catch (err) {
      console.error('Failed to load file tree:', err);
    }
  }, [currentProject]);

  const expandDirectory = useCallback(async (path: string) => {
    if (!currentProject) return;

    try {
      const subtree = await files.getTree(currentProject.id, 1, path, { maxChildren: 200, maxNodes: 5000 });
      setDirectoryChildren(path, subtree.children);
    } catch (err) {
      console.error('Failed to expand directory:', err);
    }
  }, [currentProject, setDirectoryChildren]);

  const selectFile = useCallback(async (path: string) => {
    if (!currentProject) return;

    setSelectedPath(path);

    try {
      const content = await files.getContent(currentProject.id, path);
      setCurrentFile(content);
    } catch (err) {
      console.error('Failed to load file:', err);
    }
  }, [currentProject]);

  const clearFile = useCallback(() => {
    setCurrentFile(null);
    setSelectedPath(null);
  }, []);

  return {
    fileTree,
    currentFile,
    selectedPath,
    setFileTree,
    setCurrentFile,
    setSelectedPath,
    loadFileTree,
    expandDirectory,
    selectFile,
    clearFile,
  };
}
