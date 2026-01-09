'use client';

import React, { useState, useMemo } from 'react';

export interface PathRecord {
  id: string;
  entryPoint: {
    filePath: string;
    lineNumber: number;
    name: string;
    route?: string;
  };
  sink: {
    filePath: string;
    lineNumber: number;
    functionName: string;
    sinkType: string;
  };
  status: 'discovered' | 'in_progress' | 'traced_safe' | 'traced_vuln' | 'blocked' | 'inconclusive';
  verdictReasoning?: string;
  findingId?: string;
}

export interface CoverageStats {
  total: number;
  traced: number;
  remaining: number;
  coveragePercent: number;
  vulnCount?: number;
}

interface CoverageTreeProps {
  paths: PathRecord[];
  stats: CoverageStats;
  onPathClick?: (path: PathRecord) => void;
}

const STATUS_ICONS: Record<string, string> = {
  discovered: '[ ]',
  in_progress: '[~]',
  traced_safe: '[ok]',
  traced_vuln: '[!!]',
  blocked: '[x]',
  inconclusive: '[?]',
};

const STATUS_COLORS: Record<string, string> = {
  discovered: 'text-gray-400',
  in_progress: 'text-blue-500',
  traced_safe: 'text-green-600',
  traced_vuln: 'text-red-600',
  blocked: 'text-gray-500',
  inconclusive: 'text-yellow-600',
};

interface EntryPointNodeProps {
  paths: PathRecord[];
  onPathClick?: (path: PathRecord) => void;
}

function EntryPointNode({ paths, onPathClick }: EntryPointNodeProps) {
  const [expanded, setExpanded] = useState(true);
  if (paths.length === 0) return null;
  const ep = paths[0].entryPoint;
  const tracedCount = paths.filter(p =>
    ['traced_safe', 'traced_vuln', 'blocked'].includes(p.status)
  ).length;

  return (
    <div className="entry-point-node mb-1">
      <div
        role="button"
        tabIndex={0}
        className="cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-800 p-1 rounded flex items-center"
        onClick={() => setExpanded(!expanded)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            setExpanded(!expanded);
          }
        }}
        aria-expanded={expanded}
      >
        <span className="mr-1 text-gray-500">{expanded ? 'v' : '>'}</span>
        <span className="font-medium">{ep.route || ep.name}</span>
        <span className="ml-2 text-gray-500 text-sm">
          ({ep.filePath}:{ep.lineNumber})
        </span>
        <span className="ml-auto text-sm text-gray-400">
          {tracedCount}/{paths.length}
        </span>
      </div>

      {expanded && (
        <div className="ml-4 border-l border-gray-200 dark:border-gray-700 pl-2">
          {paths.map(path => (
            <div
              key={path.id}
              role="button"
              tabIndex={0}
              className={`p-1 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800 rounded text-sm ${STATUS_COLORS[path.status]}`}
              onClick={() => onPathClick?.(path)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  onPathClick?.(path);
                }
              }}
            >
              <span className="font-mono">{STATUS_ICONS[path.status]}</span>
              <span className="ml-1">-{'>'}</span>
              <span className="ml-1">{path.sink.functionName}</span>
              <span className="ml-1 text-gray-500">
                ({path.sink.filePath}:{path.sink.lineNumber})
              </span>
              {path.verdictReasoning && (
                <span className="ml-2 text-gray-400 text-xs italic">
                  - {path.verdictReasoning}
                </span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function CoverageTree({ paths, stats, onPathClick }: CoverageTreeProps) {
  const grouped = useMemo(() => {
    const map = new Map<string, PathRecord[]>();
    for (const path of paths) {
      const key = `${path.entryPoint.filePath}:${path.entryPoint.lineNumber}`;
      if (!map.has(key)) map.set(key, []);
      map.get(key)!.push(path);
    }
    return map;
  }, [paths]);

  return (
    <div className="coverage-tree h-full flex flex-col">
      {/* Summary bar */}
      <div className="coverage-summary p-2 border-b border-gray-200 dark:border-gray-700 flex items-center gap-4 text-sm">
        <span>
          Coverage: {stats.traced}/{stats.total} ({stats.coveragePercent.toFixed(1)}%)
        </span>
        {stats.vulnCount !== undefined && stats.vulnCount > 0 && (
          <span className="text-red-600">{stats.vulnCount} vulns</span>
        )}
        <span className="text-gray-400">{stats.remaining} remaining</span>
      </div>

      {/* Progress bar */}
      <div className="h-1 bg-gray-200 dark:bg-gray-700">
        <div
          className="h-full bg-green-500 transition-all duration-300"
          style={{ width: `${stats.coveragePercent}%` }}
        />
      </div>

      {/* Tree */}
      <div className="tree-content flex-1 overflow-y-auto p-2 font-mono text-sm">
        {paths.length === 0 ? (
          <div className="text-gray-400 text-center py-4">
            No paths discovered yet
          </div>
        ) : (
          Array.from(grouped.entries()).map(([epKey, epPaths]) => (
            <EntryPointNode
              key={epKey}
              paths={epPaths}
              onPathClick={onPathClick}
            />
          ))
        )}
      </div>

      {/* Legend */}
      <div className="legend p-2 border-t border-gray-200 dark:border-gray-700 text-xs text-gray-500 flex gap-3">
        <span>[ ] discovered</span>
        <span className="text-blue-500">[~] in progress</span>
        <span className="text-green-600">[ok] safe</span>
        <span className="text-red-600">[!!] vuln</span>
        <span>[x] blocked</span>
        <span className="text-yellow-600">[?] inconclusive</span>
      </div>
    </div>
  );
}
