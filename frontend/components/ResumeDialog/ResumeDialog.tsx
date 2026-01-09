'use client';

import { X } from 'lucide-react';
import type { SnapshotInfo } from '@/types';

interface ResumeDialogProps {
  snapshotInfo: SnapshotInfo;
  onRestore: () => void;
  onKeepCurrent: () => void;
  onClose: () => void;
}

export function ResumeDialog({
  snapshotInfo,
  onRestore,
  onKeepCurrent,
  onClose,
}: ResumeDialogProps) {
  const formattedDate = new Date(snapshotInfo.timestamp).toLocaleString();

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="bg-zinc-800 rounded-lg shadow-xl w-full max-w-md mx-4 border border-zinc-700">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-700">
          <h2 className="text-lg font-semibold text-zinc-100">
            Saved Session Found
          </h2>
          <button
            onClick={onClose}
            className="p-1 rounded-md hover:bg-zinc-700 text-zinc-400 hover:text-zinc-200 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="px-6 py-4 space-y-4">
          <p className="text-zinc-400 text-sm">
            From: <span className="text-zinc-200">{formattedDate}</span>
          </p>

          <ul className="space-y-2 text-sm">
            <li className="flex items-center gap-2 text-zinc-300">
              <span className="w-2 h-2 rounded-full bg-amber-500" />
              {snapshotInfo.agent_count} paused agent{snapshotInfo.agent_count !== 1 ? 's' : ''}
            </li>
            <li className="flex items-center gap-2 text-zinc-300">
              <span className="w-2 h-2 rounded-full bg-red-500" />
              {snapshotInfo.findings_count} finding{snapshotInfo.findings_count !== 1 ? 's' : ''}
            </li>
            <li className="flex items-center gap-2 text-zinc-300">
              <span className="w-2 h-2 rounded-full bg-blue-500" />
              {snapshotInfo.pending_files} file{snapshotInfo.pending_files !== 1 ? 's' : ''} remaining
            </li>
          </ul>
        </div>

        {/* Actions */}
        <div className="flex gap-3 px-6 py-4 border-t border-zinc-700">
          <button
            onClick={onKeepCurrent}
            className="flex-1 px-4 py-2 text-sm font-medium rounded-md bg-zinc-700 hover:bg-zinc-600 text-zinc-200 transition-colors"
          >
            Keep Current
          </button>
          <button
            onClick={onRestore}
            className="flex-1 px-4 py-2 text-sm font-medium rounded-md bg-green-600 hover:bg-green-700 text-white transition-colors"
          >
            Restore Session
          </button>
        </div>
      </div>
    </div>
  );
}
