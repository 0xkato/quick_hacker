'use client';

import { useEffect, useCallback } from 'react';
import { X } from 'lucide-react';
import { ReportPanel } from './ReportPanel';
import { InvestigationReport } from '@/types';

interface ReportModalProps {
  report: InvestigationReport;
  isOpen: boolean;
  onClose: () => void;
  onDownload: (format: 'md' | 'json' | 'svg') => void;
}

export function ReportModal({ report, isOpen, onClose, onDownload }: ReportModalProps) {
  // Handle escape key
  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    },
    [onClose]
  );

  useEffect(() => {
    if (isOpen) {
      document.addEventListener('keydown', handleKeyDown);
      document.body.style.overflow = 'hidden';
    }
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = '';
    };
  }, [isOpen, handleKeyDown]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="relative w-full max-w-3xl h-[80vh] bg-vsc-bg border border-vsc-border rounded-lg shadow-2xl overflow-hidden flex flex-col">
        {/* Close button */}
        <button
          onClick={onClose}
          className="absolute top-3 right-3 z-10 p-1 hover:bg-vsc-hover rounded text-vsc-text-muted hover:text-vsc-text"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Report content */}
        <ReportPanel report={report} onDownload={onDownload} />
      </div>
    </div>
  );
}
