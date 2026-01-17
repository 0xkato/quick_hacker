'use client';

import { useState } from 'react';
import { Download } from 'lucide-react';

interface DownloadReportButtonProps {
  agentId: string;
}

export function DownloadReportButton({ agentId }: DownloadReportButtonProps) {
  const [isDownloading, setIsDownloading] = useState(false);

  const handleDownload = async () => {
    if (!agentId) {
      alert('No agent selected');
      return;
    }

    setIsDownloading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`/api/agents/${agentId}/report`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        const error = await response.text();
        throw new Error(error || 'Failed to download report');
      }

      // Get filename from headers or use default
      const contentDisposition = response.headers.get('Content-Disposition');
      let filename = `security-report-${agentId}.md`;
      if (contentDisposition) {
        const match = contentDisposition.match(/filename="?(.+)"?/i);
        if (match) {
          filename = match[1];
        }
      }

      // Download file
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Failed to download report:', error);
      alert('Failed to download report. Please try again.');
    } finally {
      setIsDownloading(false);
    }
  };

  return (
    <button
      onClick={handleDownload}
      disabled={isDownloading || !agentId}
      className="flex items-center gap-1.5 px-2 py-1 text-vsc-xs transition-all hover:bg-vsc-hover disabled:opacity-50 disabled:cursor-not-allowed"
      style={{
        borderRadius: 'var(--radius-sm)',
        border: '1px solid var(--vsc-border)',
        color: 'var(--vsc-text-muted)',
      }}
      title="Download all findings as Markdown report"
    >
      <Download className="w-3 h-3" />
      <span>{isDownloading ? 'Downloading...' : 'Download Report'}</span>
    </button>
  );
}
