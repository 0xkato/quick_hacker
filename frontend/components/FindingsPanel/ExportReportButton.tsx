"use client";

import React, { useState } from "react";
import { Download, FileText, Code, FileJson } from "lucide-react";

interface ExportReportButtonProps {
  agentId: string;
  className?: string;
}

type ReportFormat = "markdown" | "html" | "json";
type GroupBy = "severity" | "disposition" | "category" | "submission" | null;

export const ExportReportButton: React.FC<ExportReportButtonProps> = ({
  agentId,
  className = "",
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [selectedFormat, setSelectedFormat] = useState<ReportFormat>("markdown");
  const [showOptions, setShowOptions] = useState(false);
  const [groupBy, setGroupBy] = useState<GroupBy>(null);
  const [includeMetadata, setIncludeMetadata] = useState(true);

  const handleExport = async () => {
    setIsExporting(true);

    try {
      // Build query parameters
      const params = new URLSearchParams({
        agent_id: agentId,
        format: selectedFormat,
        include_metadata: includeMetadata.toString(),
      });

      if (groupBy) {
        params.append("group_by", groupBy);
      }

      // Fetch report
      const response = await fetch(`/api/reports/findings/export?${params.toString()}`, {
        headers: {
          Authorization: `Bearer ${localStorage.getItem("token")}`,
        },
      });

      if (!response.ok) {
        throw new Error("Failed to generate report");
      }

      // Get filename from headers or create default
      const contentDisposition = response.headers.get("Content-Disposition");
      let filename = `security-report-${agentId}.${getFileExtension(selectedFormat)}`;

      if (contentDisposition) {
        const filenameMatch = contentDisposition.match(/filename="?(.+)"?/i);
        if (filenameMatch) {
          filename = filenameMatch[1];
        }
      }

      // Download file
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);

      setIsOpen(false);
      setShowOptions(false);
    } catch (error) {
      console.error("Export failed:", error);
      alert("Failed to export report. Please try again.");
    } finally {
      setIsExporting(false);
    }
  };

  const handlePreview = async () => {
    const params = new URLSearchParams({
      agent_id: agentId,
      format: selectedFormat,
      limit: "5",
    });

    const url = `/api/reports/findings/preview?${params.toString()}`;
    window.open(url, "_blank");
  };

  const getFileExtension = (format: ReportFormat): string => {
    switch (format) {
      case "markdown":
        return "md";
      case "html":
        return "html";
      case "json":
        return "json";
      default:
        return "txt";
    }
  };

  const formatOptions: { value: ReportFormat; label: string; icon: React.ReactNode }[] = [
    { value: "markdown", label: "Markdown", icon: <FileText className="w-4 h-4" /> },
    { value: "html", label: "HTML", icon: <Code className="w-4 h-4" /> },
    { value: "json", label: "JSON", icon: <FileJson className="w-4 h-4" /> },
  ];

  const groupByOptions: { value: GroupBy; label: string }[] = [
    { value: null, label: "No grouping" },
    { value: "severity", label: "Group by Severity" },
    { value: "disposition", label: "Group by Disposition" },
    { value: "category", label: "Group by Category" },
    { value: "submission", label: "Group by Submission Decision" },
  ];

  return (
    <div className="relative">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className={`flex items-center gap-2 px-4 py-2 bg-vsc-button-bg hover:bg-vsc-button-hover-bg text-vsc-button-fg border border-vsc-input-border rounded transition-colors ${className}`}
        disabled={isExporting}
      >
        <Download className="w-4 h-4" />
        <span>Export Report</span>
      </button>

      {isOpen && (
        <div className="absolute right-0 mt-2 w-80 bg-vsc-dropdown-bg border border-vsc-input-border rounded-lg shadow-lg z-50">
          <div className="p-4 space-y-4">
            {/* Format Selection */}
            <div>
              <label className="block text-xs font-semibold text-vsc-foreground mb-2">
                Report Format
              </label>
              <div className="space-y-2">
                {formatOptions.map((option) => (
                  <button
                    key={option.value}
                    onClick={() => setSelectedFormat(option.value)}
                    className={`w-full flex items-center gap-3 px-3 py-2 rounded transition-colors ${
                      selectedFormat === option.value
                        ? "bg-vsc-list-active-selection-bg text-vsc-list-active-selection-fg"
                        : "hover:bg-vsc-list-hover-bg"
                    }`}
                  >
                    {option.icon}
                    <span className="text-sm">{option.label}</span>
                    {selectedFormat === option.value && (
                      <span className="ml-auto text-xs">✓</span>
                    )}
                  </button>
                ))}
              </div>
            </div>

            {/* Advanced Options Toggle */}
            <button
              onClick={() => setShowOptions(!showOptions)}
              className="w-full text-left text-xs text-vsc-textLink hover:underline"
            >
              {showOptions ? "Hide" : "Show"} Advanced Options
            </button>

            {/* Advanced Options */}
            {showOptions && (
              <div className="space-y-3 pt-2 border-t border-vsc-input-border">
                {/* Group By */}
                <div>
                  <label className="block text-xs font-semibold text-vsc-foreground mb-2">
                    Group Findings
                  </label>
                  <select
                    value={groupBy || ""}
                    onChange={(e) => setGroupBy((e.target.value as GroupBy) || null)}
                    className="w-full px-3 py-2 text-sm bg-vsc-input-bg text-vsc-input-fg border border-vsc-input-border rounded focus:border-vsc-focusBorder focus:outline-none"
                  >
                    {groupByOptions.map((option) => (
                      <option key={option.label} value={option.value || ""}>
                        {option.label}
                      </option>
                    ))}
                  </select>
                </div>

                {/* Include Metadata */}
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={includeMetadata}
                    onChange={(e) => setIncludeMetadata(e.target.checked)}
                    className="w-4 h-4"
                  />
                  <span className="text-sm text-vsc-foreground">
                    Include detailed metadata
                  </span>
                </label>
              </div>
            )}

            {/* Action Buttons */}
            <div className="flex gap-2 pt-3 border-t border-vsc-input-border">
              <button
                onClick={handlePreview}
                disabled={isExporting}
                className="flex-1 px-3 py-2 text-sm bg-vsc-button-secondary-bg hover:bg-vsc-button-secondary-hover-bg text-vsc-button-secondary-fg border border-vsc-input-border rounded transition-colors disabled:opacity-50"
              >
                Preview
              </button>
              <button
                onClick={handleExport}
                disabled={isExporting}
                className="flex-1 px-3 py-2 text-sm bg-vsc-button-bg hover:bg-vsc-button-hover-bg text-vsc-button-fg rounded transition-colors disabled:opacity-50"
              >
                {isExporting ? "Exporting..." : "Export"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Close dropdown when clicking outside */}
      {isOpen && (
        <div
          className="fixed inset-0 z-40"
          onClick={() => {
            setIsOpen(false);
            setShowOptions(false);
          }}
        />
      )}
    </div>
  );
};
