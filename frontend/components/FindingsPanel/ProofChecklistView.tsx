'use client';

import { CheckCircle2, XCircle, HelpCircle } from 'lucide-react';
import type { ProofChecklist, ChecklistItem, ChecklistStatus } from '@/types';

interface ProofChecklistViewProps {
  checklist: ProofChecklist;
  className?: string;
}

const STATUS_ICONS: Record<ChecklistStatus, React.ReactNode> = {
  PROVEN: <CheckCircle2 className="w-4 h-4 text-green-500" />,
  DISPROVEN: <XCircle className="w-4 h-4 text-red-500" />,
  UNKNOWN: <HelpCircle className="w-4 h-4 text-gray-400" />,
};

const STATUS_LABELS: Record<ChecklistStatus, string> = {
  PROVEN: 'Proven',
  DISPROVEN: 'Disproven',
  UNKNOWN: 'Unknown',
};

const STATUS_COLORS: Record<ChecklistStatus, string> = {
  PROVEN: 'text-green-500',
  DISPROVEN: 'text-red-500',
  UNKNOWN: 'text-gray-400',
};

const CHECKLIST_FIELD_LABELS: Record<string, { label: string; description: string }> = {
  source_controlled_input: {
    label: 'Source Controlled Input',
    description: 'User/attacker controls the input',
  },
  sink_present: {
    label: 'Sink Present',
    description: 'Dangerous operation identified',
  },
  dataflow_evidenced: {
    label: 'Data Flow Evidenced',
    description: 'Input flows to sink without sanitization',
  },
  reachable: {
    label: 'Reachable',
    description: 'Code path can actually execute',
  },
  boundary_crossed: {
    label: 'Boundary Crossed',
    description: 'External input reaches internal system',
  },
  not_only_misconfig: {
    label: 'Not Only Misconfiguration',
    description: 'Vulnerability in code, not just config',
  },
  security_control_bypassed: {
    label: 'Security Control Bypassed',
    description: 'Security controls are absent or bypassable',
  },
};

function ChecklistItemRow({ field, item }: { field: string; item: ChecklistItem }) {
  const fieldInfo = CHECKLIST_FIELD_LABELS[field] || { label: field, description: '' };

  return (
    <div className="flex items-start gap-3 py-2 border-b border-vsc-border last:border-0">
      {/* Status icon */}
      <div className="mt-0.5 flex-shrink-0">
        {STATUS_ICONS[item.status]}
      </div>

      {/* Label and status */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-1">
          <span className="font-medium text-vsc-text">{fieldInfo.label}</span>
          <span className={`text-xs font-medium ${STATUS_COLORS[item.status]}`}>
            {STATUS_LABELS[item.status]}
          </span>
        </div>

        {/* Description */}
        {fieldInfo.description && (
          <p className="text-xs text-vsc-text-muted mb-1">{fieldInfo.description}</p>
        )}

        {/* Reason */}
        {item.reason && (
          <p className="text-xs text-vsc-text-secondary italic">
            {item.reason}
          </p>
        )}
      </div>
    </div>
  );
}

export default function ProofChecklistView({ checklist, className = '' }: ProofChecklistViewProps) {
  // Collect all checklist fields (including optional security_control_bypassed)
  const fields = [
    'source_controlled_input',
    'sink_present',
    'dataflow_evidenced',
    'reachable',
    'boundary_crossed',
    'not_only_misconfig',
  ];

  if (checklist.security_control_bypassed) {
    fields.push('security_control_bypassed');
  }

  // Calculate proven count
  const provenCount = fields.filter(
    f => checklist[f as keyof ProofChecklist]?.status === 'PROVEN'
  ).length;

  return (
    <div className={`soft-card ${className}`}>
      <div className="flex items-center gap-2 mb-3">
        <h4 className="font-semibold text-vsc-text">Proof Checklist</h4>
        <span className="text-xs text-vsc-text-muted">
          ({provenCount}/{fields.length} proven)
        </span>
      </div>

      <div className="space-y-0">
        {fields.map((field) => {
          const item = checklist[field as keyof ProofChecklist];
          if (!item) return null;
          return <ChecklistItemRow key={field} field={field} item={item} />;
        })}
      </div>
    </div>
  );
}
