'use client';

import { useState, useEffect } from 'react';
import { AlertTriangle } from 'lucide-react';
import { ProtocolPolicy } from '@/types/protocol';
import { protocolPolicies } from '@/lib/api';

interface ProtocolPolicySelectorProps {
  projectId: string;
  currentPolicyId: string;
  onPolicyChange: (policyId: string) => void;
}

export const ProtocolPolicySelector: React.FC<ProtocolPolicySelectorProps> = ({
  projectId,
  currentPolicyId,
  onPolicyChange
}) => {
  const [policies, setPolicies] = useState<ProtocolPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchPolicies();
  }, []);

  const fetchPolicies = async () => {
    try {
      const data = await protocolPolicies.list();
      setPolicies(data);
      setLoading(false);
    } catch (err) {
      setError('Failed to load policies');
      setLoading(false);
    }
  };

  const handleChange = async (policyId: string) => {
    try {
      await protocolPolicies.updateProjectProtocol(projectId, policyId);
      onPolicyChange(policyId);
    } catch (err) {
      setError('Failed to update protocol');
    }
  };

  if (loading) {
    return <div className="text-vsc-text-muted text-sm">Loading policies...</div>;
  }

  if (error) {
    return <div className="text-vsc-error text-sm">{error}</div>;
  }

  const currentPolicy = policies.find(p => p.id === currentPolicyId);

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <label className="text-sm font-medium text-vsc-text">Submission Protocol</label>
        <span
          className="text-xs text-vsc-text-muted cursor-help"
          title="Protocol defines quality gates for submission"
        >
          ℹ️
        </span>
      </div>

      <select
        value={currentPolicyId}
        onChange={(e) => handleChange(e.target.value)}
        className="input w-full"
      >
        {policies.map(policy => (
          <option key={policy.id} value={policy.id}>
            {policy.display_name}
          </option>
        ))}
      </select>

      {currentPolicy && (
        <div className="text-xs text-vsc-text-muted space-y-1">
          <div className="flex gap-2 flex-wrap">
            <span className="px-2 py-1 bg-vsc-sidebar rounded text-vsc-text">
              Threat Model: {currentPolicy.default_threat_model_preset}
            </span>
            <span className="px-2 py-1 bg-vsc-sidebar rounded text-vsc-text">
              Min: {currentPolicy.min_disposition_to_submit.join(', ')}
            </span>
          </div>
          <p className="text-vsc-text-muted text-xs">
            {currentPolicy.require_cross_boundary_for_local_bugs && '✓ Requires automation boundary • '}
            {currentPolicy.enable_evidence_quests && '✓ Evidence quests enabled'}
          </p>
        </div>
      )}

      <div className="text-xs text-amber-600 bg-amber-900/20 p-2 rounded border border-amber-800/30 flex items-start gap-2">
        <AlertTriangle className="w-3 h-3 flex-shrink-0 mt-0.5" />
        <span>Changing protocol affects future scans only</span>
      </div>
    </div>
  );
};
