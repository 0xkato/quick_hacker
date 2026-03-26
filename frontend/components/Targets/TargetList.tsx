'use client';
import type { Target } from '@/types';

interface TargetListProps {
  targets: Target[];
  isLoading?: boolean;
}

const kindIcon = (kind: string) => {
  switch (kind) {
    case 'api_route': return '\u{1F310}';
    case 'parser': return '\u{1F4C4}';
    case 'workflow': return '\u{1F504}';
    case 'browser': return '\u{1F5A5}\u{FE0F}';
    default: return '\u{26A1}';
  }
};

const engineForTarget = (t: Target) => {
  const kind = t.kind;
  const lang = (t.language || '').toLowerCase();
  if (kind === 'api_route') return 'Schemathesis';
  if (kind === 'native_function') {
    if (lang === 'python') return 'Atheris';
    if (['c', 'cpp', 'c++'].includes(lang)) return 'AFL++';
    if (lang === 'java') return 'Jazzer';
    if (lang === 'go') return 'Go Fuzz';
    if (lang === 'rust') return 'Cargo Fuzz';
    if (lang === 'solidity') return 'Echidna';
    return 'Radamsa';
  }
  if (kind === 'parser') return 'Grammarinator';
  if (kind === 'workflow') return 'RESTler';
  if (kind === 'message_consumer') return 'Boofuzz';
  return 'Auto';
};

export function TargetList({ targets, isLoading }: TargetListProps) {
  if (isLoading) {
    return <div className="p-4 text-xs text-[var(--text-muted)] text-center animate-pulse">Loading...</div>;
  }

  if (targets.length === 0) {
    return <div className="p-4 text-xs text-[var(--text-muted)] text-center">No targets discovered yet. Start a campaign to extract targets.</div>;
  }

  return (
    <div className="flex flex-col h-full overflow-y-auto">
      <div className="p-2 border-b border-[var(--border-primary)]">
        <span className="text-xs text-[var(--text-muted)]">{targets.length} targets</span>
      </div>
      {targets.map(t => (
        <div key={t.id} className="p-3 border-b border-[var(--border-primary)] hover:bg-[var(--bg-secondary)]">
          <div className="flex items-center gap-2 mb-1">
            <span>{kindIcon(t.kind)}</span>
            <span className="text-xs font-medium text-[var(--text-primary)]">{t.entrypoint}</span>
          </div>
          <div className="flex items-center gap-2 text-[10px] text-[var(--text-muted)]">
            <span>{t.kind}</span>
            {t.language && <span>&middot; {t.language}</span>}
            {t.stateful && <span className="text-yellow-400">&middot; stateful</span>}
            {t.priority_score != null && <span>&middot; priority: {t.priority_score.toFixed(2)}</span>}
            <span className="text-[10px] px-1 py-0.5 rounded bg-[var(--bg-tertiary)] text-cyan-400">{engineForTarget(t)}</span>
          </div>
          {t.actors && t.actors.length > 0 && (
            <div className="text-[10px] text-[var(--text-muted)]">actors: {t.actors.join(', ')}</div>
          )}
          {t.reset_strategy && (
            <div className="text-[10px] text-[var(--text-muted)]">reset: {t.reset_strategy}</div>
          )}
        </div>
      ))}
    </div>
  );
}
