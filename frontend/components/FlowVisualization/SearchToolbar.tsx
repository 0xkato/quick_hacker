import { useState } from 'react';
import { Search, X, ChevronUp, ChevronDown } from 'lucide-react';

interface SearchToolbarProps {
  onSearch: (query: string) => void;
  resultCount: number;
  currentIndex: number;
  onNavigate: (direction: 'up' | 'down') => void;
}

export function SearchToolbar({
  onSearch,
  resultCount,
  currentIndex,
  onNavigate
}: SearchToolbarProps) {
  const [query, setQuery] = useState('');

  return (
    <div className="flex items-center gap-2 p-2 border-b border-vsc-border bg-vsc-sidebar">
      <Search className="w-4 h-4 text-vsc-text-muted" />
      <input
        type="text"
        value={query}
        onChange={e => {
          setQuery(e.target.value);
          onSearch(e.target.value);
        }}
        placeholder="Search: type:file, function:handle*, api.py"
        className="flex-1 bg-vsc-input border border-vsc-border rounded px-2 py-1 text-sm text-vsc-text placeholder-vsc-text-muted focus:outline-none focus:ring-1 focus:ring-vsc-accent"
      />
      {query && (
        <>
          <button
            onClick={() => {
              setQuery('');
              onSearch('');
            }}
            className="p-1 hover:bg-vsc-hover rounded"
            title="Clear search"
          >
            <X className="w-4 h-4" />
          </button>
          {resultCount > 0 && (
            <>
              <div className="text-sm text-vsc-text-muted whitespace-nowrap">
                {currentIndex + 1}/{resultCount}
              </div>
              <div className="flex gap-1">
                <button
                  onClick={() => onNavigate('up')}
                  className="p-1 hover:bg-vsc-hover rounded"
                  title="Previous match"
                  disabled={resultCount === 0}
                >
                  <ChevronUp className="w-4 h-4" />
                </button>
                <button
                  onClick={() => onNavigate('down')}
                  className="p-1 hover:bg-vsc-hover rounded"
                  title="Next match"
                  disabled={resultCount === 0}
                >
                  <ChevronDown className="w-4 h-4" />
                </button>
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}
