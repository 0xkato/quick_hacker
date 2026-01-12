export interface SearchQuery {
  types: string[];           // Node types to show
  labelPattern?: string;     // Text to match in labels
  functionPattern?: string;  // Function name pattern (regex)
  caseSensitive: boolean;
}

export function parseSearchQuery(query: string): SearchQuery {
  if (!query.trim()) {
    return {
      types: [],
      caseSensitive: false
    };
  }

  const parts = query.trim().split(/\s+/);
  const types: string[] = [];
  let labelPattern = '';
  let functionPattern = '';

  parts.forEach(part => {
    if (part.startsWith('type:')) {
      types.push(part.substring(5));
    } else if (part.startsWith('function:')) {
      // Convert wildcard to regex
      functionPattern = part.substring(9).replace(/\*/g, '.*');
    } else if (part !== 'OR' && part !== 'AND') {
      labelPattern = part;
    }
  });

  return {
    types,
    labelPattern: labelPattern || undefined,
    functionPattern: functionPattern || undefined,
    caseSensitive: false
  };
}

export function matchesQuery(
  node: any,
  query: SearchQuery
): boolean {
  if (!query.types.length && !query.labelPattern && !query.functionPattern) {
    return true; // Empty query matches all
  }

  let matches = true;

  // Type filter
  if (query.types.length > 0) {
    matches = matches && query.types.includes(node.type);
  }

  // Label pattern
  if (query.labelPattern) {
    const labelLower = (node.label || '').toLowerCase();
    const patternLower = query.labelPattern.toLowerCase();
    matches = matches && labelLower.includes(patternLower);
  }

  // Function name pattern
  if (query.functionPattern && node.type === 'function') {
    const regex = new RegExp(query.functionPattern, 'i');
    const functionName = node.data?.function_name || node.label;
    matches = matches && regex.test(functionName);
  }

  return matches;
}
