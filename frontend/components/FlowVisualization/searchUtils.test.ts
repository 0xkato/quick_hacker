import { parseSearchQuery, matchesQuery } from './searchUtils';

describe('parseSearchQuery', () => {
  it('should parse type filter', () => {
    const query = parseSearchQuery('type:file');
    expect(query.types).toEqual(['file']);
  });

  it('should parse function pattern with wildcard', () => {
    const query = parseSearchQuery('function:handle*');
    expect(query.functionPattern).toBe('handle.*');
  });

  it('should parse label pattern', () => {
    const query = parseSearchQuery('api.py');
    expect(query.labelPattern).toBe('api.py');
  });

  it('should parse combined filters', () => {
    const query = parseSearchQuery('type:file routes');
    expect(query.types).toEqual(['file']);
    expect(query.labelPattern).toBe('routes');
  });
});

describe('matchesQuery', () => {
  it('should match by type', () => {
    const node = { type: 'file', label: 'test.py' };
    const query = { types: ['file'], caseSensitive: false };
    expect(matchesQuery(node, query)).toBe(true);
  });

  it('should not match wrong type', () => {
    const node = { type: 'function', label: 'test' };
    const query = { types: ['file'], caseSensitive: false };
    expect(matchesQuery(node, query)).toBe(false);
  });

  it('should match by label pattern (case-insensitive)', () => {
    const node = { type: 'file', label: 'api_routes.py' };
    const query = { types: [], labelPattern: 'routes', caseSensitive: false };
    expect(matchesQuery(node, query)).toBe(true);
  });

  it('should not match wrong label pattern', () => {
    const node = { type: 'file', label: 'test.py' };
    const query = { types: [], labelPattern: 'routes', caseSensitive: false };
    expect(matchesQuery(node, query)).toBe(false);
  });

  it('should match function by pattern with wildcard', () => {
    const node = { type: 'function', label: 'handleRequest', data: { function_name: 'handleRequest' } };
    const query = { types: [], functionPattern: 'handle.*', caseSensitive: false };
    expect(matchesQuery(node, query)).toBe(true);
  });

  it('should not match function wrong pattern', () => {
    const node = { type: 'function', label: 'processData', data: { function_name: 'processData' } };
    const query = { types: [], functionPattern: 'handle.*', caseSensitive: false };
    expect(matchesQuery(node, query)).toBe(false);
  });

  it('should return true for empty query', () => {
    const node = { type: 'file', label: 'test.py' };
    const query = { types: [], caseSensitive: false };
    expect(matchesQuery(node, query)).toBe(true);
  });

  it('should use AND logic for multiple filters', () => {
    const node = { type: 'file', label: 'api_routes.py' };
    const queryMatch = { types: ['file'], labelPattern: 'routes', caseSensitive: false };
    const queryNoMatch = { types: ['function'], labelPattern: 'routes', caseSensitive: false };

    expect(matchesQuery(node, queryMatch)).toBe(true);
    expect(matchesQuery(node, queryNoMatch)).toBe(false);
  });
});
