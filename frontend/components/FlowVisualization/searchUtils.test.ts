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
});
