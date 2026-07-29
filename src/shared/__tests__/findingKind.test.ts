import { emptyKindCounts } from '../findingKind';

describe('findingKind', () => {
  it('returns every kind zeroed', () => {
    expect(emptyKindCounts()).toEqual({
      vulnerability: 0,
      secret: 0,
      misconfiguration: 0,
      license: 0,
    });
  });

  it('returns a fresh object on each call', () => {
    const first = emptyKindCounts();
    first.vulnerability = 5;
    const second = emptyKindCounts();
    expect(second.vulnerability).toBe(0);
  });
});
