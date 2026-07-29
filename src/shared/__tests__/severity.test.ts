import { compareSeverity, isAtLeast, parseSeverityList, emptySeverityCounts } from '../severity';

describe('severity', () => {
  it('orders severities from UNKNOWN to CRITICAL', () => {
    expect(compareSeverity('CRITICAL', 'HIGH')).toBeGreaterThan(0);
    expect(compareSeverity('LOW', 'MEDIUM')).toBeLessThan(0);
    expect(compareSeverity('HIGH', 'HIGH')).toBe(0);
  });

  it('treats a severity as meeting a threshold when equal or higher', () => {
    expect(isAtLeast('CRITICAL', 'HIGH')).toBe(true);
    expect(isAtLeast('HIGH', 'HIGH')).toBe(true);
    expect(isAtLeast('MEDIUM', 'HIGH')).toBe(false);
  });

  it('parses a comma separated list case-insensitively and trims blanks', () => {
    expect(parseSeverityList(' critical , HIGH ')).toEqual(['CRITICAL', 'HIGH']);
  });

  it('rejects an unknown severity naming the offending value', () => {
    expect(() => parseSeverityList('CRITICAL,BOGUS')).toThrow(/BOGUS/);
  });

  it('returns zeroed counts for every severity', () => {
    expect(emptySeverityCounts()).toEqual({
      UNKNOWN: 0,
      LOW: 0,
      MEDIUM: 0,
      HIGH: 0,
      CRITICAL: 0,
    });
  });
});
