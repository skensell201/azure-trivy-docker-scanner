import {
  compareSeverity,
  isAtLeast,
  isSeverity,
  parseSeverity,
  parseSeverityList,
  severityRank,
  emptySeverityCounts,
} from '../severity';
import { Severity } from '../types';

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

  it('returns freshly zeroed counts on every call', () => {
    const first = emptySeverityCounts();
    first.HIGH = 7;
    const second = emptySeverityCounts();
    expect(second).toEqual({
      UNKNOWN: 0,
      LOW: 0,
      MEDIUM: 0,
      HIGH: 0,
      CRITICAL: 0,
    });
  });

  it('is case-sensitive by design, leaving uppercasing to callers', () => {
    expect(isSeverity('high')).toBe(false);
    expect(isSeverity('HIGH')).toBe(true);
  });

  describe('severityRank', () => {
    it('throws on a value outside the severity vocabulary', () => {
      expect(() => severityRank('critical' as Severity)).toThrow(/critical/);
    });
  });

  describe('compareSeverity vocabulary enforcement', () => {
    it('throws on an unknown left-hand value instead of silently ranking it', () => {
      expect(() => compareSeverity('critical' as Severity, 'HIGH')).toThrow(/critical/);
    });
  });

  describe('isAtLeast vocabulary enforcement', () => {
    it('throws when the threshold is unknown instead of comparing against -1', () => {
      expect(() => isAtLeast('HIGH', 'critical' as Severity)).toThrow(/critical/);
    });
  });

  describe('parseSeverity', () => {
    it('trims and uppercases a single value', () => {
      expect(parseSeverity(' high ')).toBe('HIGH');
    });

    it('throws on an empty string', () => {
      expect(() => parseSeverity('')).toThrow();
    });

    it('throws on an unknown value, naming it', () => {
      expect(() => parseSeverity('bogus')).toThrow(/BOGUS/);
    });
  });

  describe('parseSeverityList empty-result rejection', () => {
    it('throws on an empty string instead of returning []', () => {
      expect(() => parseSeverityList('')).toThrow();
    });

    it('throws on a list of only separators/blanks instead of returning []', () => {
      expect(() => parseSeverityList(' ,, ')).toThrow();
    });
  });
});
