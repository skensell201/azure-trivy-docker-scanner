import { Severity } from './types';

export const SEVERITY_ORDER: Severity[] = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_ORDER.indexOf(a) - SEVERITY_ORDER.indexOf(b);
}

export function isAtLeast(value: Severity, threshold: Severity): boolean {
  return compareSeverity(value, threshold) >= 0;
}

export function isSeverity(value: string): value is Severity {
  return (SEVERITY_ORDER as string[]).includes(value);
}

export function parseSeverityList(raw: string): Severity[] {
  return raw
    .split(',')
    .map((part) => part.trim().toUpperCase())
    .filter((part) => part.length > 0)
    .map((part) => {
      if (!isSeverity(part)) {
        throw new Error(
          `Unknown severity "${part}". Allowed values: ${SEVERITY_ORDER.join(', ')}.`,
        );
      }
      return part;
    });
}

export function emptySeverityCounts(): Record<Severity, number> {
  return { UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
}
