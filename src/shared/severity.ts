import { Severity, SeverityCounts } from './types';

export const SEVERITY_ORDER = [
  'UNKNOWN',
  'LOW',
  'MEDIUM',
  'HIGH',
  'CRITICAL',
] as const satisfies readonly Severity[];

export function isSeverity(value: string): value is Severity {
  return (SEVERITY_ORDER as readonly string[]).includes(value);
}

export function severityRank(value: Severity): number {
  const index = SEVERITY_ORDER.indexOf(value);
  if (index === -1) {
    throw new Error(
      `Unknown severity "${value}". Allowed values: ${SEVERITY_ORDER.join(', ')}.`,
    );
  }
  return index;
}

export function compareSeverity(a: Severity, b: Severity): number {
  return severityRank(a) - severityRank(b);
}

export function isAtLeast(value: Severity, threshold: Severity): boolean {
  return compareSeverity(value, threshold) >= 0;
}

export function parseSeverity(raw: string): Severity {
  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    throw new Error(
      `Severity value is empty. Allowed values: ${SEVERITY_ORDER.join(', ')}.`,
    );
  }
  const upper = trimmed.toUpperCase();
  if (!isSeverity(upper)) {
    throw new Error(
      `Unknown severity "${upper}". Allowed values: ${SEVERITY_ORDER.join(', ')}.`,
    );
  }
  return upper;
}

export function parseSeverityList(raw: string): Severity[] {
  const parts = raw
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part.length > 0);

  if (parts.length === 0) {
    throw new Error(`No severities found in "${raw}".`);
  }

  return parts.map((part) => parseSeverity(part));
}

export function emptySeverityCounts(): SeverityCounts {
  return { UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
}
