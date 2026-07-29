import { FindingKind, KindCounts } from './types';

export const FINDING_KINDS: readonly FindingKind[] = [
  'vulnerability',
  'secret',
  'misconfiguration',
  'license',
];

export function emptyKindCounts(): KindCounts {
  return {
    vulnerability: 0,
    secret: 0,
    misconfiguration: 0,
    license: 0,
  };
}
