import { FindingKind, KindCounts } from './types';

export const FINDING_KINDS = [
  'vulnerability',
  'secret',
  'misconfiguration',
  'license',
] as const satisfies readonly FindingKind[];

export function emptyKindCounts(): KindCounts {
  return {
    vulnerability: 0,
    secret: 0,
    misconfiguration: 0,
    license: 0,
  };
}
