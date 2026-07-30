/**
 * Picks which OS trust bundle to load when the agent has no CA of its own configured (see
 * `buildFetch` in `index.ts`). Deliberately just the decision, not the filesystem access: it takes
 * an existence predicate rather than calling `fs.existsSync` itself, so the choice among several
 * candidate paths can be unit-tested without touching a real filesystem, and so this module has no
 * side effects at import time (unlike `index.ts`, which calls `void main()` at module load and so
 * cannot be imported by a test at all).
 *
 * Returns the first candidate, in priority order, for which `exists` is true - or `undefined` if
 * none are. Actually reading the chosen path (and falling back if it exists but cannot be read) is
 * the caller's job, not this function's: that is an I/O concern, not a selection concern.
 */
export function selectOsCaBundlePath(
  candidates: readonly string[],
  exists: (candidatePath: string) => boolean,
): string | undefined {
  return candidates.find(exists);
}
