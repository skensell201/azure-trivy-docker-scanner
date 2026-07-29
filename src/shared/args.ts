/**
 * Splits an administrator- or pipeline-supplied argument string into argv
 * entries for `child_process.spawn`. Whitespace separates arguments;
 * single- or double-quoted segments are kept together with the quotes
 * stripped. Splitting is on Unicode whitespace (`\s`) deliberately, so a
 * copy-pasted non-breaking space acts as a separator instead of silently
 * becoming part of a token. There is no shell involved, so this does not
 * handle shell escaping, variable expansion, or backslash escapes.
 */
export function splitArgs(raw: string | undefined): string[] {
  if (!raw) {
    return [];
  }

  const result: string[] = [];
  let current = '';
  let quote: '"' | "'" | null = null;
  let quoteStart = -1;
  // Whether the current token has been "opened" - i.e. there is an argument
  // to emit even if `current` is empty. This is not the same as truthy
  // `current`: an explicit empty quoted argument (`""`) opens a token with
  // no characters in it, and must still be pushed to the result instead of
  // silently dropped.
  let hasContent = false;

  let index = 0;
  for (const char of raw) {
    // Capture this code point's position before advancing, so `continue`
    // below never skips the bookkeeping for the next iteration.
    const charIndex = index;
    index += char.length;

    if (quote) {
      if (char === quote) {
        quote = null;
      } else {
        current += char;
      }
      continue;
    }

    if (char === '"' || char === "'") {
      quote = char;
      quoteStart = charIndex;
      hasContent = true;
      continue;
    }

    if (/\s/.test(char)) {
      if (hasContent) {
        result.push(current);
        current = '';
        hasContent = false;
      }
      continue;
    }

    current += char;
    hasContent = true;
  }

  if (quote) {
    throw new Error(`Unterminated quote in arguments at position ${quoteStart}.`);
  }
  if (hasContent) {
    result.push(current);
  }
  return result;
}
