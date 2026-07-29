/**
 * Splits an administrator- or pipeline-supplied argument string into argv
 * entries for `child_process.spawn`. Whitespace separates arguments;
 * single- or double-quoted segments are kept together with the quotes
 * stripped. There is no shell involved, so this does not handle shell
 * escaping, variable expansion, or backslash escapes.
 */
export function splitArgs(raw: string | undefined): string[] {
  if (!raw) {
    return [];
  }

  const result: string[] = [];
  let current = '';
  let quote: '"' | "'" | null = null;
  let hasContent = false;

  for (const char of raw) {
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
    throw new Error(`Unterminated quote in arguments: ${raw}`);
  }
  if (hasContent) {
    result.push(current);
  }
  return result;
}
