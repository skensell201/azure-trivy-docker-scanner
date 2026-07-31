/**
 * Theme detection for the hub. Azure DevOps hosts two themes (light and dark) and renders this
 * hub inside an iframe in whichever one the signed-in user picked; getting this wrong means a
 * dark panel sitting inside a white page, or vice versa.
 *
 * hub.css's palette stays plain hardcoded colour under our own `--hub-*` names, never
 * `var(--something-the-host-defined)`: the host's variable set differs between the cloud service
 * and an on-premises server, and referencing a missing one would silently degrade the whole page
 * to unstyled browser defaults. The host's variables are read *here*, and only here, purely to
 * decide which of our own two token sets to switch on.
 *
 * Reading them is a direct question with an unambiguous answer:
 * `getComputedStyle(root).getPropertyValue('--text-primary-color')` is `""` when nobody set it,
 * and the host's value when someone did - whether the host set it through a stylesheet (which is
 * what `azure-devops-extension-sdk`'s `applyTheme()` does: it injects
 * `:root { --<key>: <value>; ... } body { color: var(--text-primary-color) }` into `<head>`) or
 * inline on the root element. That is unlike an ordinary property such as `color`, where "the
 * host set black" and "nobody set anything and black is the browser default" compute identically;
 * v0.6.0 worked around that by sniffing `<head>` for a `<style>` mentioning
 * `--text-primary-color` and then reading `getComputedStyle(body)` - which read back the hub's own
 * `body { background: var(--hub-bg) }` and concluded, from its own light default, that the host
 * was light. A custom property has no such ambiguity and needs no sniffing.
 */

export interface RGB {
  r: number;
  g: number;
  b: number;
}

const HEX6 = /^#([0-9a-f]{6})$/i;
const HEX3 = /^#([0-9a-f]{3})$/i;
// Matches both rgb(r, g, b) and rgba(r, g, b, a); the alpha group, if present, is ignored here -
// hasPaint (below) is what cares about transparency.
const RGB_FUNC = /^rgba?\(\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)\s*(?:,\s*[\d.]+\s*)?\)$/i;

/**
 * Parses a colour string into 0-255 RGB components. Handles the three forms a CSS engine might
 * hand back or that a host might inject: `#rgb`, `#rrggbb` and `rgb(...)`/`rgba(...)` - which one
 * a given host (or browser's `getComputedStyle`) uses is not ours to choose. Returns undefined
 * for anything else (e.g. a named colour, `hsl(...)`) rather than guessing.
 */
export function parseColor(color: string): RGB | undefined {
  const trimmed = color.trim();

  const hex6 = HEX6.exec(trimmed);
  if (hex6) {
    const value = hex6[1];
    return {
      r: parseInt(value.slice(0, 2), 16),
      g: parseInt(value.slice(2, 4), 16),
      b: parseInt(value.slice(4, 6), 16),
    };
  }

  const hex3 = HEX3.exec(trimmed);
  if (hex3) {
    const [r, g, b] = hex3[1].split('');
    return { r: parseInt(r + r, 16), g: parseInt(g + g, 16), b: parseInt(b + b, 16) };
  }

  const rgbFunc = RGB_FUNC.exec(trimmed);
  if (rgbFunc) {
    return { r: Number(rgbFunc[1]), g: Number(rgbFunc[2]), b: Number(rgbFunc[3]) };
  }

  return undefined;
}

function linearize(channel: number): number {
  const normalized = channel / 255;
  return normalized <= 0.03928 ? normalized / 12.92 : Math.pow((normalized + 0.055) / 1.055, 2.4);
}

/** WCAG relative luminance, 0 (black) to 1 (white). */
export function relativeLuminance({ r, g, b }: RGB): number {
  return 0.2126 * linearize(r) + 0.7152 * linearize(g) + 0.0722 * linearize(b);
}

/**
 * Pure decision: given a rendered colour, which of our two themes is it? Exported on its own,
 * separate from anything that touches `document`, so the decision itself can be unit tested
 * without a browser. A colour this cannot parse gets the same safe default as no signal at all -
 * see `detectTheme`'s final fallback.
 */
export function themeFromColor(color: string): 'light' | 'dark' {
  const parsed = parseColor(color);
  if (!parsed) {
    return 'light';
  }
  // The palette's own bg/fg pairs sit nowhere near 0.5 (dark backgrounds land under 0.03, light
  // ones at 1.0), so the exact placement of the threshold does not matter for what this hub
  // actually renders; 0.5 just needs to separate "clearly dark" from "clearly light".
  return relativeLuminance(parsed) < 0.5 ? 'dark' : 'light';
}

/**
 * True when `value` is an actually-painted colour rather than the initial/unset state
 * (`""`, `"transparent"`, or `rgba(..., 0)`). Only the explicit 4-argument `rgba(...)` form is
 * checked for a zero alpha: a 3-argument `rgb(...)` has no alpha channel to be zero, so it is
 * always paint.
 */
function hasPaint(value: string | undefined | null): value is string {
  if (!value) {
    return false;
  }
  const trimmed = value.trim();
  if (trimmed === '' || trimmed === 'transparent') {
    return false;
  }
  const rgba = /^rgba\(\s*[\d.]+\s*,\s*[\d.]+\s*,\s*[\d.]+\s*,\s*([\d.]+)\s*\)$/i.exec(trimmed);
  if (rgba && Number(rgba[1]) === 0) {
    return false;
  }
  return true;
}

/**
 * Reads one CSS custom property, returning `""` when it is not set. The whole host-facing surface
 * of this module is this one function type, so the decision below stays a pure function that can
 * be tested without a browser - which matters because jsdom computes no custom properties at all
 * and would otherwise leave the entire host branch untestable.
 */
export type HostVariableReader = (name: string) => string;

/**
 * The host's page background. Opportunistic: it is a real Azure DevOps theme key, but nothing in
 * the SDK guarantees any particular key is present, so this is tried first and simply skipped
 * when the host did not send it.
 */
export const HOST_BACKGROUND_VARIABLE = '--background-color';

/**
 * The host's primary text colour - the one key `azure-devops-extension-sdk` itself depends on
 * (its injected rule is literally `body { color: var(--text-primary-color) }`), so if the host
 * sent theme data at all, this is the key most likely to be in it.
 */
export const HOST_FOREGROUND_VARIABLE = '--text-primary-color';

/**
 * The real reader: the document root's computed custom properties. This sees the value whether
 * the host declared it in a stylesheet (`:root { --text-primary-color: ... }`, which is what the
 * SDK injects) or set it inline on `<html>`, and returns `""` when nothing set it.
 */
export function readHostVariable(name: string): string {
  if (typeof document === 'undefined' || !document.documentElement) {
    return '';
  }
  if (typeof getComputedStyle !== 'function') {
    return '';
  }
  return getComputedStyle(document.documentElement).getPropertyValue(name);
}

/**
 * `themeFromColor` with the two things a *host* colour needs on top of it.
 *
 * `invert` is for a foreground: a light theme's text is dark and a dark theme's is light, so the
 * theme read off a foreground is the mirror image of the one read off a background.
 *
 * The unparseable case is checked before inverting, on purpose. `themeFromColor` answers light
 * for a colour it cannot parse - the same safe default as no signal at all - and inverting that
 * would turn "no idea" into a confident dark.
 */
function themeFromHostColor(color: string, invert: boolean): 'light' | 'dark' {
  if (!parseColor(color)) {
    return 'light';
  }
  const decided = themeFromColor(color);
  if (!invert) {
    return decided;
  }
  return decided === 'dark' ? 'light' : 'dark';
}

/**
 * The host's answer, if it gave one: its background variable when set, else its foreground
 * variable read inverted, else undefined for "the host said nothing" - which is every session
 * where the host sent no theme data, and every run under jsdom with the real reader.
 */
export function themeFromHostVariables(read: HostVariableReader): 'light' | 'dark' | undefined {
  const background = read(HOST_BACKGROUND_VARIABLE);
  if (hasPaint(background)) {
    return themeFromHostColor(background, false);
  }
  const foreground = read(HOST_FOREGROUND_VARIABLE);
  if (hasPaint(foreground)) {
    return themeFromHostColor(foreground, true);
  }
  return undefined;
}

/**
 * Decides which theme is active: the host's own variables if it set any, else
 * `prefers-color-scheme`, else light.
 */
export function detectTheme(read: HostVariableReader = readHostVariable): 'light' | 'dark' {
  const fromHost = themeFromHostVariables(read);
  if (fromHost) {
    return fromHost;
  }
  if (typeof window !== 'undefined' && typeof window.matchMedia === 'function') {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  return 'light';
}

/** Decides the theme and stamps it onto `root` (the document root by default) as `data-theme`. */
export function applyDetectedTheme(
  root: HTMLElement = document.documentElement,
  read: HostVariableReader = readHostVariable,
): 'light' | 'dark' {
  const theme = detectTheme(read);
  root.setAttribute('data-theme', theme);
  return theme;
}
