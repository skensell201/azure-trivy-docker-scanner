/**
 * Theme detection for the hub. Azure DevOps hosts two themes (light and dark) and renders this
 * hub inside an iframe in whichever one the signed-in user picked; getting this wrong means a
 * dark panel sitting inside a white page, or vice versa.
 *
 * This module deliberately never builds anything on the *host's* CSS variable names: their set
 * differs between the cloud service and an on-premises server, and a missing one would silently
 * degrade our entire palette to unstyled browser defaults (see hub.css's own tokens for the
 * palette itself, which is plain hardcoded colour, never `var(--something-the-host-defined)`).
 * The only thing this module borrows from the host is a single rendered colour, purely to decide
 * which of *our own* two token sets to switch on.
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
 * Whether `azure-devops-extension-sdk`'s theme handshake actually ran in this document. Reading
 * `getComputedStyle` alone cannot tell "the host set --text-primary-color to black" apart from
 * "nothing was ever set and the browser's own default body text is black" - both compute to the
 * same value - so this checks for the one thing that is unambiguous: the `<style>` element the
 * SDK's `applyTheme()` injects (confirmed by reading the shipped `SDK.js`; see this module's
 * top-level doc comment and hub.tsx for the corresponding note on the SDK's *typings* not
 * covering this).
 */
function hostThemeWasApplied(): boolean {
  if (typeof document === 'undefined') {
    return false;
  }
  return Array.from(document.getElementsByTagName('style')).some((style) =>
    (style.textContent ?? '').includes('--text-primary-color'),
  );
}

interface HostSignal {
  color: string;
  /**
   * True when `color` is a foreground colour rather than a background: a light theme's body
   * text is dark and a dark theme's is light, so the theme decided from a foreground colour is
   * the mirror image of the one decided from an actual background.
   */
  invert: boolean;
}

/**
 * Reads whatever the host actually painted, if anything. Prefers an actual rendered background
 * should one ever appear (some future SDK version, or a host that goes beyond what
 * `azure-devops-extension-sdk` does today); falls back to the one rule the SDK's `applyTheme()`
 * is confirmed to apply unconditionally today, `body { color: var(--text-primary-color) }`.
 * Returns undefined when neither is actually painted - including, deliberately, every run under
 * jsdom, which does not resolve CSS custom properties at all (`var(...)` always computes to
 * `""`), and every real browser session where the host never sent theme data.
 */
function resolveHostSignal(): HostSignal | undefined {
  if (!hostThemeWasApplied() || typeof document === 'undefined' || !document.body) {
    return undefined;
  }
  const bodyStyle = getComputedStyle(document.body);
  if (hasPaint(bodyStyle.backgroundColor)) {
    return { color: bodyStyle.backgroundColor, invert: false };
  }
  if (hasPaint(bodyStyle.color)) {
    return { color: bodyStyle.color, invert: true };
  }
  return undefined;
}

/**
 * Decides which theme is active: the host's own rendered colour if one was actually painted,
 * else `prefers-color-scheme`, else light - the same three-step fallback described in the plan
 * this module implements.
 */
export function detectTheme(): 'light' | 'dark' {
  const signal = resolveHostSignal();
  if (signal) {
    const decided = themeFromColor(signal.color);
    return signal.invert ? (decided === 'dark' ? 'light' : 'dark') : decided;
  }
  if (typeof window !== 'undefined' && typeof window.matchMedia === 'function') {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  return 'light';
}

/** Decides the theme and stamps it onto `root` (the document root by default) as `data-theme`. */
export function applyDetectedTheme(root: HTMLElement = document.documentElement): 'light' | 'dark' {
  const theme = detectTheme();
  root.setAttribute('data-theme', theme);
  return theme;
}
