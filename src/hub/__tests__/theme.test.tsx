import {
  applyDetectedTheme,
  detectTheme,
  parseColor,
  relativeLuminance,
  themeFromColor,
} from '../theme';

describe('parseColor', () => {
  it('parses a 6-digit hex colour', () => {
    expect(parseColor('#15181d')).toEqual({ r: 0x15, g: 0x18, b: 0x1d });
  });

  it('parses a 3-digit hex colour by doubling each digit', () => {
    expect(parseColor('#fff')).toEqual({ r: 255, g: 255, b: 255 });
    expect(parseColor('#000')).toEqual({ r: 0, g: 0, b: 0 });
  });

  it('parses an rgb(...) colour', () => {
    expect(parseColor('rgb(233, 236, 241)')).toEqual({ r: 233, g: 236, b: 241 });
  });

  it('parses an rgba(...) colour, ignoring alpha', () => {
    expect(parseColor('rgba(21, 24, 29, 1)')).toEqual({ r: 21, g: 24, b: 29 });
  });

  it('is case-insensitive on hex digits', () => {
    expect(parseColor('#E9ECF1')).toEqual({ r: 0xe9, g: 0xec, b: 0xf1 });
  });

  it('returns undefined for a form it does not recognize', () => {
    expect(parseColor('not-a-colour')).toBeUndefined();
    expect(parseColor('hsl(0, 0%, 0%)')).toBeUndefined();
  });
});

describe('relativeLuminance', () => {
  it('is 0 for black', () => {
    expect(relativeLuminance({ r: 0, g: 0, b: 0 })).toBeCloseTo(0, 5);
  });

  it('is 1 for white', () => {
    expect(relativeLuminance({ r: 255, g: 255, b: 255 })).toBeCloseTo(1, 5);
  });
});

describe('themeFromColor', () => {
  it('calls the dark palette background dark', () => {
    expect(themeFromColor('#15181d')).toBe('dark');
  });

  it('calls the light palette background light', () => {
    expect(themeFromColor('#ffffff')).toBe('light');
  });

  it('handles a 3-digit hex form', () => {
    expect(themeFromColor('#fff')).toBe('light');
    expect(themeFromColor('#000')).toBe('dark');
  });

  it('handles an rgb(...) form', () => {
    expect(themeFromColor('rgb(21, 24, 29)')).toBe('dark');
    expect(themeFromColor('rgb(255, 255, 255)')).toBe('light');
  });

  it('defaults to light for a colour it cannot parse, the same safe default as no signal at all', () => {
    expect(themeFromColor('not-a-colour')).toBe('light');
  });
});

describe('detectTheme', () => {
  const originalMatchMedia = window.matchMedia;

  afterEach(() => {
    window.matchMedia = originalMatchMedia;
    document.documentElement.removeAttribute('data-theme');
    document.head.innerHTML = '';
  });

  function mockMatchMedia(matchesDark: boolean): void {
    window.matchMedia = jest.fn().mockImplementation((query: string) => ({
      matches: query.includes('dark') && matchesDark,
      media: query,
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
    })) as unknown as typeof window.matchMedia;
  }

  // jsdom never resolves CSS custom properties (`var(...)` always computes to an empty string),
  // so under jest there is never a real host signal to read - every test here exercises the
  // prefers-color-scheme fallback, which is exactly the path a browser takes too when the host
  // never sent theme data at all.

  it('falls back to prefers-color-scheme: dark when there is no host signal', () => {
    mockMatchMedia(true);
    expect(detectTheme()).toBe('dark');
  });

  it('falls back to prefers-color-scheme: light when there is no host signal', () => {
    mockMatchMedia(false);
    expect(detectTheme()).toBe('light');
  });

  it('falls back to light when matchMedia itself is unavailable', () => {
    // @ts-expect-error - simulating an environment with no matchMedia at all
    delete window.matchMedia;
    expect(detectTheme()).toBe('light');
  });
});

describe('applyDetectedTheme', () => {
  const originalMatchMedia = window.matchMedia;

  afterEach(() => {
    window.matchMedia = originalMatchMedia;
    document.documentElement.removeAttribute('data-theme');
  });

  it('stamps data-theme on the given root once a theme is decided', () => {
    window.matchMedia = jest.fn().mockImplementation((query: string) => ({
      matches: query.includes('dark'),
      media: query,
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
    })) as unknown as typeof window.matchMedia;

    const root = document.createElement('html');
    const result = applyDetectedTheme(root);

    expect(result).toBe('dark');
    expect(root.getAttribute('data-theme')).toBe('dark');
  });

  it('defaults to the document root when none is passed', () => {
    window.matchMedia = jest.fn().mockImplementation(() => ({
      matches: false,
      media: '',
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
    })) as unknown as typeof window.matchMedia;

    applyDetectedTheme();

    expect(document.documentElement.getAttribute('data-theme')).toBe('light');
  });
});
