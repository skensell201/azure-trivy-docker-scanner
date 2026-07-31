import {
  applyDetectedTheme,
  detectTheme,
  HOST_BACKGROUND_VARIABLE,
  HOST_FOREGROUND_VARIABLE,
  parseColor,
  relativeLuminance,
  themeFromColor,
  themeFromHostVariables,
} from '../theme';

/**
 * A stand-in for `getComputedStyle(root).getPropertyValue`. The real reader returns `""` for a
 * custom property nobody set, which is exactly what an absent key here produces.
 */
function hostVariables(variables: Record<string, string>): (name: string) => string {
  return (name) => variables[name] ?? '';
}

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

describe('themeFromHostVariables', () => {
  it('prefers the host background variable when it is set', () => {
    expect(
      themeFromHostVariables(hostVariables({ [HOST_BACKGROUND_VARIABLE]: '#1f1f1f' })),
    ).toBe('dark');
    expect(
      themeFromHostVariables(hostVariables({ [HOST_BACKGROUND_VARIABLE]: '#ffffff' })),
    ).toBe('light');
  });

  it('reads the background rather than the foreground when both are set', () => {
    // A dark host sets both; taking the foreground here would invert the right answer.
    expect(
      themeFromHostVariables(
        hostVariables({
          [HOST_BACKGROUND_VARIABLE]: 'rgba(31, 31, 31, 1)',
          [HOST_FOREGROUND_VARIABLE]: 'rgba(255, 255, 255, .9)',
        }),
      ),
    ).toBe('dark');
  });

  it('falls back to the foreground variable, inverted, when no background is set', () => {
    // This is the shape `azure-devops-extension-sdk` guarantees today: whatever else the host's
    // theme data contains, `--text-primary-color` is the one key its own injected rule uses.
    expect(
      themeFromHostVariables(hostVariables({ [HOST_FOREGROUND_VARIABLE]: 'rgba(255, 255, 255, .9)' })),
    ).toBe('dark');
    expect(
      themeFromHostVariables(hostVariables({ [HOST_FOREGROUND_VARIABLE]: '#1f2328' })),
    ).toBe('light');
  });

  it('returns undefined when the host set neither variable', () => {
    expect(themeFromHostVariables(hostVariables({}))).toBeUndefined();
  });

  it('treats an unpainted background as no background and reads the foreground instead', () => {
    for (const unpainted of ['', '   ', 'transparent', 'rgba(0, 0, 0, 0)']) {
      expect(
        themeFromHostVariables(
          hostVariables({
            [HOST_BACKGROUND_VARIABLE]: unpainted,
            [HOST_FOREGROUND_VARIABLE]: 'rgba(255, 255, 255, .9)',
          }),
        ),
      ).toBe('dark');
    }
  });

  it('lands on light for a value it cannot parse, the same safe default as no signal at all', () => {
    expect(
      themeFromHostVariables(hostVariables({ [HOST_BACKGROUND_VARIABLE]: 'hsl(0, 0%, 12%)' })),
    ).toBe('light');
    // The foreground path must reach the same default, not the inverse of it: inverting an
    // unparseable value would turn "we have no idea" into a confident dark.
    expect(
      themeFromHostVariables(hostVariables({ [HOST_FOREGROUND_VARIABLE]: 'hsl(0, 0%, 98%)' })),
    ).toBe('light');
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

  // jsdom computes no custom properties at all, so the default reader always answers `""` here -
  // which is precisely the "host never sent theme data" case, and why the reader is a parameter:
  // the host branch is tested by passing one, not by hoping jsdom grows a cascade.

  it('reads the host variables before anything else', () => {
    // The bug this covers, in full: an on-premises Azure DevOps Server on its dark theme, inside
    // a browser whose OS preference is light. v0.6.0 answered light here and rendered the host's
    // white body text onto its own white card.
    mockMatchMedia(false);
    expect(
      detectTheme(
        hostVariables({
          [HOST_BACKGROUND_VARIABLE]: 'rgba(31, 31, 31, 1)',
          [HOST_FOREGROUND_VARIABLE]: 'rgba(255, 255, 255, .9)',
        }),
      ),
    ).toBe('dark');
  });

  it('reads a host that sets only the foreground variable, which is all the SDK guarantees', () => {
    mockMatchMedia(false);
    expect(
      detectTheme(hostVariables({ [HOST_FOREGROUND_VARIABLE]: 'rgba(255, 255, 255, .9)' })),
    ).toBe('dark');
  });

  it('does not let prefers-color-scheme override a light host', () => {
    mockMatchMedia(true);
    expect(detectTheme(hostVariables({ [HOST_BACKGROUND_VARIABLE]: '#ffffff' }))).toBe('light');
  });

  it('falls back to prefers-color-scheme when the host set no variables', () => {
    mockMatchMedia(true);
    expect(detectTheme(hostVariables({}))).toBe('dark');
    mockMatchMedia(false);
    expect(detectTheme(hostVariables({}))).toBe('light');
  });

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

  it('passes the host variable reader through to detection', () => {
    window.matchMedia = jest.fn().mockImplementation(() => ({
      matches: false,
      media: '',
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
    })) as unknown as typeof window.matchMedia;

    const root = document.createElement('html');
    const read = jest.fn(hostVariables({ [HOST_FOREGROUND_VARIABLE]: 'rgba(255, 255, 255, .9)' }));

    expect(applyDetectedTheme(root, read)).toBe('dark');
    expect(root.getAttribute('data-theme')).toBe('dark');
    expect(read).toHaveBeenCalledWith(HOST_FOREGROUND_VARIABLE);
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
