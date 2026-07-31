import * as fs from 'fs';
import * as path from 'path';
import * as React from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from '../App';
import { DatabaseConfig, DefaultsConfig, RunnerConfig } from '../../shared/types';

/**
 * The property this file exists to hold: **a rule the host puts on `body` must not be able to
 * change the colour of any text inside the hub.**
 *
 * v0.6.0 broke it. hub.css declared `body { color: var(--hub-fg) }`, and
 * `azure-devops-extension-sdk`'s `applyTheme()` injects a `<style>` into `<head>` at runtime whose
 * last rule is `body { color: var(--text-primary-color) }` - same selector, same specificity,
 * injected later, so the host's rule won. Every element that did not set a `color` of its own
 * (field labels, the detail-pane heading) then inherited the *host's* foreground - white, under
 * the host's dark theme - while our surfaces stayed whatever `data-theme` had decided. White text
 * on a white card.
 *
 * jsdom neither resolves `var(...)` nor propagates inherited properties through `getComputedStyle`
 * (a descendant of a coloured element computes to `""`), so the property cannot be checked by
 * reading computed colours. It is checked instead the way the cascade itself decides an inherited
 * property: walk up from an element until an ancestor is found that a `color` rule actually
 * matches. That ancestor is where the text's colour comes from. It must be inside the hub.
 */

const HUB_CSS = fs.readFileSync(path.join(__dirname, '..', 'hub.css'), 'utf8');

/**
 * What the SDK actually injects, built the way `applyTheme()` builds it (SDK.js, v4.2.0):
 *
 *   themeElement.innerText = ":root { " + cssVariables.join("; ") + " } body { color: var(--text-primary-color) }";
 *
 * where `cssVariables` is one `--<key>: <value>` per key of the host's theme data. The values
 * below are a dark host: light foreground, dark background.
 */
const HOST_THEME_DATA: Record<string, string> = {
  'background-color': 'rgba(31, 31, 31, 1)',
  'text-primary-color': 'rgba(255, 255, 255, .9)',
};

function hostThemeStyleText(themeData: Record<string, string>): string {
  const cssVariables = Object.keys(themeData).map((name) => `--${name}: ${themeData[name]}`);
  return `:root { ${cssVariables.join('; ')} } body { color: var(--text-primary-color) }`;
}

class FakeStore {
  runners: RunnerConfig[] = [
    { alias: 'baseline', image: 'registry.example.com/trivy:0.58.1', isDefault: true, enabled: true },
  ];
  defaults: DefaultsConfig = {};
  databases: DatabaseConfig[] = [];

  loadRunners = jest.fn(async () => this.runners);
  loadDefaults = jest.fn(async () => this.defaults);
  loadDatabases = jest.fn(async () => this.databases);
  saveRunners = jest.fn(async () => undefined);
  saveDefaults = jest.fn(async () => undefined);
  saveDatabases = jest.fn(async () => undefined);
}

interface ColorRule {
  selectorText: string;
  value: string;
}

/**
 * Every rule in the document that declares a `color`, in document order - ours first, the host's
 * last, exactly as they sit in `<head>` at runtime. Grouping rules (`@media`) are descended into:
 * jsdom cannot evaluate a media query, but no rule inside one declares a colour, so including
 * them can only ever make this stricter, never weaker.
 */
function colorRules(): ColorRule[] {
  const found: ColorRule[] = [];
  const visit = (rules: CSSRuleList): void => {
    for (const rule of Array.from(rules)) {
      const grouping = rule as CSSGroupingRule;
      if (grouping.cssRules) {
        visit(grouping.cssRules);
      }
      const styleRule = rule as CSSStyleRule;
      if (!styleRule.selectorText || !styleRule.style) {
        continue;
      }
      const value = styleRule.style.getPropertyValue('color');
      if (value) {
        found.push({ selectorText: styleRule.selectorText, value });
      }
    }
  };
  for (const sheet of Array.from(document.styleSheets)) {
    visit(sheet.cssRules);
  }
  return found;
}

/**
 * Where `element`'s text colour actually comes from: the nearest ancestor-or-self a `color` rule
 * matches, and the value that rule declares. This is how an inherited property resolves - the
 * cascade stops at the first ancestor that has a declaration and never looks further up.
 *
 * Among several rules matching the *same* element the last one wins, which is the cascade's
 * tiebreak at equal specificity - and equal specificity is precisely the situation the bug lived
 * in (`body` versus `body`). No element reached below is matched by two colour rules of differing
 * specificity, so this deliberately does not implement specificity at all.
 */
function colorSourceFor(element: Element): { element: Element; value: string } {
  const rules = colorRules();
  for (let node: Element | null = element; node !== null; node = node.parentElement) {
    const matching = rules.filter((rule) => node !== null && node.matches(rule.selectorText));
    if (matching.length > 0) {
      return { element: node, value: matching[matching.length - 1].value };
    }
  }
  throw new Error(`no color rule matches ${element.tagName} or any of its ancestors`);
}

/**
 * Our own stylesheet among the document's. jsdom's `CSSStyleSheet` exposes no `ownerNode`, so the
 * sheet is identified by something only hub.css contains rather than by the element that carries
 * it - which also means these tests cannot quietly start reading the host's sheet by mistake.
 */
function hubStyleSheet(): CSSStyleSheet {
  const sheet = Array.from(document.styleSheets).find((candidate) =>
    Array.from(candidate.cssRules).some(
      (rule) => (rule as CSSStyleRule).selectorText === ":root[data-theme='dark']",
    ),
  );
  if (!sheet) {
    throw new Error('hub.css is not in the document');
  }
  return sheet;
}

function describeElement(element: Element): string {
  const id = element.id ? `#${element.id}` : '';
  const classes = element.className ? `.${String(element.className).trim().split(/\s+/).join('.')}` : '';
  return `${element.tagName.toLowerCase()}${id}${classes}`;
}

describe('the host cannot recolour the hub through `body`', () => {
  let hubRoot: HTMLElement;

  beforeEach(() => {
    const hubStyle = document.createElement('style');
    hubStyle.id = 'hub-css';
    hubStyle.textContent = HUB_CSS;
    document.head.appendChild(hubStyle);

    // Appended after ours, as it is at runtime: the SDK injects during `SDK.init()`, long after
    // the bundle's own stylesheet is in the document.
    const hostStyle = document.createElement('style');
    hostStyle.id = 'host-theme';
    hostStyle.textContent = hostThemeStyleText(HOST_THEME_DATA);
    document.head.appendChild(hostStyle);

    // The host is on its dark theme, and theme detection agreed - so any unreadable text here is
    // the cascade going wrong on its own, not a mis-detection.
    document.documentElement.setAttribute('data-theme', 'dark');

    hubRoot = document.createElement('div');
    hubRoot.id = 'root';
    document.body.appendChild(hubRoot);
  });

  afterEach(() => {
    document.head.innerHTML = '';
    document.documentElement.removeAttribute('data-theme');
    hubRoot.remove();
  });

  it('owns `body` in this fixture, so the hub really is under the rule that broke it', () => {
    // Guards the rest of this file: if the host's rule ever stopped applying to `body`, every
    // assertion below would pass for the wrong reason.
    expect(colorSourceFor(document.body)).toEqual({
      element: document.body,
      value: 'var(--text-primary-color)',
    });
  });

  it('leaves the hub root itself coloured by our own token', () => {
    const source = colorSourceFor(hubRoot);
    expect(source.element).toBe(hubRoot);
    expect(source.value).toBe('var(--hub-fg)');
  });

  it('colours every rendered element from inside the hub, never from `body`', async () => {
    render(<App store={new FakeStore()} />, { container: hubRoot });
    await screen.findByText('baseline');
    // Open the edit pane: the field labels and the pane heading are exactly the text that went
    // white-on-white, and they only exist once a runner is selected.
    await userEvent.click(screen.getByRole('button', { name: /edit baseline/i }));
    expect(screen.getByText(/edit runner: baseline/i)).toBeTruthy();

    const offenders = Array.from(hubRoot.querySelectorAll('*'))
      .map((element) => ({ element, source: colorSourceFor(element) }))
      .filter(({ source }) => !hubRoot.contains(source.element))
      .map(({ element, source }) => `${describeElement(element)} <- ${describeElement(source.element)}`);

    expect(offenders).toEqual([]);
  });

  it('colours the empty detail pane from inside the hub too', async () => {
    render(<App store={new FakeStore()} />, { container: hubRoot });
    await screen.findByText('baseline');

    const emptyState = screen.getByText('Select a runner from the list, or add a new one.');
    expect(hubRoot.contains(colorSourceFor(emptyState).element)).toBe(true);
  });

  it('never declares a colour on `body` at all', () => {
    // The narrow statement of the same property, straight from the stylesheet: whatever else
    // hub.css does with `body` (it still paints the page background, since the host paints none),
    // the hub's foreground is not `body`'s to carry.
    const bodyColorRules = Array.from(hubStyleSheet().cssRules)
      .filter((rule): rule is CSSStyleRule => Boolean((rule as CSSStyleRule).selectorText))
      .filter((rule) =>
        rule.selectorText
          .split(',')
          .some((selector) => selector.trim() === 'body' || selector.trim() === 'html'),
      )
      .filter((rule) => rule.style.getPropertyValue('color'));

    expect(bodyColorRules.map((rule) => rule.cssText)).toEqual([]);
  });

  it('still paints the page background, which the host never does', () => {
    const bodyBackground = Array.from(hubStyleSheet().cssRules)
      .filter((rule): rule is CSSStyleRule => (rule as CSSStyleRule).selectorText === 'body')
      .map((rule) => rule.style.getPropertyValue('background'))
      .filter(Boolean);

    expect(bodyBackground).toEqual(['var(--hub-bg)']);
  });
});
