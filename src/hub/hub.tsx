import * as SDK from 'azure-devops-extension-sdk';
import { CommonServiceIds, IExtensionDataService } from 'azure-devops-extension-api';
import * as React from 'react';
import * as ReactDOM from 'react-dom';
import { App } from './App';
import { SettingsStore } from './settingsStore';
import { applyDetectedTheme } from './theme';
import './hub.css';

async function start(): Promise<void> {
  try {
    // `IExtensionInitOptions.applyTheme` (azure-devops-extension-sdk/SDK.d.ts) - "Extensions that
    // show UI should specify this to true in order for the current user's theme to be applied to
    // this extension content. Defaults to true." Passed explicitly here even though it is already
    // the default, so the intent is visible at the call site. What it actually does, confirmed by
    // reading the shipped SDK.js rather than the typings (which stop at the option's existence):
    // if the host's handshake includes theme data, the SDK injects every key of that data onto
    // `:root` as a `--key: value` custom property and adds exactly one rule of its own,
    // `body { color: var(--text-primary-color) }` - it does not set a background anywhere. See
    // theme.ts's top-level comment for why this hub never builds its own palette on those
    // variable names, and for how it reads this one guaranteed rule (plus, opportunistically, an
    // actual background if some future SDK version starts setting one) to decide which of its own
    // two token sets to switch on.
    await SDK.init({ loaded: false, applyTheme: true });
    applyDetectedTheme();

    // SDK.d.ts exposes no callback or event for a host theme change - `init`'s only theming lever
    // is the one-shot `applyTheme` option above. Reading SDK.js shows the SDK does re-detect
    // internally: when a theme was applied at init, it listens for a "themeChanged" event the
    // host dispatches on `window` and re-applies the new theme data, and every application -
    // the first one and any later one - ends with `window.dispatchEvent(new
    // CustomEvent('themeApplied', { detail: themeData }))`. That event is real and currently
    // shipping, but it is an implementation detail, not part of the typed/documented contract, so
    // relying on it (as this does) means a future SDK version could silently stop dispatching it
    // with no typings change to flag the break.
    window.addEventListener('themeApplied', () => applyDetectedTheme());

    const dataService = await SDK.getService<IExtensionDataService>(
      CommonServiceIds.ExtensionDataService,
    );
    const manager = await dataService.getExtensionDataManager(
      SDK.getExtensionContext().id,
      await SDK.getAccessToken(),
    );
    ReactDOM.render(<App store={new SettingsStore(manager)} />, document.getElementById('root'));
    await SDK.notifyLoadSucceeded();
  } catch (error) {
    // SDK.init and the service lookups above can throw before App ever mounts - most likely
    // because the extension's data_write scope was raised and an administrator has not yet
    // re-approved the update. Without this catch, `void start()` would swallow the error and the
    // host page would show its loading spinner forever with no explanation, which is the worst
    // possible failure for the very first person who opens this page after an upgrade.
    const message = error instanceof Error ? error.message : String(error);
    const root = document.getElementById('root');
    if (root) {
      root.textContent = `Trivy Scanner failed to load: ${message}`;
    }
    // notifyLoadFailed exists on this SDK version (see azure-devops-extension-sdk/SDK.d.ts) and
    // is the correct signal here: it tells the host to stop showing its own loading indicator
    // and to render the failure state around this iframe instead of pretending we succeeded.
    await SDK.notifyLoadFailed(error instanceof Error ? error : message);
  }
}

void start();
