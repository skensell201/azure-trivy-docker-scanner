import * as SDK from 'azure-devops-extension-sdk';
import { CommonServiceIds, IExtensionDataService } from 'azure-devops-extension-api';
import * as React from 'react';
import * as ReactDOM from 'react-dom';
import { App } from './App';
import { SettingsStore } from './settingsStore';

async function start(): Promise<void> {
  try {
    await SDK.init({ loaded: false });
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
