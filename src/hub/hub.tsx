import * as SDK from 'azure-devops-extension-sdk';
import { CommonServiceIds, IExtensionDataService } from 'azure-devops-extension-api';
import * as React from 'react';
import * as ReactDOM from 'react-dom';
import { App } from './App';
import { SettingsStore } from './settingsStore';

async function start(): Promise<void> {
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
}

void start();
