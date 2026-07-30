import * as React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from '../App';
import { SettingsConflictError } from '../settingsStore';
import { DefaultsConfig, RunnerConfig } from '../../shared/types';

class FakeStore {
  runners: RunnerConfig[] = [
    { alias: 'baseline', image: 'reg.corp/trivy:0.58.1', isDefault: true, enabled: true },
  ];
  defaults: DefaultsConfig = { dbRepository: 'reg.corp/trivy-db:2' };
  savedRunners: RunnerConfig[][] = [];
  failNextSave: Error | undefined;

  loadRunners = jest.fn(async () => this.runners);
  loadDefaults = jest.fn(async () => this.defaults);
  saveRunners = jest.fn(async (runners: RunnerConfig[]) => {
    if (this.failNextSave) {
      const error = this.failNextSave;
      this.failNextSave = undefined;
      throw error;
    }
    this.savedRunners.push(runners);
  });
  saveDefaults = jest.fn(async () => undefined);
}

describe('App', () => {
  it('shows the runner catalog once loaded', async () => {
    render(<App store={new FakeStore()} />);
    expect(await screen.findByText('baseline')).toBeTruthy();
  });

  it('offers the three tabs', async () => {
    render(<App store={new FakeStore()} />);
    await screen.findByText('baseline');
    expect(screen.getByRole('tab', { name: /runners/i })).toBeTruthy();
    expect(screen.getByRole('tab', { name: /defaults/i })).toBeTruthy();
    expect(screen.getByRole('tab', { name: /policy/i })).toBeTruthy();
  });

  it('switches to the defaults tab', async () => {
    render(<App store={new FakeStore()} />);
    await screen.findByText('baseline');
    await userEvent.click(screen.getByRole('tab', { name: /defaults/i }));
    expect(screen.getByLabelText(/database repository/i)).toBeTruthy();
  });

  it('adds a runner and saves the whole catalog', async () => {
    const store = new FakeStore();
    render(<App store={store} />);
    await screen.findByText('baseline');
    await userEvent.click(screen.getByRole('button', { name: /add runner/i }));
    await userEvent.type(screen.getByLabelText(/alias/i), 'hardened');
    await userEvent.type(screen.getByLabelText(/image/i), 'reg.corp/trivy-fips:0.58.1');
    await userEvent.click(screen.getByRole('button', { name: /^save$/i }));
    await waitFor(() => expect(store.saveRunners).toHaveBeenCalled());
    expect(store.savedRunners[0].map((runner) => runner.alias)).toEqual(['baseline', 'hardened']);
  });

  it('refuses to save a catalog the task would reject', async () => {
    const store = new FakeStore();
    render(<App store={store} />);
    await screen.findByText('baseline');
    await userEvent.click(screen.getByRole('button', { name: /add runner/i }));
    await userEvent.type(screen.getByLabelText(/alias/i), 'hardened');
    await userEvent.type(screen.getByLabelText(/image/i), 'reg.corp/trivy-fips:0.58.1');
    await userEvent.click(screen.getByLabelText(/default runner/i));
    await userEvent.click(screen.getByRole('button', { name: /^save$/i }));
    await waitFor(() => expect(screen.getByRole('alert').textContent).toMatch(/exactly one/i));
    expect(store.saveRunners).not.toHaveBeenCalled();
  });

  it('tells the administrator when someone else changed the settings', async () => {
    const store = new FakeStore();
    store.failNextSave = new SettingsConflictError('Another administrator changed these settings.');
    render(<App store={store} />);
    await screen.findByText('baseline');
    await userEvent.click(screen.getAllByRole('button', { name: /delete/i })[0]);
    await waitFor(() => expect(screen.getByRole('alert').textContent).toMatch(/another administrator/i));
  });

  it('reports a failed load instead of showing an empty catalog', async () => {
    const store = new FakeStore();
    store.loadRunners = jest.fn(async () => {
      throw new Error('the server said no');
    });
    render(<App store={store} />);
    expect(await screen.findByRole('alert')).toBeTruthy();
    expect(screen.getByRole('alert').textContent).toMatch(/the server said no/);
  });

  it('confirms a successful save', async () => {
    const store = new FakeStore();
    render(<App store={store} />);
    await screen.findByText('baseline');
    await userEvent.click(screen.getAllByRole('button', { name: /delete/i })[0]);
    await waitFor(() => expect(screen.getByText(/saved/i)).toBeTruthy());
  });
});
