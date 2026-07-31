import * as React from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DefaultsForm } from '../components/DefaultsForm';
import { DefaultsConfig, RunnerConfig } from '../../shared/types';

const stored: DefaultsConfig = {
  dbRepository: 'registry.example.com/trivy-db:2',
  severities: ['CRITICAL', 'HIGH'],
  failOn: 'CRITICAL',
  timeoutMinutes: 10,
  dbRegistryUsername: 'svc',
  dbRegistryPassword: 'stored-secret',
};

const unlinkedRunner: RunnerConfig = {
  alias: 'legacy',
  image: 'registry.example.com/trivy:0.44.0',
  enabled: true,
};

const linkedRunner: RunnerConfig = {
  alias: 'hardened',
  image: 'registry.example.com/trivy-fips:0.58.1',
  enabled: true,
  database: 'official',
};

describe('DefaultsForm', () => {
  it('prefills from the stored document', () => {
    render(<DefaultsForm defaults={stored} runners={[]} onSave={jest.fn()} onRemoveLegacyDatabaseSettings={jest.fn()} />);
    expect((screen.getByLabelText(/cache directory/i) as HTMLInputElement).value).toBe('');
    expect((screen.getByLabelText(/timeout/i) as HTMLInputElement).value).toBe('10');
  });

  it('never renders the stored database registry password', () => {
    const { container } = render(
      <DefaultsForm defaults={stored} runners={[]} onSave={jest.fn()} onRemoveLegacyDatabaseSettings={jest.fn()} />,
    );
    expect(container.innerHTML).not.toContain('stored-secret');
  });

  it('does not show the deprecated database fields any more', () => {
    render(<DefaultsForm defaults={stored} runners={[]} onSave={jest.fn()} onRemoveLegacyDatabaseSettings={jest.fn()} />);
    expect(screen.queryByLabelText(/database repository/i)).toBeNull();
    expect(screen.queryByLabelText(/java db repository/i)).toBeNull();
    expect(screen.queryByLabelText(/database registry username/i)).toBeNull();
    expect(screen.queryByLabelText(/database registry password/i)).toBeNull();
  });

  it('keeps the stored database registry password when it was not replaced', async () => {
    const onSave = jest.fn();
    render(
      <DefaultsForm defaults={stored} runners={[]} onSave={onSave} onRemoveLegacyDatabaseSettings={jest.fn()} />,
    );
    await userEvent.click(screen.getByRole('button', { name: /save/i }));
    expect(onSave).toHaveBeenCalledWith(
      expect.objectContaining({
        dbRepository: 'registry.example.com/trivy-db:2',
        dbRegistryUsername: 'svc',
        dbRegistryPassword: 'stored-secret',
      }),
    );
  });

  it('shows no migration note once no legacy database settings remain', () => {
    render(<DefaultsForm defaults={{}} runners={[]} onSave={jest.fn()} onRemoveLegacyDatabaseSettings={jest.fn()} />);
    expect(screen.queryByText(/moved to the Databases tab/i)).toBeNull();
  });

  it('no longer requires a database repository, since that setting has moved to the Databases tab', async () => {
    const onSave = jest.fn();
    render(<DefaultsForm defaults={{}} runners={[]} onSave={onSave} onRemoveLegacyDatabaseSettings={jest.fn()} />);
    await userEvent.click(screen.getByRole('button', { name: /save/i }));
    expect(onSave).toHaveBeenCalled();
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('rejects a severity list the task would reject too', async () => {
    const onSave = jest.fn();
    render(
      <DefaultsForm defaults={stored} runners={[]} onSave={onSave} onRemoveLegacyDatabaseSettings={jest.fn()} />,
    );
    const severities = screen.getByLabelText(/severities/i);
    await userEvent.clear(severities);
    await userEvent.type(severities, 'CRITICAL,BOGUS');
    await userEvent.click(screen.getByRole('button', { name: /save/i }));
    expect(onSave).not.toHaveBeenCalled();
    expect(screen.getByRole('alert').textContent).toMatch(/BOGUS/);
  });

  it('rejects UNKNOWN as a gate threshold and explains why', async () => {
    const onSave = jest.fn();
    render(
      <DefaultsForm defaults={stored} runners={[]} onSave={onSave} onRemoveLegacyDatabaseSettings={jest.fn()} />,
    );
    const failOn = screen.getByLabelText(/fail on/i);
    await userEvent.clear(failOn);
    await userEvent.type(failOn, 'UNKNOWN');
    await userEvent.click(screen.getByRole('button', { name: /save/i }));
    expect(onSave).not.toHaveBeenCalled();
    expect(screen.getByRole('alert').textContent).toMatch(/ranks lowest/i);
  });

  it('omits an empty optional field instead of storing an empty string', async () => {
    const onSave = jest.fn();
    render(
      <DefaultsForm
        defaults={{ dbRepository: 'registry.example.com/trivy-db:2' }}
        runners={[]}
        onSave={onSave}
        onRemoveLegacyDatabaseSettings={jest.fn()}
      />,
    );
    await userEvent.click(screen.getByRole('button', { name: /save/i }));
    const saved = onSave.mock.calls[0][0] as DefaultsConfig;
    expect('javaDbRepository' in saved).toBe(false);
    expect('cacheDir' in saved).toBe(false);
  });

  it('saves a numeric timeout as a number, not a string', async () => {
    const onSave = jest.fn();
    render(
      <DefaultsForm defaults={stored} runners={[]} onSave={onSave} onRemoveLegacyDatabaseSettings={jest.fn()} />,
    );
    const timeout = screen.getByLabelText(/timeout/i);
    await userEvent.clear(timeout);
    await userEvent.type(timeout, '25');
    await userEvent.click(screen.getByRole('button', { name: /save/i }));
    expect(onSave).toHaveBeenCalledWith(expect.objectContaining({ timeoutMinutes: 25 }));
  });

  // --- Finishing the migration: retiring the legacy database fields ---

  describe('legacy database settings note', () => {
    it('names the runners still relying on them, and does not offer to remove them', () => {
      render(
        <DefaultsForm
          defaults={stored}
          runners={[unlinkedRunner]}
          onSave={jest.fn()}
          onRemoveLegacyDatabaseSettings={jest.fn()}
        />,
      );
      expect(screen.getByText(/moved to the Databases tab/i)).toBeTruthy();
      expect(screen.getByText(/still in use by 1 runner/i)).toBeTruthy();
      expect(screen.getByText(/still in use by 1 runner/i).textContent).toMatch(/legacy/);
      expect(screen.queryByRole('button', { name: /remove legacy database settings/i })).toBeNull();
    });

    it('names every runner still missing a link when more than one remains', () => {
      const anotherUnlinked: RunnerConfig = {
        alias: 'sidecar',
        image: 'registry.example.com/trivy:0.50.0',
        enabled: true,
      };
      render(
        <DefaultsForm
          defaults={stored}
          runners={[unlinkedRunner, anotherUnlinked, linkedRunner]}
          onSave={jest.fn()}
          onRemoveLegacyDatabaseSettings={jest.fn()}
        />,
      );
      const note = screen.getByText(/still in use by 2 runners/i);
      expect(note.textContent).toMatch(/legacy/);
      expect(note.textContent).toMatch(/sidecar/);
      // The linked runner isn't part of what's left to do.
      expect(note.textContent).not.toMatch(/hardened/);
    });

    it('offers to remove them once every runner has a database linked', () => {
      render(
        <DefaultsForm
          defaults={stored}
          runners={[linkedRunner]}
          onSave={jest.fn()}
          onRemoveLegacyDatabaseSettings={jest.fn()}
        />,
      );
      expect(screen.getByText(/nothing uses these any more/i)).toBeTruthy();
      expect(screen.getByRole('button', { name: /remove legacy database settings/i })).toBeTruthy();
    });

    it('offers to remove them when the catalogue has no runners at all, vacuously fully migrated', () => {
      render(
        <DefaultsForm
          defaults={stored}
          runners={[]}
          onSave={jest.fn()}
          onRemoveLegacyDatabaseSettings={jest.fn()}
        />,
      );
      expect(screen.getByText(/nothing uses these any more/i)).toBeTruthy();
      expect(screen.getByRole('button', { name: /remove legacy database settings/i })).toBeTruthy();
    });

    it('requires confirmation before removing them, and does nothing on cancel', async () => {
      const onRemove = jest.fn();
      render(
        <DefaultsForm defaults={stored} runners={[linkedRunner]} onSave={jest.fn()} onRemoveLegacyDatabaseSettings={onRemove} />,
      );
      await userEvent.click(screen.getByRole('button', { name: /remove legacy database settings/i }));
      expect(onRemove).not.toHaveBeenCalled();
      expect(screen.getByText(/cannot be undone/i)).toBeTruthy();
      await userEvent.click(screen.getByRole('button', { name: /^cancel$/i }));
      expect(onRemove).not.toHaveBeenCalled();
      expect(screen.queryByText(/cannot be undone/i)).toBeNull();
    });

    it('removes them once the administrator confirms', async () => {
      const onRemove = jest.fn();
      render(
        <DefaultsForm defaults={stored} runners={[linkedRunner]} onSave={jest.fn()} onRemoveLegacyDatabaseSettings={onRemove} />,
      );
      await userEvent.click(screen.getByRole('button', { name: /remove legacy database settings/i }));
      await userEvent.click(screen.getByRole('button', { name: /yes, remove them/i }));
      expect(onRemove).toHaveBeenCalledTimes(1);
    });
  });
});
