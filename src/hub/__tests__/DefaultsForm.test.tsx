import * as React from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DefaultsForm } from '../components/DefaultsForm';
import { DefaultsConfig } from '../../shared/types';

const stored: DefaultsConfig = {
  dbRepository: 'registry.example.com/trivy-db:2',
  severities: ['CRITICAL', 'HIGH'],
  failOn: 'CRITICAL',
  timeoutMinutes: 10,
  dbRegistryUsername: 'svc',
  dbRegistryPassword: 'stored-secret',
};

describe('DefaultsForm', () => {
  it('prefills from the stored document', () => {
    render(<DefaultsForm defaults={stored} onSave={jest.fn()} />);
    expect((screen.getByLabelText(/cache directory/i) as HTMLInputElement).value).toBe('');
    expect((screen.getByLabelText(/timeout/i) as HTMLInputElement).value).toBe('10');
  });

  it('never renders the stored database registry password', () => {
    const { container } = render(<DefaultsForm defaults={stored} onSave={jest.fn()} />);
    expect(container.innerHTML).not.toContain('stored-secret');
  });

  it('does not show the deprecated database fields any more', () => {
    render(<DefaultsForm defaults={stored} onSave={jest.fn()} />);
    expect(screen.queryByLabelText(/database repository/i)).toBeNull();
    expect(screen.queryByLabelText(/java db repository/i)).toBeNull();
    expect(screen.queryByLabelText(/database registry username/i)).toBeNull();
    expect(screen.queryByLabelText(/database registry password/i)).toBeNull();
  });

  it('keeps the stored database registry password when it was not replaced', async () => {
    const onSave = jest.fn();
    render(<DefaultsForm defaults={stored} onSave={onSave} />);
    await userEvent.click(screen.getByRole('button', { name: /save/i }));
    expect(onSave).toHaveBeenCalledWith(
      expect.objectContaining({
        dbRepository: 'registry.example.com/trivy-db:2',
        dbRegistryUsername: 'svc',
        dbRegistryPassword: 'stored-secret',
      }),
    );
  });

  it('shows a migration note when legacy database settings are still present', () => {
    render(<DefaultsForm defaults={stored} onSave={jest.fn()} />);
    expect(screen.getByText(/moved to the Databases tab/i)).toBeTruthy();
    expect(screen.getByText(/no database linked/i)).toBeTruthy();
  });

  it('shows no migration note once no legacy database settings remain', () => {
    render(<DefaultsForm defaults={{}} onSave={jest.fn()} />);
    expect(screen.queryByText(/moved to the Databases tab/i)).toBeNull();
  });

  it('no longer requires a database repository, since that setting has moved to the Databases tab', async () => {
    const onSave = jest.fn();
    render(<DefaultsForm defaults={{}} onSave={onSave} />);
    await userEvent.click(screen.getByRole('button', { name: /save/i }));
    expect(onSave).toHaveBeenCalled();
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('rejects a severity list the task would reject too', async () => {
    const onSave = jest.fn();
    render(<DefaultsForm defaults={stored} onSave={onSave} />);
    const severities = screen.getByLabelText(/severities/i);
    await userEvent.clear(severities);
    await userEvent.type(severities, 'CRITICAL,BOGUS');
    await userEvent.click(screen.getByRole('button', { name: /save/i }));
    expect(onSave).not.toHaveBeenCalled();
    expect(screen.getByRole('alert').textContent).toMatch(/BOGUS/);
  });

  it('rejects UNKNOWN as a gate threshold and explains why', async () => {
    const onSave = jest.fn();
    render(<DefaultsForm defaults={stored} onSave={onSave} />);
    const failOn = screen.getByLabelText(/fail on/i);
    await userEvent.clear(failOn);
    await userEvent.type(failOn, 'UNKNOWN');
    await userEvent.click(screen.getByRole('button', { name: /save/i }));
    expect(onSave).not.toHaveBeenCalled();
    expect(screen.getByRole('alert').textContent).toMatch(/ranks lowest/i);
  });

  it('omits an empty optional field instead of storing an empty string', async () => {
    const onSave = jest.fn();
    render(<DefaultsForm defaults={{ dbRepository: 'registry.example.com/trivy-db:2' }} onSave={onSave} />);
    await userEvent.click(screen.getByRole('button', { name: /save/i }));
    const saved = onSave.mock.calls[0][0] as DefaultsConfig;
    expect('javaDbRepository' in saved).toBe(false);
    expect('cacheDir' in saved).toBe(false);
  });

  it('saves a numeric timeout as a number, not a string', async () => {
    const onSave = jest.fn();
    render(<DefaultsForm defaults={stored} onSave={onSave} />);
    const timeout = screen.getByLabelText(/timeout/i);
    await userEvent.clear(timeout);
    await userEvent.type(timeout, '25');
    await userEvent.click(screen.getByRole('button', { name: /save/i }));
    expect(onSave).toHaveBeenCalledWith(expect.objectContaining({ timeoutMinutes: 25 }));
  });
});
