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
    expect((screen.getByLabelText(/database repository/i) as HTMLInputElement).value).toBe(
      'registry.example.com/trivy-db:2',
    );
  });

  it('never renders the stored database registry password', () => {
    const { container } = render(<DefaultsForm defaults={stored} onSave={jest.fn()} />);
    expect(container.innerHTML).not.toContain('stored-secret');
  });

  it('keeps the stored database registry password when it was not replaced', async () => {
    const onSave = jest.fn();
    render(<DefaultsForm defaults={stored} onSave={onSave} />);
    await userEvent.click(screen.getByRole('button', { name: /save/i }));
    expect(onSave).toHaveBeenCalledWith(
      expect.objectContaining({ dbRegistryPassword: 'stored-secret' }),
    );
  });

  it('refuses to save without a database repository, because agents have no internet', async () => {
    const onSave = jest.fn();
    render(<DefaultsForm defaults={{ dbRepository: '' }} onSave={onSave} />);
    await userEvent.click(screen.getByRole('button', { name: /save/i }));
    expect(onSave).not.toHaveBeenCalled();
    expect(screen.getByRole('alert').textContent).toMatch(/required/i);
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
