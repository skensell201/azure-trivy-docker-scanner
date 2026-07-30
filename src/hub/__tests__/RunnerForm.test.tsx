import * as React from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { RunnerForm } from '../components/RunnerForm';
import { RunnerConfig } from '../../shared/types';

const existing: RunnerConfig = {
  alias: 'baseline',
  image: 'reg.corp/trivy:0.58.1',
  isDefault: true,
  enabled: true,
  registryUsername: 'svc',
  registryPassword: 'stored-secret',
};

describe('RunnerForm', () => {
  it('starts empty when adding a runner', () => {
    render(<RunnerForm runner={undefined} onSave={jest.fn()} onCancel={jest.fn()} />);
    expect((screen.getByLabelText('Alias') as HTMLInputElement).value).toBe('');
  });

  it('prefills the fields when editing', () => {
    render(<RunnerForm runner={existing} onSave={jest.fn()} onCancel={jest.fn()} />);
    expect((screen.getByLabelText('Alias') as HTMLInputElement).value).toBe('baseline');
    expect((screen.getByLabelText('Image') as HTMLInputElement).value).toBe('reg.corp/trivy:0.58.1');
  });

  it('never renders the stored password', () => {
    const { container } = render(
      <RunnerForm runner={existing} onSave={jest.fn()} onCancel={jest.fn()} />,
    );
    expect(container.innerHTML).not.toContain('stored-secret');
  });

  it('says a password is already stored instead of showing a password field', () => {
    render(<RunnerForm runner={existing} onSave={jest.fn()} onCancel={jest.fn()} />);
    expect(screen.getByText(/password is stored for this runner/i)).toBeTruthy();
    expect(screen.queryByLabelText('Password')).toBeNull();
  });

  it('reveals a password field once replacing is requested', async () => {
    render(<RunnerForm runner={existing} onSave={jest.fn()} onCancel={jest.fn()} />);
    await userEvent.click(screen.getByRole('button', { name: /replace password/i }));
    expect(screen.getByLabelText('Password')).toBeTruthy();
  });

  it('keeps the stored password when it was not replaced', async () => {
    const onSave = jest.fn();
    render(<RunnerForm runner={existing} onSave={onSave} onCancel={jest.fn()} />);
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(onSave).toHaveBeenCalledWith(
      expect.objectContaining({ registryPassword: 'stored-secret' }),
    );
  });

  it('sends the new password when it was replaced', async () => {
    const onSave = jest.fn();
    render(<RunnerForm runner={existing} onSave={onSave} onCancel={jest.fn()} />);
    await userEvent.click(screen.getByRole('button', { name: /replace password/i }));
    await userEvent.type(screen.getByLabelText('Password'), 'new-secret');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(onSave).toHaveBeenCalledWith(expect.objectContaining({ registryPassword: 'new-secret' }));
  });

  it('warns that the password is stored in clear text', () => {
    render(<RunnerForm runner={undefined} onSave={jest.fn()} onCancel={jest.fn()} />);
    expect(screen.getByText(/clear text/i)).toBeTruthy();
  });

  it('blocks saving an invalid runner and shows the reason', async () => {
    const onSave = jest.fn();
    render(<RunnerForm runner={undefined} onSave={onSave} onCancel={jest.fn()} />);
    await userEvent.type(screen.getByLabelText('Alias'), 'Bad Alias');
    await userEvent.type(screen.getByLabelText('Image'), 'reg.corp/trivy:latest');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(onSave).not.toHaveBeenCalled();
    expect(screen.getByRole('alert').textContent).toMatch(/lowercase/);
    expect(screen.getByRole('alert').textContent).toMatch(/latest/);
  });

  it('saves a valid runner', async () => {
    const onSave = jest.fn();
    render(<RunnerForm runner={undefined} onSave={onSave} onCancel={jest.fn()} />);
    await userEvent.type(screen.getByLabelText('Alias'), 'hardened');
    await userEvent.type(screen.getByLabelText('Image'), 'reg.corp/trivy-fips:0.58.1');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(onSave).toHaveBeenCalledWith(
      expect.objectContaining({ alias: 'hardened', image: 'reg.corp/trivy-fips:0.58.1' }),
    );
  });

  it('does not send an empty username or password as a stored value', async () => {
    const onSave = jest.fn();
    render(<RunnerForm runner={undefined} onSave={onSave} onCancel={jest.fn()} />);
    await userEvent.type(screen.getByLabelText('Alias'), 'hardened');
    await userEvent.type(screen.getByLabelText('Image'), 'reg.corp/trivy:0.58.1');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    const saved = onSave.mock.calls[0][0] as RunnerConfig;
    expect('registryUsername' in saved).toBe(false);
    expect('registryPassword' in saved).toBe(false);
  });

  it('rejects a username without a password, as the task would', async () => {
    const onSave = jest.fn();
    render(<RunnerForm runner={undefined} onSave={onSave} onCancel={jest.fn()} />);
    await userEvent.type(screen.getByLabelText('Alias'), 'hardened');
    await userEvent.type(screen.getByLabelText('Image'), 'reg.corp/trivy:0.58.1');
    await userEvent.type(screen.getByLabelText(/registry username/i), 'svc');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(onSave).not.toHaveBeenCalled();
    expect(screen.getByRole('alert').textContent).toMatch(/registryPassword/);
  });

  it('trims surrounding whitespace so a stray space cannot fail validation', async () => {
    const onSave = jest.fn();
    render(<RunnerForm runner={undefined} onSave={onSave} onCancel={jest.fn()} />);
    await userEvent.type(screen.getByLabelText('Alias'), '  hardened  ');
    await userEvent.type(screen.getByLabelText('Image'), '  reg.corp/trivy:0.58.1  ');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(onSave).toHaveBeenCalledWith(
      expect.objectContaining({ alias: 'hardened', image: 'reg.corp/trivy:0.58.1' }),
    );
  });

  it('treats an omitted enabled flag as enabled when editing', () => {
    render(
      <RunnerForm
        runner={{ alias: 'plain', image: 'reg.corp/trivy:0.58.1' }}
        onSave={jest.fn()}
        onCancel={jest.fn()}
      />,
    );
    expect((screen.getByLabelText('Enabled') as HTMLInputElement).checked).toBe(true);
  });

  it('cancels without saving', async () => {
    const onSave = jest.fn();
    const onCancel = jest.fn();
    render(<RunnerForm runner={existing} onSave={onSave} onCancel={onCancel} />);
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onCancel).toHaveBeenCalled();
    expect(onSave).not.toHaveBeenCalled();
  });
});
