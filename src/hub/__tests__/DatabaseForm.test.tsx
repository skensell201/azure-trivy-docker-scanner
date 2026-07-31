import * as React from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DatabaseForm } from '../components/DatabaseForm';
import { DatabaseConfig } from '../../shared/types';

const existing: DatabaseConfig = {
  alias: 'official',
  repository: 'registry.example.com/trivy-db:2',
  registryUsername: 'svc',
  registryPassword: 'stored-secret',
};

describe('DatabaseForm', () => {
  it('starts empty when adding a database', () => {
    render(<DatabaseForm database={undefined} onSave={jest.fn()} onCancel={jest.fn()} />);
    expect((screen.getByLabelText('Alias') as HTMLInputElement).value).toBe('');
  });

  it('prefills the fields when editing', () => {
    render(<DatabaseForm database={existing} onSave={jest.fn()} onCancel={jest.fn()} />);
    expect((screen.getByLabelText('Alias') as HTMLInputElement).value).toBe('official');
    expect((screen.getByLabelText(/^repository$/i) as HTMLInputElement).value).toBe(
      'registry.example.com/trivy-db:2',
    );
  });

  it('never renders the stored password', () => {
    const { container } = render(
      <DatabaseForm database={existing} onSave={jest.fn()} onCancel={jest.fn()} />,
    );
    expect(container.innerHTML).not.toContain('stored-secret');
  });

  it('says a password is already stored instead of showing a password field', () => {
    render(<DatabaseForm database={existing} onSave={jest.fn()} onCancel={jest.fn()} />);
    expect(screen.getByText(/password is stored for this database/i)).toBeTruthy();
    expect(screen.queryByLabelText('Password')).toBeNull();
  });

  it('reveals a password field once replacing is requested', async () => {
    render(<DatabaseForm database={existing} onSave={jest.fn()} onCancel={jest.fn()} />);
    await userEvent.click(screen.getByRole('button', { name: /replace password/i }));
    expect(screen.getByLabelText('Password')).toBeTruthy();
  });

  it('keeps the stored password when it was not replaced', async () => {
    const onSave = jest.fn();
    render(<DatabaseForm database={existing} onSave={onSave} onCancel={jest.fn()} />);
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(onSave).toHaveBeenCalledWith(
      expect.objectContaining({ registryPassword: 'stored-secret' }),
    );
  });

  it('sends the new password when it was replaced', async () => {
    const onSave = jest.fn();
    render(<DatabaseForm database={existing} onSave={onSave} onCancel={jest.fn()} />);
    await userEvent.click(screen.getByRole('button', { name: /replace password/i }));
    await userEvent.type(screen.getByLabelText('Password'), 'new-secret');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(onSave).toHaveBeenCalledWith(expect.objectContaining({ registryPassword: 'new-secret' }));
  });

  it('warns that the password is stored in clear text', () => {
    render(<DatabaseForm database={undefined} onSave={jest.fn()} onCancel={jest.fn()} />);
    expect(screen.getByText(/clear text/i)).toBeTruthy();
  });

  it('blocks saving an invalid database and shows the reason next to each field', async () => {
    const onSave = jest.fn();
    render(<DatabaseForm database={undefined} onSave={onSave} onCancel={jest.fn()} />);
    await userEvent.type(screen.getByLabelText('Alias'), 'Bad Alias');
    // Unlike a runner's image, an untagged/latest repository is valid (see validation.ts); a
    // syntactically invalid tag is still rejected, so use one of those to exercise this field.
    await userEvent.type(
      screen.getByLabelText(/^repository$/i),
      'registry.example.com/trivy-db:0.58.1 --privileged',
    );
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(onSave).not.toHaveBeenCalled();
    // One field-level alert per invalid field, not a single combined block - each lives next to
    // the input it concerns.
    expect(screen.getByLabelText('Alias').closest('.trivy-field')?.textContent).toMatch(/lowercase/);
    expect(screen.getByLabelText(/^repository$/i).closest('.trivy-field')?.textContent).toMatch(/tag/);
  });

  it('saves a valid database', async () => {
    const onSave = jest.fn();
    render(<DatabaseForm database={undefined} onSave={onSave} onCancel={jest.fn()} />);
    await userEvent.type(screen.getByLabelText('Alias'), 'hardened-db');
    await userEvent.type(screen.getByLabelText(/^repository$/i), 'registry.example.com/trivy-db:2');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(onSave).toHaveBeenCalledWith(
      expect.objectContaining({ alias: 'hardened-db', repository: 'registry.example.com/trivy-db:2' }),
    );
  });

  it('does not send an empty username or password as a stored value', async () => {
    const onSave = jest.fn();
    render(<DatabaseForm database={undefined} onSave={onSave} onCancel={jest.fn()} />);
    await userEvent.type(screen.getByLabelText('Alias'), 'hardened-db');
    await userEvent.type(screen.getByLabelText(/^repository$/i), 'registry.example.com/trivy-db:2');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    const saved = onSave.mock.calls[0][0] as DatabaseConfig;
    expect('registryUsername' in saved).toBe(false);
    expect('registryPassword' in saved).toBe(false);
  });

  it('rejects a username without a password, as the task would', async () => {
    const onSave = jest.fn();
    render(<DatabaseForm database={undefined} onSave={onSave} onCancel={jest.fn()} />);
    await userEvent.type(screen.getByLabelText('Alias'), 'hardened-db');
    await userEvent.type(screen.getByLabelText(/^repository$/i), 'registry.example.com/trivy-db:2');
    await userEvent.type(screen.getByLabelText(/registry username/i), 'svc');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(onSave).not.toHaveBeenCalled();
    expect(screen.getByRole('alert').textContent).toMatch(/registryPassword/);
  });

  it('trims surrounding whitespace so a stray space cannot fail validation', async () => {
    const onSave = jest.fn();
    render(<DatabaseForm database={undefined} onSave={onSave} onCancel={jest.fn()} />);
    await userEvent.type(screen.getByLabelText('Alias'), '  hardened-db  ');
    await userEvent.type(screen.getByLabelText(/^repository$/i), '  registry.example.com/trivy-db:2  ');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(onSave).toHaveBeenCalledWith(
      expect.objectContaining({ alias: 'hardened-db', repository: 'registry.example.com/trivy-db:2' }),
    );
  });

  it('cancels without saving', async () => {
    const onSave = jest.fn();
    const onCancel = jest.fn();
    render(<DatabaseForm database={existing} onSave={onSave} onCancel={onCancel} />);
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onCancel).toHaveBeenCalled();
    expect(onSave).not.toHaveBeenCalled();
  });
});
