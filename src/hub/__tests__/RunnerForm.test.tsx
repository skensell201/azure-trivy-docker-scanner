import * as React from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { RunnerForm } from '../components/RunnerForm';
import { DatabaseConfig, RunnerConfig } from '../../shared/types';

const existing: RunnerConfig = {
  alias: 'baseline',
  image: 'registry.example.com/trivy:0.58.1',
  isDefault: true,
  enabled: true,
  registryUsername: 'svc',
  registryPassword: 'stored-secret',
};

const databases: DatabaseConfig[] = [
  { alias: 'official', repository: 'registry.example.com/trivy-db:2' },
  { alias: 'fips-db', repository: 'registry.example.com/trivy-db-fips:2' },
];

describe('RunnerForm', () => {
  it('starts empty when adding a runner', () => {
    render(<RunnerForm runner={undefined} databases={[]} onSave={jest.fn()} onCancel={jest.fn()} />);
    expect((screen.getByLabelText('Alias') as HTMLInputElement).value).toBe('');
  });

  it('prefills the fields when editing', () => {
    render(<RunnerForm runner={existing} databases={[]} onSave={jest.fn()} onCancel={jest.fn()} />);
    expect((screen.getByLabelText('Alias') as HTMLInputElement).value).toBe('baseline');
    expect((screen.getByLabelText('Image') as HTMLInputElement).value).toBe('registry.example.com/trivy:0.58.1');
  });

  it('never renders the stored password', () => {
    const { container } = render(
      <RunnerForm runner={existing} databases={[]} onSave={jest.fn()} onCancel={jest.fn()} />,
    );
    expect(container.innerHTML).not.toContain('stored-secret');
  });

  it('says a password is already stored instead of showing a password field', () => {
    render(<RunnerForm runner={existing} databases={[]} onSave={jest.fn()} onCancel={jest.fn()} />);
    expect(screen.getByText(/password is stored for this runner/i)).toBeTruthy();
    expect(screen.queryByLabelText('Password')).toBeNull();
  });

  it('reveals a password field once replacing is requested', async () => {
    render(<RunnerForm runner={existing} databases={[]} onSave={jest.fn()} onCancel={jest.fn()} />);
    await userEvent.click(screen.getByRole('button', { name: /replace password/i }));
    expect(screen.getByLabelText('Password')).toBeTruthy();
  });

  it('keeps the stored password when it was not replaced', async () => {
    const onSave = jest.fn();
    render(<RunnerForm runner={existing} databases={[]} onSave={onSave} onCancel={jest.fn()} />);
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(onSave).toHaveBeenCalledWith(
      expect.objectContaining({ registryPassword: 'stored-secret' }),
    );
  });

  it('sends the new password when it was replaced', async () => {
    const onSave = jest.fn();
    render(<RunnerForm runner={existing} databases={[]} onSave={onSave} onCancel={jest.fn()} />);
    await userEvent.click(screen.getByRole('button', { name: /replace password/i }));
    await userEvent.type(screen.getByLabelText('Password'), 'new-secret');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(onSave).toHaveBeenCalledWith(expect.objectContaining({ registryPassword: 'new-secret' }));
  });

  it('warns that the password is stored in clear text', () => {
    render(<RunnerForm runner={undefined} databases={[]} onSave={jest.fn()} onCancel={jest.fn()} />);
    expect(screen.getByText(/clear text/i)).toBeTruthy();
  });

  it('blocks saving an invalid runner and shows the reason next to each field', async () => {
    const onSave = jest.fn();
    render(<RunnerForm runner={undefined} databases={[]} onSave={onSave} onCancel={jest.fn()} />);
    await userEvent.type(screen.getByLabelText('Alias'), 'Bad Alias');
    await userEvent.type(screen.getByLabelText('Image'), 'registry.example.com/trivy:latest');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(onSave).not.toHaveBeenCalled();
    // One field-level alert per invalid field, not a single combined block - each lives next to
    // the input it concerns.
    expect(screen.getByLabelText('Alias').closest('.trivy-field')?.textContent).toMatch(/lowercase/);
    expect(screen.getByLabelText('Image').closest('.trivy-field')?.textContent).toMatch(/latest/);
  });

  it('shows a field-level validation message next to the field it concerns, not only in a combined block', async () => {
    const onSave = jest.fn();
    render(<RunnerForm runner={undefined} databases={[]} onSave={onSave} onCancel={jest.fn()} />);
    await userEvent.type(screen.getByLabelText('Alias'), 'Bad Alias');
    await userEvent.type(screen.getByLabelText('Image'), 'registry.example.com/trivy:0.58.1');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    const aliasField = screen.getByLabelText('Alias').closest('.trivy-field');
    expect(aliasField?.textContent).toMatch(/lowercase/i);
    // The image field is valid, so it carries no error of its own even though the alias field does.
    const imageField = screen.getByLabelText('Image').closest('.trivy-field');
    expect(imageField?.textContent).not.toMatch(/lowercase/i);
  });

  it('saves a valid runner', async () => {
    const onSave = jest.fn();
    render(<RunnerForm runner={undefined} databases={[]} onSave={onSave} onCancel={jest.fn()} />);
    await userEvent.type(screen.getByLabelText('Alias'), 'hardened');
    await userEvent.type(screen.getByLabelText('Image'), 'registry.example.com/trivy-fips:0.58.1');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(onSave).toHaveBeenCalledWith(
      expect.objectContaining({ alias: 'hardened', image: 'registry.example.com/trivy-fips:0.58.1' }),
    );
  });

  it('does not send an empty username or password as a stored value', async () => {
    const onSave = jest.fn();
    render(<RunnerForm runner={undefined} databases={[]} onSave={onSave} onCancel={jest.fn()} />);
    await userEvent.type(screen.getByLabelText('Alias'), 'hardened');
    await userEvent.type(screen.getByLabelText('Image'), 'registry.example.com/trivy:0.58.1');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    const saved = onSave.mock.calls[0][0] as RunnerConfig;
    expect('registryUsername' in saved).toBe(false);
    expect('registryPassword' in saved).toBe(false);
  });

  it('rejects a username without a password, as the task would', async () => {
    const onSave = jest.fn();
    render(<RunnerForm runner={undefined} databases={[]} onSave={onSave} onCancel={jest.fn()} />);
    await userEvent.type(screen.getByLabelText('Alias'), 'hardened');
    await userEvent.type(screen.getByLabelText('Image'), 'registry.example.com/trivy:0.58.1');
    await userEvent.type(screen.getByLabelText(/registry username/i), 'svc');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(onSave).not.toHaveBeenCalled();
    expect(screen.getByRole('alert').textContent).toMatch(/registryPassword/);
  });

  it('trims surrounding whitespace so a stray space cannot fail validation', async () => {
    const onSave = jest.fn();
    render(<RunnerForm runner={undefined} databases={[]} onSave={onSave} onCancel={jest.fn()} />);
    await userEvent.type(screen.getByLabelText('Alias'), '  hardened  ');
    await userEvent.type(screen.getByLabelText('Image'), '  registry.example.com/trivy:0.58.1  ');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(onSave).toHaveBeenCalledWith(
      expect.objectContaining({ alias: 'hardened', image: 'registry.example.com/trivy:0.58.1' }),
    );
  });

  it('treats an omitted enabled flag as enabled when editing', () => {
    render(
      <RunnerForm
        runner={{ alias: 'plain', image: 'registry.example.com/trivy:0.58.1' }}
        databases={[]}
        onSave={jest.fn()}
        onCancel={jest.fn()}
      />,
    );
    expect((screen.getByLabelText('Enabled') as HTMLInputElement).checked).toBe(true);
  });

  it('cancels without saving', async () => {
    const onSave = jest.fn();
    const onCancel = jest.fn();
    render(<RunnerForm runner={existing} databases={[]} onSave={onSave} onCancel={onCancel} />);
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onCancel).toHaveBeenCalled();
    expect(onSave).not.toHaveBeenCalled();
  });

  // --- database link: a select populated from the catalogue, not free text ---

  it('offers the catalogue aliases and a not-linked option in the database select', () => {
    render(<RunnerForm runner={undefined} databases={databases} onSave={jest.fn()} onCancel={jest.fn()} />);
    const select = screen.getByLabelText('Database') as HTMLSelectElement;
    const optionLabels = Array.from(select.options).map((option) => option.value);
    expect(optionLabels).toEqual(['', 'official', 'fips-db']);
    expect(screen.getByText(/not linked/i)).toBeTruthy();
  });

  it('defaults the database select to not-linked when the runner has none set', () => {
    render(<RunnerForm runner={undefined} databases={databases} onSave={jest.fn()} onCancel={jest.fn()} />);
    expect((screen.getByLabelText('Database') as HTMLSelectElement).value).toBe('');
  });

  it('preselects the database the runner is already linked to', () => {
    render(
      <RunnerForm
        runner={{ ...existing, database: 'fips-db' }}
        databases={databases}
        onSave={jest.fn()}
        onCancel={jest.fn()}
      />,
    );
    expect((screen.getByLabelText('Database') as HTMLSelectElement).value).toBe('fips-db');
  });

  it('says the not-linked option falls back to the deprecated Defaults tab settings', () => {
    render(<RunnerForm runner={undefined} databases={databases} onSave={jest.fn()} onCancel={jest.fn()} />);
    expect(screen.getByText(/deprecated Defaults tab settings/i)).toBeTruthy();
    expect(screen.getByText(/phased out/i)).toBeTruthy();
  });

  it('saves the selected database alias on the runner', async () => {
    const onSave = jest.fn();
    render(<RunnerForm runner={undefined} databases={databases} onSave={onSave} onCancel={jest.fn()} />);
    await userEvent.type(screen.getByLabelText('Alias'), 'hardened');
    await userEvent.type(screen.getByLabelText('Image'), 'registry.example.com/trivy:0.58.1');
    await userEvent.selectOptions(screen.getByLabelText('Database'), 'fips-db');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(onSave).toHaveBeenCalledWith(expect.objectContaining({ database: 'fips-db' }));
  });

  it('omits the database field rather than saving an empty string when left not-linked', async () => {
    const onSave = jest.fn();
    render(<RunnerForm runner={undefined} databases={databases} onSave={onSave} onCancel={jest.fn()} />);
    await userEvent.type(screen.getByLabelText('Alias'), 'hardened');
    await userEvent.type(screen.getByLabelText('Image'), 'registry.example.com/trivy:0.58.1');
    await userEvent.click(screen.getByRole('button', { name: 'Save' }));
    const saved = onSave.mock.calls[0][0] as RunnerConfig;
    expect('database' in saved).toBe(false);
  });
});
