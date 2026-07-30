import * as React from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { RunnerTable } from '../components/RunnerTable';
import { RunnerConfig } from '../../shared/types';

const runners: RunnerConfig[] = [
  { alias: 'baseline', image: 'reg.corp/trivy:0.58.1', isDefault: true, enabled: true },
  { alias: 'legacy', image: 'reg.corp/trivy:0.44.0', enabled: false },
];

describe('RunnerTable', () => {
  it('says the catalog is empty and what to do about it', () => {
    render(<RunnerTable runners={[]} onEdit={jest.fn()} onDelete={jest.fn()} />);
    expect(screen.getByText(/no runners/i)).toBeTruthy();
  });

  it('lists every runner with its alias and image', () => {
    render(<RunnerTable runners={runners} onEdit={jest.fn()} onDelete={jest.fn()} />);
    expect(screen.getByText('baseline')).toBeTruthy();
    expect(screen.getByText('reg.corp/trivy:0.58.1')).toBeTruthy();
    expect(screen.getByText('legacy')).toBeTruthy();
  });

  it('marks which runner is the default', () => {
    render(<RunnerTable runners={runners} onEdit={jest.fn()} onDelete={jest.fn()} />);
    const defaultRow = screen.getByText('baseline').closest('tr');
    expect(defaultRow?.textContent).toMatch(/default/i);
  });

  it('marks a disabled runner as disabled', () => {
    render(<RunnerTable runners={runners} onEdit={jest.fn()} onDelete={jest.fn()} />);
    const row = screen.getByText('legacy').closest('tr');
    expect(row?.textContent).toMatch(/disabled/i);
  });

  it('does not label an ordinary runner as default or disabled', () => {
    render(
      <RunnerTable
        runners={[{ alias: 'plain', image: 'reg.corp/trivy:0.58.1' }]}
        onEdit={jest.fn()}
        onDelete={jest.fn()}
      />,
    );
    const row = screen.getByText('plain').closest('tr');
    expect(row?.textContent).not.toMatch(/default|disabled/i);
  });

  it('does not show a password or a username in the table', () => {
    const { container } = render(
      <RunnerTable
        runners={[{ ...runners[0], registryUsername: 'svc', registryPassword: 'secret' }]}
        onEdit={jest.fn()}
        onDelete={jest.fn()}
      />,
    );
    expect(container.innerHTML).not.toContain('secret');
    expect(container.innerHTML).not.toContain('svc');
  });

  it('asks to edit the runner that was clicked', async () => {
    const onEdit = jest.fn();
    render(<RunnerTable runners={runners} onEdit={onEdit} onDelete={jest.fn()} />);
    await userEvent.click(screen.getAllByRole('button', { name: /edit/i })[1]);
    expect(onEdit).toHaveBeenCalledWith(runners[1]);
  });

  it('asks to delete the runner that was clicked', async () => {
    const onDelete = jest.fn();
    render(<RunnerTable runners={runners} onEdit={jest.fn()} onDelete={onDelete} />);
    await userEvent.click(screen.getAllByRole('button', { name: /delete/i })[0]);
    expect(onDelete).toHaveBeenCalledWith(runners[0]);
  });
});
