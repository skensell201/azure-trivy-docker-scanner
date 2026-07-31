import * as React from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { RunnerList } from '../components/RunnerList';
import { RunnerConfig } from '../../shared/types';

const runners: RunnerConfig[] = [
  { alias: 'baseline', image: 'registry.example.com/trivy:0.58.1', isDefault: true, enabled: true },
  { alias: 'legacy', image: 'registry.example.com/trivy:0.44.0', enabled: false },
];

describe('RunnerList', () => {
  it('says the catalog is empty and what to do about it', () => {
    render(<RunnerList runners={[]} onEdit={jest.fn()} onDelete={jest.fn()} />);
    expect(screen.getByText(/no runners/i)).toBeTruthy();
  });

  it('lists every runner with its alias and image', () => {
    render(<RunnerList runners={runners} onEdit={jest.fn()} onDelete={jest.fn()} />);
    expect(screen.getByText('baseline')).toBeTruthy();
    expect(screen.getByText('registry.example.com/trivy:0.58.1')).toBeTruthy();
    expect(screen.getByText('legacy')).toBeTruthy();
  });

  it('marks which runner is the default', () => {
    render(<RunnerList runners={runners} onEdit={jest.fn()} onDelete={jest.fn()} />);
    const defaultRow = screen.getByText('baseline').closest('li');
    expect(defaultRow?.textContent).toMatch(/default/i);
  });

  it('marks a disabled runner as disabled', () => {
    render(<RunnerList runners={runners} onEdit={jest.fn()} onDelete={jest.fn()} />);
    const row = screen.getByText('legacy').closest('li');
    expect(row?.textContent).toMatch(/disabled/i);
  });

  // Rewritten for the operations console: a plain runner with no database link now legitimately
  // shows a chip mentioning the deprecated "Defaults" tab (see the database-link tests below),
  // whose text contains the substring "default" - so this can no longer assert on the row's
  // whole textContent the way the table-row version did. It now checks for the specific
  // Default/Disabled chip classes instead, which is the tighter, still-accurate check.
  it('does not show a default or disabled chip for an ordinary, enabled runner', () => {
    render(
      <RunnerList
        runners={[{ alias: 'plain', image: 'registry.example.com/trivy:0.58.1' }]}
        onEdit={jest.fn()}
        onDelete={jest.fn()}
      />,
    );
    const row = screen.getByText('plain').closest('li');
    expect(row?.querySelector('.trivy-chip-default')).toBeNull();
    expect(row?.querySelector('.trivy-chip-disabled')).toBeNull();
  });

  it('does not show a password or a username in the list', () => {
    const { container } = render(
      <RunnerList
        runners={[{ ...runners[0], registryUsername: 'svc', registryPassword: 'secret' }]}
        onEdit={jest.fn()}
        onDelete={jest.fn()}
      />,
    );
    expect(container.innerHTML).not.toContain('secret');
    expect(container.innerHTML).not.toContain('svc');
  });

  it('asks to edit the runner whose row was selected', async () => {
    const onEdit = jest.fn();
    render(<RunnerList runners={runners} onEdit={onEdit} onDelete={jest.fn()} />);
    await userEvent.click(screen.getAllByRole('button', { name: /edit/i })[1]);
    expect(onEdit).toHaveBeenCalledWith(runners[1]);
  });

  it('asks to delete the runner that was clicked', async () => {
    const onDelete = jest.fn();
    render(<RunnerList runners={runners} onEdit={jest.fn()} onDelete={onDelete} />);
    await userEvent.click(screen.getAllByRole('button', { name: /delete/i })[0]);
    expect(onDelete).toHaveBeenCalledWith(runners[0]);
  });

  // --- keyboard access: a row that opens the detail pane must be a real, focusable control ---

  it('exposes each row as a real button so it is reachable and operable from the keyboard', () => {
    render(<RunnerList runners={runners} onEdit={jest.fn()} onDelete={jest.fn()} />);
    const row = screen.getByRole('button', { name: /edit baseline/i });
    expect(row.tagName).toBe('BUTTON');
  });

  it('opens the runner via the keyboard, not just a pointer click', async () => {
    const onEdit = jest.fn();
    render(<RunnerList runners={runners} onEdit={onEdit} onDelete={jest.fn()} />);
    const row = screen.getByRole('button', { name: /edit baseline/i });
    row.focus();
    expect(document.activeElement).toBe(row);
    await userEvent.keyboard('{Enter}');
    expect(onEdit).toHaveBeenCalledWith(runners[0]);
  });

  // --- database link chip: the migration state must be visible without opening anything ---

  it('shows a warning chip for a runner with no database, and the database alias for one that has one', () => {
    render(
      <RunnerList
        runners={[
          { ...runners[0], database: 'official' },
          { alias: 'legacy', image: 'registry.example.com/trivy:0.44.0', enabled: true },
        ]}
        onEdit={jest.fn()}
        onDelete={jest.fn()}
      />,
    );
    const linkedRow = screen.getByText('baseline').closest('li');
    expect(linkedRow?.textContent).toMatch(/official/);
    expect(linkedRow?.querySelector('.trivy-chip-dbwarn')).toBeNull();

    const unlinkedRow = screen.getByText('legacy').closest('li');
    expect(unlinkedRow?.textContent).toMatch(/deprecated Defaults settings/i);
    expect(unlinkedRow?.querySelector('.trivy-chip-db')).toBeNull();
  });
});
