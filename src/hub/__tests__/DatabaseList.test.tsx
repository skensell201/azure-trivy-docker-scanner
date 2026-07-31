import * as React from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DatabaseList } from '../components/DatabaseList';
import { DatabaseConfig } from '../../shared/types';

const databases: DatabaseConfig[] = [
  { alias: 'official', repository: 'registry.example.com/trivy-db:2' },
  { alias: 'fips-db', repository: 'registry.example.com/trivy-db-fips:2' },
];

describe('DatabaseList', () => {
  it('says the catalogue is empty and what to do about it', () => {
    render(<DatabaseList databases={[]} onEdit={jest.fn()} onDelete={jest.fn()} />);
    expect(screen.getByText(/no databases/i)).toBeTruthy();
  });

  it('lists every database with its alias and repository', () => {
    render(<DatabaseList databases={databases} onEdit={jest.fn()} onDelete={jest.fn()} />);
    expect(screen.getByText('official')).toBeTruthy();
    expect(screen.getByText('registry.example.com/trivy-db:2')).toBeTruthy();
    expect(screen.getByText('fips-db')).toBeTruthy();
  });

  it('does not show a password or a username in the list', () => {
    const { container } = render(
      <DatabaseList
        databases={[{ ...databases[0], registryUsername: 'svc', registryPassword: 'secret' }]}
        onEdit={jest.fn()}
        onDelete={jest.fn()}
      />,
    );
    expect(container.innerHTML).not.toContain('secret');
    expect(container.innerHTML).not.toContain('svc');
  });

  it('asks to edit the database whose row was selected', async () => {
    const onEdit = jest.fn();
    render(<DatabaseList databases={databases} onEdit={onEdit} onDelete={jest.fn()} />);
    await userEvent.click(screen.getAllByRole('button', { name: /edit/i })[1]);
    expect(onEdit).toHaveBeenCalledWith(databases[1]);
  });

  it('asks to delete the database that was clicked', async () => {
    const onDelete = jest.fn();
    render(<DatabaseList databases={databases} onEdit={jest.fn()} onDelete={onDelete} />);
    await userEvent.click(screen.getAllByRole('button', { name: /delete/i })[0]);
    expect(onDelete).toHaveBeenCalledWith(databases[0]);
  });

  // --- keyboard access: a row that opens the detail pane must be a real, focusable control ---

  it('exposes each row as a real button so it is reachable and operable from the keyboard', () => {
    render(<DatabaseList databases={databases} onEdit={jest.fn()} onDelete={jest.fn()} />);
    const row = screen.getByRole('button', { name: /edit official/i });
    expect(row.tagName).toBe('BUTTON');
  });

  it('opens the database via the keyboard, not just a pointer click', async () => {
    const onEdit = jest.fn();
    render(<DatabaseList databases={databases} onEdit={onEdit} onDelete={jest.fn()} />);
    const row = screen.getByRole('button', { name: /edit official/i });
    row.focus();
    expect(document.activeElement).toBe(row);
    await userEvent.keyboard('{Enter}');
    expect(onEdit).toHaveBeenCalledWith(databases[0]);
  });
});
