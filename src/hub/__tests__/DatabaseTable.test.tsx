import * as React from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DatabaseTable } from '../components/DatabaseTable';
import { DatabaseConfig } from '../../shared/types';

const databases: DatabaseConfig[] = [
  { alias: 'official', repository: 'registry.example.com/trivy-db:2' },
  { alias: 'fips-db', repository: 'registry.example.com/trivy-db-fips:2' },
];

describe('DatabaseTable', () => {
  it('says the catalogue is empty and what to do about it', () => {
    render(<DatabaseTable databases={[]} onEdit={jest.fn()} onDelete={jest.fn()} />);
    expect(screen.getByText(/no databases/i)).toBeTruthy();
  });

  it('lists every database with its alias and repository', () => {
    render(<DatabaseTable databases={databases} onEdit={jest.fn()} onDelete={jest.fn()} />);
    expect(screen.getByText('official')).toBeTruthy();
    expect(screen.getByText('registry.example.com/trivy-db:2')).toBeTruthy();
    expect(screen.getByText('fips-db')).toBeTruthy();
  });

  it('does not show a password or a username in the table', () => {
    const { container } = render(
      <DatabaseTable
        databases={[{ ...databases[0], registryUsername: 'svc', registryPassword: 'secret' }]}
        onEdit={jest.fn()}
        onDelete={jest.fn()}
      />,
    );
    expect(container.innerHTML).not.toContain('secret');
    expect(container.innerHTML).not.toContain('svc');
  });

  it('asks to edit the database that was clicked', async () => {
    const onEdit = jest.fn();
    render(<DatabaseTable databases={databases} onEdit={onEdit} onDelete={jest.fn()} />);
    await userEvent.click(screen.getAllByRole('button', { name: /edit/i })[1]);
    expect(onEdit).toHaveBeenCalledWith(databases[1]);
  });

  it('asks to delete the database that was clicked', async () => {
    const onDelete = jest.fn();
    render(<DatabaseTable databases={databases} onEdit={jest.fn()} onDelete={onDelete} />);
    await userEvent.click(screen.getAllByRole('button', { name: /delete/i })[0]);
    expect(onDelete).toHaveBeenCalledWith(databases[0]);
  });
});
