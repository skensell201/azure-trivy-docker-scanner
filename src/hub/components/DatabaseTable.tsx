import * as React from 'react';
import { DatabaseConfig } from '../../shared/types';

export interface DatabaseTableProps {
  databases: DatabaseConfig[];
  onEdit: (database: DatabaseConfig) => void;
  onDelete: (database: DatabaseConfig) => void;
}

/** Registry credentials are deliberately absent from this view, same rule as RunnerTable: a catalogue row is not where anyone should stumble over a password. */
export function DatabaseTable({ databases, onEdit, onDelete }: DatabaseTableProps): JSX.Element {
  if (databases.length === 0) {
    return (
      <p>No databases are configured yet. Add one to let a runner bring its own vulnerability database.</p>
    );
  }

  return (
    <table className="trivy-database-table">
      <thead>
        <tr>
          <th>Alias</th>
          <th>Repository</th>
          <th aria-label="Actions" />
        </tr>
      </thead>
      <tbody>
        {databases.map((database) => (
          <tr key={database.alias}>
            <td>{database.alias}</td>
            <td>{database.repository}</td>
            <td>
              <button type="button" onClick={() => onEdit(database)}>
                Edit
              </button>
              <button type="button" onClick={() => onDelete(database)}>
                Delete
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
