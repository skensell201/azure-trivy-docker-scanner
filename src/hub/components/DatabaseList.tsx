import * as React from 'react';
import { DatabaseConfig } from '../../shared/types';

export interface DatabaseListProps {
  databases: DatabaseConfig[];
  /** The alias currently open in the detail pane, if any, so its row can be marked selected. */
  selectedAlias?: string;
  onEdit: (database: DatabaseConfig) => void;
  onDelete: (database: DatabaseConfig) => void;
}

/**
 * The left-hand list of the Databases operations console: one row per catalogue entry, each
 * carrying a state stripe, its alias, its repository in monospace, and (when set) a chip noting
 * it also carries a Java database. Registry credentials are deliberately absent from this view,
 * same rule as RunnerList: a list row is not where anyone should stumble over a password.
 */
export function DatabaseList({ databases, selectedAlias, onEdit, onDelete }: DatabaseListProps): JSX.Element {
  if (databases.length === 0) {
    return (
      <p>No databases are configured yet. Add one to let a runner bring its own vulnerability database.</p>
    );
  }

  return (
    <ul className="trivy-list trivy-database-list">
      {databases.map((database) => (
        <li
          key={database.alias}
          className={`trivy-row${database.alias === selectedAlias ? ' trivy-row-selected' : ''}`}
        >
          <span className="trivy-row-stripe trivy-row-stripe-ok" aria-hidden="true" />
          <button
            type="button"
            className="trivy-row-main"
            aria-label={`Edit ${database.alias}`}
            aria-current={database.alias === selectedAlias ? 'true' : undefined}
            onClick={() => onEdit(database)}
          >
            <span className="trivy-row-alias">{database.alias}</span>
            <span className="trivy-row-mono trivy-mono">{database.repository}</span>
            {database.javaRepository ? (
              <span className="trivy-row-chips">
                <span className="trivy-chip trivy-chip-db">Java DB</span>
              </span>
            ) : null}
          </button>
          <button type="button" className="trivy-row-delete" onClick={() => onDelete(database)}>
            Delete
          </button>
        </li>
      ))}
    </ul>
  );
}
