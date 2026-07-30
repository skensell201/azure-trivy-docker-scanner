import * as React from 'react';
import { RunnerConfig } from '../../shared/types';

export interface RunnerTableProps {
  runners: RunnerConfig[];
  onEdit: (runner: RunnerConfig) => void;
  onDelete: (runner: RunnerConfig) => void;
}

/** Registry credentials are deliberately absent from this view: a catalog row is not where anyone should stumble over a password. */
export function RunnerTable({ runners, onEdit, onDelete }: RunnerTableProps): JSX.Element {
  if (runners.length === 0) {
    return <p>No runners are configured yet. Add one to let pipelines run a scan.</p>;
  }

  return (
    <table className="trivy-runner-table">
      <thead>
        <tr>
          <th>Alias</th>
          <th>Image</th>
          <th>State</th>
          <th aria-label="Actions" />
        </tr>
      </thead>
      <tbody>
        {runners.map((runner) => (
          <tr key={runner.alias}>
            <td>{runner.alias}</td>
            <td>{runner.image}</td>
            <td>
              {[runner.isDefault ? 'Default' : '', runner.enabled === false ? 'Disabled' : '']
                .filter((label) => label.length > 0)
                .join(', ')}
            </td>
            <td>
              <button type="button" onClick={() => onEdit(runner)}>
                Edit
              </button>
              <button type="button" onClick={() => onDelete(runner)}>
                Delete
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
