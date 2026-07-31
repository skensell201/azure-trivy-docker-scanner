import * as React from 'react';
import { RunnerConfig } from '../../shared/types';

export interface RunnerListProps {
  runners: RunnerConfig[];
  /** The alias currently open in the detail pane, if any, so its row can be marked selected. */
  selectedAlias?: string;
  onEdit: (runner: RunnerConfig) => void;
  onDelete: (runner: RunnerConfig) => void;
}

/**
 * The left-hand list of the Runners operations console: one row per runner, each carrying a
 * state stripe, its alias, its image in monospace, and chips for its state. Registry credentials
 * are deliberately absent from this view: a list row is not where anyone should stumble over a
 * password.
 *
 * State is encoded in shape and position as well as colour (a solid stripe versus a dashed one,
 * a distinct leading glyph per chip) so a row still reads correctly for someone who cannot
 * distinguish the colours apart - the same convention the top bar's unlinked-runner stat already
 * uses (see hub.css's `.trivy-stat-warn`).
 */
export function RunnerList({ runners, selectedAlias, onEdit, onDelete }: RunnerListProps): JSX.Element {
  if (runners.length === 0) {
    return <p>No runners are configured yet. Add one to let pipelines run a scan.</p>;
  }

  return (
    <ul className="trivy-list trivy-runner-list">
      {runners.map((runner) => {
        const disabled = runner.enabled === false;
        // Precedence: a disabled runner's stripe reports "inactive", not "unlinked" - an
        // administrator does not need a migration warning for a runner nothing can currently
        // select. Otherwise, no database link is the state most worth a glance.
        const stripeTone = disabled ? 'trivy-row-stripe-dim' : runner.database ? 'trivy-row-stripe-ok' : 'trivy-row-stripe-warn';

        return (
          <li key={runner.alias} className={`trivy-row${runner.alias === selectedAlias ? ' trivy-row-selected' : ''}`}>
            <span className={`trivy-row-stripe ${stripeTone}`} aria-hidden="true" />
            <button
              type="button"
              className="trivy-row-main"
              aria-label={`Edit ${runner.alias}`}
              aria-current={runner.alias === selectedAlias ? 'true' : undefined}
              onClick={() => onEdit(runner)}
            >
              <span className="trivy-row-alias">{runner.alias}</span>
              <span className="trivy-row-mono trivy-mono">{runner.image}</span>
              <span className="trivy-row-chips">
                {runner.isDefault ? <span className="trivy-chip trivy-chip-default">Default</span> : null}
                {disabled ? <span className="trivy-chip trivy-chip-disabled">Disabled</span> : null}
                {runner.database ? (
                  <span className="trivy-chip trivy-chip-db">{runner.database}</span>
                ) : (
                  <span className="trivy-chip trivy-chip-dbwarn">
                    Falls back to the deprecated Defaults settings
                  </span>
                )}
              </span>
            </button>
            <button type="button" className="trivy-row-delete" onClick={() => onDelete(runner)}>
              Delete
            </button>
          </li>
        );
      })}
    </ul>
  );
}
