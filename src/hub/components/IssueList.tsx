import * as React from 'react';
import { ValidationIssue } from '../../shared/validation';

/**
 * Renders the issues returned by the shared validation rules - the same rules the pipeline task
 * applies - so a form cannot accept a document the task would later reject.
 */
export function IssueList({ issues }: { issues: ValidationIssue[] }): JSX.Element | null {
  if (issues.length === 0) {
    return null;
  }

  return (
    <div role="alert" className="trivy-issues">
      {issues.map((issue, index) => (
        <div key={`${index}:${issue.field}`}>
          <strong>{issue.field}</strong>: {issue.message}
        </div>
      ))}
    </div>
  );
}
