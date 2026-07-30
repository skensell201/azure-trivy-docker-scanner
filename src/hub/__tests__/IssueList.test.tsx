import * as React from 'react';
import { render, screen } from '@testing-library/react';
import { IssueList } from '../components/IssueList';

describe('IssueList', () => {
  it('renders nothing when there are no issues', () => {
    const { container } = render(<IssueList issues={[]} />);
    expect(container.innerHTML).toBe('');
  });

  it('shows one line per issue, naming the field', () => {
    render(
      <IssueList
        issues={[
          { field: 'alias', message: 'Alias must be lowercase.' },
          { field: 'image', message: 'Image reference is required.' },
        ]}
      />,
    );
    expect(screen.getByText(/Alias must be lowercase\./)).toBeTruthy();
    expect(screen.getByText(/Image reference is required\./)).toBeTruthy();
    expect(screen.getByText('alias')).toBeTruthy();
    expect(screen.getByText('image')).toBeTruthy();
  });

  it('marks itself as an alert so a screen reader announces a failed save', () => {
    render(<IssueList issues={[{ field: 'alias', message: 'bad' }]} />);
    expect(screen.getByRole('alert')).toBeTruthy();
  });

  it('keeps two issues on the same field distinct', () => {
    render(
      <IssueList
        issues={[
          { field: 'image', message: 'Image must carry an explicit tag.' },
          { field: 'image', message: 'extraDockerArgs must be a string.' },
        ]}
      />,
    );
    expect(screen.getByRole('alert').children).toHaveLength(2);
  });
});
