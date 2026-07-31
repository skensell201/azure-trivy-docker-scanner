import * as React from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { PolicyForm } from '../components/PolicyForm';
import { DefaultsConfig } from '../../shared/types';

describe('PolicyForm', () => {
  it('treats an absent allowOverrides as everything allowed', () => {
    render(<PolicyForm defaults={{ dbRepository: 'x:1' }} onSave={jest.fn()} />);
    for (const box of screen.getAllByRole('checkbox')) {
      expect((box as HTMLInputElement).checked).toBe(true);
    }
  });

  it('treats an empty allowOverrides as nothing allowed', () => {
    render(<PolicyForm defaults={{ dbRepository: 'x:1', allowOverrides: [] }} onSave={jest.fn()} />);
    for (const box of screen.getAllByRole('checkbox')) {
      expect((box as HTMLInputElement).checked).toBe(false);
    }
  });

  it('explains that the two states mean opposite things', () => {
    render(<PolicyForm defaults={{ dbRepository: 'x:1' }} onSave={jest.fn()} />);
    expect(screen.getByText(/every field.*overridden|nothing/i)).toBeTruthy();
  });

  it('offers a checkbox for each overridable field', () => {
    render(<PolicyForm defaults={{ dbRepository: 'x:1' }} onSave={jest.fn()} />);
    expect(screen.getAllByRole('checkbox')).toHaveLength(10);
    expect(screen.getByLabelText(/extraTrivyArgs/)).toBeTruthy();
    expect(screen.getByLabelText(/useDockerSocket/)).toBeTruthy();
  });

  it('warns which fields let a pipeline defeat the gate if left open', () => {
    // The three gate-defeating fields now also get a fieldset legend naming them as a group
    // ("Fields that can defeat the other locks"), which - deliberately - also contains the word
    // "defeat"; the original `getByText(/extraTrivyArgs.*ignoreFile|defeat/i)` query now matches
    // both the legend and the full explanation paragraph, so this is tightened to a direct,
    // real-class lookup of the explanation paragraph rather than loosened to allow either match.
    const { container } = render(<PolicyForm defaults={{ dbRepository: 'x:1' }} onSave={jest.fn()} />);
    const warning = container.querySelector('.trivy-policy-group-critical .trivy-warning');
    expect(warning?.textContent).toMatch(/extraTrivyArgs/);
    expect(warning?.textContent).toMatch(/ignoreFile/);
    expect(warning?.textContent).toMatch(/useDockerSocket/);
    expect(warning?.textContent).toMatch(/defeat/i);
  });

  it('groups the three gate-defeating fields into their own labelled fieldset, saying why', () => {
    render(<PolicyForm defaults={{ dbRepository: 'x:1' }} onSave={jest.fn()} />);
    // A <fieldset> has an implicit "group" role, named by its <legend> - so this both confirms
    // the fields are grouped in a fieldset and that the fieldset itself explains why.
    const group = screen.getByRole('group', { name: /defeat the other locks/i });
    expect(group.textContent).toMatch(/extraTrivyArgs/);
    expect(group.textContent).toMatch(/ignoreFile/);
    expect(group.textContent).toMatch(/useDockerSocket/);
    // The other seven fields are not inside this same group.
    expect(group.textContent).not.toMatch(/severities/);
  });

  it('saves an explicit list rather than relying on absence', async () => {
    const onSave = jest.fn();
    render(<PolicyForm defaults={{ dbRepository: 'x:1' }} onSave={onSave} />);
    await userEvent.click(screen.getByLabelText(/extraTrivyArgs/));
    await userEvent.click(screen.getByRole('button', { name: /save/i }));
    const saved = onSave.mock.calls[0][0] as DefaultsConfig;
    expect(Array.isArray(saved.allowOverrides)).toBe(true);
    expect(saved.allowOverrides).not.toContain('extraTrivyArgs');
    expect(saved.allowOverrides).toContain('severities');
  });

  it('preserves the rest of the defaults document', async () => {
    const onSave = jest.fn();
    render(
      <PolicyForm defaults={{ dbRepository: 'reg:1', failOn: 'HIGH' }} onSave={onSave} />,
    );
    await userEvent.click(screen.getByRole('button', { name: /save/i }));
    expect(onSave).toHaveBeenCalledWith(
      expect.objectContaining({ dbRepository: 'reg:1', failOn: 'HIGH' }),
    );
  });
});
