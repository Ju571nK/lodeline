import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import type { InvocationDetail, InvocationEvent } from '@/api/proxies';
import { InvocationDetailView } from './InvocationDetailView';
import { invocation } from './invocation.fixture';

afterEach(cleanup);

function event(sequence: number): InvocationEvent {
  return {
    event_type: sequence === 1 ? 'invocation.started' : 'invocation.cancel_requested',
    event_id: `e-${sequence}`,
    epoch_id: 'ep-1',
    sequence,
    occurred_at: new Date().toISOString(),
    received_at: new Date().toISOString(),
  };
}

function detail(patch: Partial<InvocationDetail> = {}): InvocationDetail {
  return {
    ...invocation({
      actor: {
        actor_id: 'svc-ci',
        actor_kind: 'non_human',
        authentication_method: 'bearer',
        evidence_source: 'proxy_credential_mapping',
        credential_owner_id: 'team-platform',
      },
      tool: { status: 'identified', metadata_ref: 'ref-1' },
    }),
    events_total: 2,
    events_truncated: false,
    events: [event(1), event(2)],
    ...patch,
  };
}

describe('invocation detail', () => {
  it('says the event list is incomplete when the server truncated it', () => {
    const events = Array.from({ length: 32 }, (_, i) => event(i + 1));
    render(
      <InvocationDetailView
        invocation={detail({ events, events_total: 40, events_truncated: true })}
      />,
    );
    expect(screen.getByRole('alert')).toHaveTextContent(
      'This list is incomplete: the server returns at most 32 events of an invocation, and 8 more are not shown.',
    );
    expect(screen.getByText(/^Showing 32 of 40/)).toBeInTheDocument();
    expect(screen.getAllByRole('row')).toHaveLength(33);
  });

  it('shows a complete event list without a notice', () => {
    render(<InvocationDetailView invocation={detail()} />);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.getByText(/^Showing 2 of 2/)).toBeInTheDocument();
    expect(
      screen.getByText('Owns the credential’s permissions. Not the one who ran the call.'),
    ).toBeInTheDocument();
  });

  it.each([
    'completion_without_start',
    'integrity_conflict',
  ] as const)('withholds the outcome of a %s invocation and keeps the claim secondary', (lifecycle) => {
    render(
      <InvocationDetailView
        invocation={detail({
          lifecycle,
          outcome: null,
          delivery_state: null,
          reported_outcome: 'success',
          reported_delivery_state: 'sent',
        })}
      />,
    );
    expect(screen.getByRole('alert')).toHaveTextContent(
      'Do not count this invocation as a success.',
    );
    expect(screen.getByText('Outcome').nextSibling).toHaveTextContent(
      'withheld: no corroborated completion',
    );
    expect(screen.queryByText('Success')).not.toBeInTheDocument();
    expect(screen.getByText('Proxy reported').nextSibling).toHaveTextContent(
      'Proxy reported outcome success, delivery sent. Not corroborated.',
    );
  });

  it('gives a completed invocation without an outcome one answer in the pill and the row', () => {
    render(
      <InvocationDetailView
        invocation={detail({ lifecycle: 'completed', outcome: null, delivery_state: 'sent' })}
      />,
    );
    expect(screen.getByText('Outcome').nextSibling).toHaveTextContent(/^Unknown outcome$/);
    expect(screen.getAllByText('Unknown outcome')).toHaveLength(2);
    expect(screen.queryByText(/withheld/)).not.toBeInTheDocument();
    expect(screen.getByText('Delivery').nextSibling).toHaveTextContent('sent');
  });

  it('renders no control', () => {
    render(<InvocationDetailView invocation={detail()} />);
    expect(screen.queryAllByRole('button')).toHaveLength(0);
    expect(screen.queryAllByRole('textbox')).toHaveLength(0);
  });
});
