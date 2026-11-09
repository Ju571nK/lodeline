import { cleanup, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { ProxyDetailView } from './ProxyDetailView';
import { ago, proxyDetail as detail } from './proxy.fixture';

afterEach(cleanup);

describe('proxy detail', () => {
  it('labels a degraded spool as the ingest stop, not a storage fault, while ingest is stopped', () => {
    render(<ProxyDetailView proxy={detail()} />);
    expect(screen.getByText('Degraded: ingest stopped')).toBeInTheDocument();
    expect(screen.getByText(/This is not a storage fault\./)).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent(/^Ingest stopped:/);
  });

  it('keeps a plain degraded spool when ingest is not stopped, or the proxy predates the flag', () => {
    const { central } = detail();
    for (const c of [{ ...central!, ingest_stopped: undefined }, null]) {
      render(<ProxyDetailView proxy={detail({ central: c })} />);
      expect(screen.getByText('Spool state').nextSibling).toHaveTextContent(/^Degraded$/);
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
      expect(screen.queryByText(/not a storage fault/)).not.toBeInTheDocument();
      cleanup();
    }
  });

  it('shows quarantined bytes next to the depth, and unknown for an older proxy', () => {
    render(<ProxyDetailView proxy={detail()} />);
    expect(screen.getByText('1840 events, 1835 unsent')).toBeInTheDocument();
    expect(screen.getByText('8 events, 40 KiB')).toBeInTheDocument();
    cleanup();
    const older = detail();
    render(
      <ProxyDetailView proxy={{ ...older, spool: { ...older.spool!, quarantined_bytes: null } }} />,
    );
    expect(screen.getByText('8 events, unknown (older proxy)')).toBeInTheDocument();
  });

  it('says the gap list is incomplete when the server dropped gaps', () => {
    render(<ProxyDetailView proxy={detail({ audit_gaps_dropped: 3 })} />);
    expect(
      screen.getByText(/This gap list is incomplete: the server dropped 3 inventory gap records/),
    ).toBeInTheDocument();
    cleanup();
    render(<ProxyDetailView proxy={detail({ audit_gaps_dropped: 0 })} />);
    expect(screen.queryByText(/gap list is incomplete/)).not.toBeInTheDocument();
  });

  it('shows the registry counters a proxy reports and leaves out the ones it does not', () => {
    render(<ProxyDetailView proxy={detail()} />);
    expect(screen.queryByText('Discarded reports')).not.toBeInTheDocument();
    cleanup();
    render(
      <ProxyDetailView
        proxy={detail({
          registry: {
            pending_entries: 3,
            sync_stalled: true,
            quarantined_entries: 1,
            poisoned_entries: 0,
            discarded_reports: 4,
          },
        })}
      />,
    );
    const row = screen.getByText('Discarded reports').closest('div')!;
    expect(within(row).getByText('4')).toBeInTheDocument();
    expect(screen.getByText('Paused (refused)')).toBeInTheDocument();
  });

  it('puts the report time and open gaps beside the connection state', () => {
    render(<ProxyDetailView proxy={detail()} />);
    const cell = screen.getByText('Connected').parentElement!;
    expect(cell).toHaveTextContent('2 open gaps');
    expect(cell).toHaveTextContent(/status as of .*\(20 seconds ago\)/);
  });

  it('shows desired and applied revisions, sync, the disabled state and the expiry', () => {
    render(
      <ProxyDetailView proxy={detail({ config_state: 'disabled', config_expires_at: ago(300) })} />,
    );
    expect(screen.getByText('Desired revision').nextSibling).toHaveTextContent('8');
    expect(screen.getByText('Applied revision').nextSibling).toHaveTextContent('7');
    expect(screen.getByText('In sync').nextSibling).toHaveTextContent('No');
    expect(screen.getByText('Disabled')).toBeInTheDocument();
    expect(screen.getByText('Config expires').nextSibling).toHaveTextContent('(5 minutes ago)');
  });

  it('reads a state from a newer server as unknown', () => {
    render(<ProxyDetailView proxy={detail({ connection_state: 'unknown' })} />);
    expect(screen.getAllByText('Unknown (newer server)')).toHaveLength(1);
  });

  it('renders upstream strings as text and has no control at all', () => {
    const markup = '<img src=x onerror="window.pwned=1">';
    const { container } = render(
      <ProxyDetailView
        proxy={detail({
          display_name: markup,
          routes: [{ upstream_id: markup, state: 'supported' }],
        })}
      />,
    );
    expect(screen.getByRole('heading', { name: markup })).toBeInTheDocument();
    expect(container.querySelector('img')).toBeNull();
    expect(screen.queryAllByRole('button')).toHaveLength(0);
    expect(screen.queryAllByRole('link')).toHaveLength(0);
    expect(container.querySelector('form, input, select, textarea')).toBeNull();
  });
});
