import { Link } from '@tanstack/react-router';
import type { ReactNode } from 'react';
import {
  type DriftRecord,
  fleetInventory,
  type InventoryRows,
  type InventoryScope,
  type InventorySnapshot,
  type InventoryView,
  type ProxyDetail,
  type RebaselineMarker,
} from '@/api/proxies';
import { Pagination } from '@/components/Fleet/Pagination';
import { SkeletonRows } from '@/components/Fleet/SkeletonRows';
import { Card, Empty } from '@/components/Host/HostMetaCard';
import { usePagedFleet } from '@/hooks/usePagedFleet';
import {
  driftChangeLabel,
  driftChangeTone,
  markerCauseLabel,
  markerCauseTone,
  snapshotComparison,
} from '@/lib/proxy';
import { cn } from '@/lib/utils';
import { ProxyReadError, Table, TonePill, When } from './ProxyParts';

interface ViewInfo<V extends InventoryView> {
  label: string;
  intro: string;
  empty: string;
  id: (row: InventoryRows[V]) => string;
  Rows: (props: { rows: InventoryRows[V][] }) => ReactNode;
}

const VIEWS: { [V in InventoryView]: ViewInfo<V> } = {
  'inventory-snapshots': {
    label: 'Snapshots',
    intro:
      'Complete observations of each upstream’s tool list, newest first. A chain is one upstream, credential scope, protocol version and observation source, and the server never compares two chains.',
    empty: 'No snapshots.',
    id: (s) => s.inventory_id,
    Rows: SnapshotTable,
  },
  drift: {
    label: 'Drift',
    intro:
      'Changes the proxy observed between two snapshots of a chain, newest first. A drift record is an observed change, not an approval: nobody reviewed or accepted it.',
    empty: 'No drift observed.',
    id: (d) => d.drift_id,
    Rows: DriftTable,
  },
  'rebaseline-markers': {
    label: 'Re-baseline markers',
    intro:
      'Places where a chain’s baseline was reset, for example by a key rotation, newest first. The server derives no drift across a marker.',
    empty: 'No re-baseline markers.',
    id: (m) => m.marker_id,
    Rows: MarkerTable,
  },
};

/** The views in tab order. */
export const inventoryViews = Object.keys(VIEWS) as InventoryView[];

/**
 * A proxy's inventory reads, one view at a time. References, counts and identifiers only: the
 * server returns no tool name or definition, and the console fetches none. Read only.
 */
export function InventorySection({ proxy, view }: { proxy: ProxyDetail; view: InventoryView }) {
  const incomplete = proxy.open_gap_counts.inventory_incomplete ?? 0;
  return (
    <Card title="Inventory">
      <nav aria-label="Inventory views" className="mb-3 flex gap-1 border-b border-border-subtle">
        {inventoryViews.map((v) => (
          <Link
            key={v}
            to="/proxies/$proxyId"
            params={{ proxyId: proxy.proxy_id }}
            search={{ inventory: v }}
            aria-current={v === view ? 'page' : undefined}
            className={cn(
              '-mb-px border-b-2 px-3 py-1.5 text-xs transition-colors',
              v === view
                ? 'border-accent text-text-primary'
                : 'border-transparent text-text-muted hover:text-text-primary',
            )}
          >
            {VIEWS[v].label}
          </Link>
        ))}
      </nav>
      <p className="mb-2 text-xs text-text-muted">
        {VIEWS[view].intro} Rows carry references and counts, never tool names.
      </p>
      {view === 'inventory-snapshots' && (
        <p className="mb-2 text-xs">
          Incomplete observations are not snapshots. The server lists each one as an Inventory
          incomplete audit gap above: {incomplete} on this proxy
          {proxy.audit_gaps_dropped > 0 && ', and the gap list is incomplete'}.
        </p>
      )}
      <InventoryList key={view} proxyId={proxy.proxy_id} view={view} />
    </Card>
  );
}

function InventoryList<V extends InventoryView>({ proxyId, view }: { proxyId: string; view: V }) {
  const info: ViewInfo<V> = VIEWS[view];
  const page = usePagedFleet(
    ['proxies', 'inventory', proxyId, view],
    (cursor, signal) => fleetInventory(proxyId, view, { cursor, limit: 100 }, signal),
    selectItems,
    info.id,
  );
  return (
    <div className="rounded-md border border-border-subtle">
      {page.isPending ? (
        <SkeletonRows count={3} />
      ) : page.rows.length === 0 && page.error ? (
        <ProxyReadError error={page.error} what={info.label.toLowerCase()} target="inventory" />
      ) : page.rows.length === 0 ? (
        <div className="p-3">
          <Empty>{info.empty}</Empty>
        </div>
      ) : (
        <info.Rows rows={page.rows} />
      )}
      {!page.isPending && (page.rows.length > 0 || !page.error) && (
        <Pagination {...page} count={page.rows.length} />
      )}
    </div>
  );
}

const selectItems = <T,>(page: { items: T[] }) => page.items;

const cell = 'px-2 py-1.5';
const id = 'font-mono text-[11px] break-all';

function Chain({ row }: { row: InventoryScope }) {
  return (
    <td className={cell}>
      <span className="font-mono">{row.upstream_id}</span>
      <div className="font-mono text-[11px] text-text-muted">{row.credential_scope_id}</div>
      <div className="text-text-muted">
        {row.protocol_version}, {row.observation_source}
      </div>
    </td>
  );
}

function Pair({ from, to }: { from: ReactNode; to: ReactNode }) {
  return (
    <>
      <div className="text-text-muted">{from}</div>
      <div>→ {to}</div>
    </>
  );
}

export function SnapshotTable({ rows }: { rows: InventorySnapshot[] }) {
  return (
    <Table head={['Received', 'Chain', 'Snapshot', 'Members', 'Comparison', 'Key']}>
      {rows.map((s) => {
        const cmp = snapshotComparison(s);
        return (
          <tr key={s.inventory_id} className="border-t border-border-subtle align-top">
            <td className={cn(cell, 'whitespace-nowrap')}>
              <When ts={s.received_at} />
              <div className="text-text-muted">
                observed <When ts={s.observed_at} />, proxy clock
              </div>
            </td>
            <Chain row={s} />
            <td className={cn(cell, id)}>{s.inventory_id}</td>
            <td className={cell}>{s.member_count}</td>
            <td className={cell}>
              <TonePill tone={cmp.tone}>{cmp.label}</TonePill>
              {s.is_latest && <span className="text-text-muted"> latest</span>}
              {cmp.note && <div className="mt-1 text-text-muted">{cmp.note}</div>}
            </td>
            <td className={cell}>
              <span className={id}>{s.key_id}</span>
              <div className="text-text-muted">{s.canon}</div>
            </td>
          </tr>
        );
      })}
    </Table>
  );
}

export function DriftTable({ rows }: { rows: DriftRecord[] }) {
  return (
    <Table head={['Detected', 'Chain', 'Observed change', 'Reference', 'Snapshots']}>
      {rows.map((d) => (
        <tr key={d.drift_id} className="border-t border-border-subtle align-top">
          <td className={cn(cell, 'whitespace-nowrap')}>
            <When ts={d.detected_at} />
          </td>
          <Chain row={d} />
          <td className={cell}>
            <TonePill tone={driftChangeTone[d.change]}>{driftChangeLabel[d.change]}</TonePill>
          </td>
          <td className={cn(cell, id)}>
            {d.previous_metadata_ref ? (
              <Pair from={d.previous_metadata_ref} to={d.metadata_ref} />
            ) : (
              d.metadata_ref
            )}
          </td>
          <td className={cn(cell, id)}>
            <Pair from={d.previous_inventory_id} to={d.inventory_id} />
          </td>
        </tr>
      ))}
    </Table>
  );
}

export function MarkerTable({ rows }: { rows: RebaselineMarker[] }) {
  return (
    <Table head={['Detected', 'Chain', 'Cause', 'Key', 'Canon', 'Links', 'Snapshots']}>
      {rows.map((m) => (
        <tr key={m.marker_id} className="border-t border-border-subtle align-top">
          <td className={cn(cell, 'whitespace-nowrap')}>
            <When ts={m.detected_at} />
          </td>
          <Chain row={m} />
          <td className={cell}>
            <TonePill tone={markerCauseTone[m.cause]}>{markerCauseLabel[m.cause]}</TonePill>
          </td>
          <td className={cn(cell, id)}>
            <Pair from={m.from_key_id} to={m.to_key_id} />
          </td>
          <td className={cell}>
            <Pair from={m.from_canon} to={m.to_canon} />
          </td>
          <td className={cell}>{m.links_present ? 'Yes' : 'No'}</td>
          <td className={cn(cell, id)}>
            <Pair from={m.previous_inventory_id ?? 'none'} to={m.inventory_id} />
          </td>
        </tr>
      ))}
    </Table>
  );
}
