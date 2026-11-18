import { useEffect, useRef, useState } from 'react';
import type { EventWithTriage } from '@/api/fleet';
import type { AlertGroup, SortMode } from '@/lib/alertGroups';
import { QueueRow } from './QueueRow';

interface Props {
  /** Rows in display order; the route sorts them. */
  groups: AlertGroup[];
  selectedEventID: string | null;
  onSelect: (event: EventWithTriage) => void;
  onRowHoverEnter: () => void;
  onRowHoverLeave: () => void;
  sort: SortMode;
  onSortChange: (next: SortMode) => void;
  /** True before the first successful fetch — show skeleton rows. */
  isPending?: boolean;
  /** True if the visible row set is empty because filters excluded everything. */
  filtersActive?: boolean;
  partialResults?: boolean;
  /** When the empty state is filter-driven, this resets the filter to defaults. */
  onResetFilters?: () => void;
}

/**
 * 28px-density alerts table per UI/UX §6.4 with sticky header. The route
 * groups and sorts the rows (UI/UX §7.2: default severity desc, then age desc);
 * clicking a sortable column header toggles its direction (severity desc only,
 * no asc for severity in v1).
 *
 * Rows that appear on this render but weren't in the previous render get
 * `isFresh=true` for one flash-cycle, driving a 1s box-shadow fade-in.
 */
export function QueueTable({
  groups,
  selectedEventID,
  onSelect,
  onRowHoverEnter,
  onRowHoverLeave,
  sort,
  onSortChange,
  isPending,
  filtersActive,
  partialResults,
  onResetFilters,
}: Props) {
  const previousIDs = useRef<Set<string>>(new Set());
  const [freshIDs, setFreshIDs] = useState<Set<string>>(new Set());

  useEffect(() => {
    const incoming = new Set(groups.map((g) => g.latest.event_id));
    const newOnes = new Set<string>();
    for (const id of incoming) {
      if (!previousIDs.current.has(id)) newOnes.add(id);
    }
    if (newOnes.size > 0 && previousIDs.current.size > 0) {
      setFreshIDs(newOnes);
      const t = setTimeout(() => setFreshIDs(new Set()), 1100);
      previousIDs.current = incoming;
      return () => clearTimeout(t);
    }
    previousIDs.current = incoming;
  }, [groups]);

  return (
    <div className="flex flex-col overflow-hidden rounded-md border border-border bg-bg-surface">
      <Header sort={sort} onSortChange={onSortChange} />
      <div className="max-h-[calc(100vh-220px)] overflow-y-auto">
        {isPending ? (
          <SkeletonRows />
        ) : groups.length === 0 ? (
          <EmptyHint
            partialResults={partialResults}
            filtersActive={filtersActive}
            onResetFilters={onResetFilters}
          />
        ) : (
          groups.map((group) => (
            <QueueRow
              key={group.key}
              group={group}
              selected={group.events.some((ev) => ev.event_id === selectedEventID)}
              onSelect={onSelect}
              onHoverEnter={onRowHoverEnter}
              onHoverLeave={onRowHoverLeave}
              isFresh={freshIDs.has(group.latest.event_id)}
            />
          ))
        )}
      </div>
    </div>
  );
}

function Header({
  sort,
  onSortChange,
}: {
  sort: SortMode;
  onSortChange: (next: SortMode) => void;
}) {
  return (
    <div className="grid h-[28px] w-full grid-cols-[16px_64px_minmax(0,1fr)_140px_72px_92px_120px] items-center gap-3 border-b border-border bg-bg-elevated px-3 text-[10px] uppercase tracking-wide text-text-subtle">
      <span aria-hidden />
      <button
        type="button"
        onClick={() => onSortChange(sort === 'age_desc' ? 'age_asc' : 'age_desc')}
        className="text-left hover:text-text-primary"
      >
        Age {sort === 'age_desc' ? '↓' : sort === 'age_asc' ? '↑' : ''}
      </button>
      <span>Event</span>
      <span>Host</span>
      <button
        type="button"
        onClick={() => onSortChange('severity_desc')}
        className="text-left hover:text-text-primary"
      >
        Severity {sort === 'severity_desc' ? '↓' : ''}
      </button>
      <span>Status</span>
      <span>Assignee</span>
    </div>
  );
}

function EmptyHint({
  filtersActive,
  partialResults,
  onResetFilters,
}: {
  filtersActive?: boolean;
  partialResults?: boolean;
  onResetFilters?: () => void;
}) {
  if (partialResults)
    return (
      <p className="p-6 text-sm text-text-muted">
        No matching alerts in loaded results. Load more to continue searching.
      </p>
    );
  if (filtersActive) {
    return (
      <div className="flex h-32 flex-col items-center justify-center gap-2 text-sm text-text-subtle">
        <span>No alerts match the current filters.</span>
        {onResetFilters && (
          <button
            type="button"
            onClick={onResetFilters}
            className="text-xs text-accent underline-offset-2 hover:underline"
          >
            Reset filters
          </button>
        )}
      </div>
    );
  }
  // Genuinely empty (no alerts at all under current filters) — celebrate
  // until UI/UX D2's "last incident N days ago" data is available
  // (Plan 04 host-detail will provide last-seen severity history).
  return (
    <div className="flex h-32 items-center justify-center text-sm text-text-muted">
      <span>🎉 No open alerts.</span>
    </div>
  );
}

/**
 * Five 28px skeleton rows with a shimmer animation while the first fetch
 * is in flight. Subsequent polling refreshes don't show this — the
 * FreshnessIndicator surfaces "Refreshing…" instead so the queue doesn't
 * jump.
 */
function SkeletonRows() {
  return (
    <div aria-hidden="true">
      {Array.from({ length: 5 }).map((_, i) => (
        <div
          // biome-ignore lint/suspicious/noArrayIndexKey: positional placeholder, no identity
          key={i}
          className="grid h-[28px] w-full grid-cols-[16px_64px_minmax(0,1fr)_140px_72px_92px_120px] items-center gap-3 border-b border-border-subtle px-3"
        >
          <span className="block h-2 w-2 rounded-full bg-bg-elevated" />
          <span className="block h-2 w-12 animate-pulse rounded bg-bg-elevated" />
          <span className="block h-2 w-3/4 animate-pulse rounded bg-bg-elevated" />
          <span className="block h-2 w-24 animate-pulse rounded bg-bg-elevated" />
          <span className="block h-2 w-10 animate-pulse rounded bg-bg-elevated" />
          <span className="block h-2 w-14 animate-pulse rounded bg-bg-elevated" />
          <span className="block h-2 w-16 animate-pulse rounded bg-bg-elevated" />
        </div>
      ))}
    </div>
  );
}
