import { createFileRoute, Link } from '@tanstack/react-router';
import { ArrowLeft } from 'lucide-react';
import { useRef } from 'react';
import { NotFoundError } from '@/api/client';
import { AlertBadges, AlertDetail, alertTitle } from '@/components/AlertsQueue/AlertDetail';
import { useEventByID } from '@/components/EventDetails';
import { validateAlertsSearch } from '@/lib/alertsSearch';

/**
 * One alert at full width, with its own URL. The search carries the list view
 * it was opened from, so Back returns to the same filters.
 */
export const Route = createFileRoute('/_authed/alerts_/$eventId')({
  validateSearch: validateAlertsSearch,
  component: AlertPage,
});

const NO_ROWS: never[] = [];

function AlertPage() {
  const { eventId } = Route.useParams();
  const search = Route.useSearch();
  const { event, query } = useEventByID(eventId, NO_ROWS);
  const assignInputRef = useRef<HTMLInputElement | null>(null);
  const noteInputRef = useRef<HTMLTextAreaElement | null>(null);

  return (
    <div className="mx-auto max-w-4xl py-4">
      <Link
        to="/alerts"
        search={{ ...search, alert: undefined }}
        className="mb-3 inline-flex items-center gap-1 text-xs text-accent hover:underline"
      >
        <ArrowLeft className="h-3 w-3" aria-hidden />
        Back to alerts
      </Link>
      {event ? (
        <div className="rounded-md border border-border bg-bg-surface px-6 py-5">
          <h1 className="text-lg font-semibold text-text-primary">{alertTitle(event)}</h1>
          <p className="mt-1 text-xs text-text-muted">
            event_id <code className="font-mono [overflow-wrap:anywhere]">{event.event_id}</code>
          </p>
          <div className="mt-2 mb-5">
            <AlertBadges event={event} />
          </div>
          <AlertDetail event={event} assignInputRef={assignInputRef} noteInputRef={noteInputRef} />
        </div>
      ) : query.error instanceof NotFoundError ? (
        <p className="text-sm text-text-body">
          Event unavailable. It may have expired from retention.
        </p>
      ) : query.error ? (
        <div>
          <p role="alert" className="text-sm text-sev-critical">
            Failed to load event: {query.error.message}
          </p>
          <button
            type="button"
            className="mt-2 text-accent"
            disabled={query.isFetching}
            onClick={() => query.refetch()}
          >
            Retry event
          </button>
        </div>
      ) : (
        <p role="status" className="text-sm text-text-muted">
          Loading event…
        </p>
      )}
    </div>
  );
}
