import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { NotFoundError } from '@/api/client';
import {
  appendNote,
  getTriage,
  type NotePayload,
  type TriageDetail,
  type TriageStatus,
  type UpsertPayload,
  upsertTriage,
} from '@/api/triage';

/** Triage mutations refresh all event views, including directly linked details. */

export function useTriageDetail(hostID: string | null, eventID: string | null) {
  return useQuery({
    queryKey: ['triage', hostID, eventID],
    queryFn: () => {
      if (!hostID || !eventID) throw new Error('hook called without ids');
      return getTriage(hostID, eventID);
    },
    enabled: !!hostID && !!eventID,
    // Triage row may not exist yet — surface NotFoundError as data:null
    // rather than spamming the boundary every time the user opens an
    // un-actioned alert.
    retry: (failureCount, error) => {
      if (error instanceof NotFoundError) return false;
      return failureCount < 2;
    },
  });
}

/** Raised when some writes of a group change failed; `failed` holds those event ids. */
export class GroupTriageError extends Error {
  readonly failed: string[];

  constructor(failed: string[], total: number, reason: string) {
    super(
      total === 1
        ? reason
        : `${failed.length} of ${total} events not saved (${failed.join(', ')}): ${reason}`,
    );
    this.name = 'GroupTriageError';
    this.failed = failed;
  }
}

/**
 * Applies one triage change to every event of an alert row. The events of a collapsed row share
 * status and assignee, so each write goes through the per event upsert. Every write is tried, and
 * the event views refetch whatever the outcome, so the list shows what the server holds.
 */
export function useUpsertTriage() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (payloads: UpsertPayload[]) => {
      const results = await Promise.allSettled(payloads.map(upsertTriage));
      const failed: string[] = [];
      let reason = '';
      results.forEach((r, i) => {
        if (r.status === 'fulfilled') return;
        failed.push(payloads[i].event_id);
        reason ||= r.reason instanceof Error && r.reason.message ? r.reason.message : 'try again';
      });
      if (failed.length > 0) throw new GroupTriageError(failed, payloads.length, reason);
    },
    onSettled: (_data, _error, payloads) => {
      for (const p of payloads) {
        qc.invalidateQueries({ queryKey: ['triage', p.host_id, p.event_id] });
        qc.invalidateQueries({ queryKey: ['fleet', 'event', p.event_id] });
      }
      qc.invalidateQueries({ queryKey: ['fleet', 'events'] });
      qc.invalidateQueries({ queryKey: ['fleet', 'events-timeline'] });
    },
  });
}

export function useAppendNote() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: NotePayload) => appendNote(payload),
    onSuccess: (note) => {
      qc.invalidateQueries({ queryKey: ['triage', note.host_id, note.event_id] });
    },
  });
}

/**
 * Convenience: full triage detail with NotFoundError flattened into
 * data===null + error===null. Slide-over callers can then `if (!detail)`
 * branch into the "no triage yet" state without juggling error types.
 */
export function useTriageDetailOrNull(
  hostID: string | null,
  eventID: string | null,
): { data: TriageDetail | null; isPending: boolean; status: TriageStatus | null } {
  const q = useTriageDetail(hostID, eventID);
  if (q.error instanceof NotFoundError) {
    return { data: null, isPending: false, status: 'open' };
  }
  return {
    data: q.data ?? null,
    isPending: q.isPending,
    status: q.data?.row.status ?? null,
  };
}
