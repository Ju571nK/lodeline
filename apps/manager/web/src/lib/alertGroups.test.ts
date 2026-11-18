import { describe, expect, it } from 'vitest';
import type { EventWithTriage, ReasonLike, Scope } from '@/api/fleet';
import { alertTitleReason, groupAlerts, sortAlertGroups } from './alertGroups';

let seq = 0;

function alert(over: {
  ts?: string;
  host?: string;
  tool?: string;
  scope?: Scope;
  user?: string;
  reasons?: ReasonLike[];
  bucket?: 'high' | 'critical';
  status?: 'open' | 'acknowledged' | 'investigating' | 'resolved' | null;
}): EventWithTriage {
  seq += 1;
  return {
    schema_version: 1,
    event_id: `ev-${seq}`,
    ts: over.ts ?? '2026-11-18T10:00:00Z',
    host_id: over.host ?? 'host-a',
    agent_version: '0.18.0',
    severity: 'warn',
    source: { kind: 'file_system' },
    subject: {},
    target_id: null,
    evidence: {
      kind: 'ai_guard_risk_assessed',
      tool: over.tool ?? 'claude_code',
      scope: over.scope ?? { kind: 'user_global' },
      ...(over.user ? { user: over.user } : {}),
      score: 5,
      bucket: over.bucket ?? 'high',
      reasons: over.reasons ?? [{ kind: 'no_sandbox', executor: 'bash' }],
      is_reattestation: false,
    },
    triage:
      over.status && over.status !== 'open'
        ? { status: over.status, assignee: null, updated_at: '2026-11-18T10:05:00Z' }
        : null,
  };
}

describe('groupAlerts', () => {
  it('collapses repeats of one host, tool, scope, user and reason set into one group', () => {
    const first = alert({ ts: '2026-11-18T10:00:00Z' });
    const second = alert({ ts: '2026-11-18T10:00:49Z' });
    const groups = groupAlerts([second, first]);
    expect(groups).toHaveLength(1);
    expect(groups[0].count).toBe(2);
    expect(groups[0].latest.event_id).toBe(second.event_id);
    expect(groups[0].events.map((e) => e.event_id)).toEqual([second.event_id, first.event_id]);
  });

  it('keeps the latest event as the representative whatever the input order', () => {
    const older = alert({ ts: '2026-11-18T09:00:00Z' });
    const newer = alert({ ts: '2026-11-18T10:00:00Z' });
    expect(groupAlerts([older, newer])[0].latest.event_id).toBe(newer.event_id);
  });

  it('does not match reasons by order', () => {
    const a: ReasonLike = { kind: 'no_sandbox', executor: 'bash' };
    const b: ReasonLike = { kind: 'sandbox_disabled' };
    expect(groupAlerts([alert({ reasons: [a, b] }), alert({ reasons: [b, a] })])).toHaveLength(1);
  });

  it('does not match reasons by object key order', () => {
    const one = alert({ reasons: [{ kind: 'no_sandbox', executor: 'bash', snippet: 'x' }] });
    const two = alert({ reasons: [{ snippet: 'x', executor: 'bash', kind: 'no_sandbox' }] });
    expect(groupAlerts([one, two])).toHaveLength(1);
  });

  it.each([
    ['host', { host: 'host-b' }],
    ['tool', { tool: 'codex' }],
    ['user', { user: 'alice' }],
    ['project scope', { scope: { kind: 'project', path: '/work/api' } as Scope }],
    ['reason detail', { reasons: [{ kind: 'no_sandbox', executor: 'zsh' }] }],
    ['reason kind', { reasons: [{ kind: 'sandbox_disabled' }] }],
  ])('keeps rows apart when the %s differs', (_name, over) => {
    expect(groupAlerts([alert({}), alert(over)])).toHaveLength(2);
  });

  it('keeps two project scopes with different paths apart', () => {
    const a = alert({ scope: { kind: 'project', path: '/work/a' } });
    const b = alert({ scope: { kind: 'project', path: '/work/b' } });
    expect(groupAlerts([a, b])).toHaveLength(2);
  });

  it('keeps an event with another triage status as its own row, so no status is hidden', () => {
    const open = alert({ ts: '2026-11-18T10:00:49Z' });
    const acked = alert({ ts: '2026-11-18T10:00:00Z', status: 'acknowledged' });
    const groups = groupAlerts([open, acked]);
    expect(groups).toHaveLength(2);
    expect(groups.map((g) => g.latest.triage?.status ?? 'open').sort()).toEqual([
      'acknowledged',
      'open',
    ]);
  });

  it('treats an untriaged event and an explicit open event as the same status', () => {
    const untriaged = alert({});
    const open = alert({});
    open.triage = { status: 'open', assignee: null, updated_at: '2026-11-18T10:05:00Z' };
    expect(groupAlerts([untriaged, open])).toHaveLength(1);
  });

  it('keeps events with another assignee apart', () => {
    const a = alert({ status: 'investigating' });
    const b = alert({ status: 'investigating' });
    if (a.triage) a.triage.assignee = 'alice';
    if (b.triage) b.triage.assignee = 'bob';
    expect(groupAlerts([a, b])).toHaveLength(2);
  });

  it('never groups an event that is not an AI Guard risk assessment', () => {
    const base = alert({});
    const hb = (id: string): EventWithTriage => ({
      ...base,
      event_id: id,
      evidence: { kind: 'heartbeat' },
    });
    expect(groupAlerts([hb('h1'), hb('h2')])).toHaveLength(2);
  });

  it('groups an assessment with no reasons with another one', () => {
    expect(groupAlerts([alert({ reasons: [] }), alert({ reasons: [] })])).toHaveLength(1);
  });
});

describe('sortAlertGroups', () => {
  it('orders by severity then latest time, and by age in both directions', () => {
    const high = alert({ bucket: 'high', ts: '2026-11-18T12:00:00Z', tool: 'codex' });
    const crit = alert({ bucket: 'critical', ts: '2026-11-18T08:00:00Z', tool: 'cursor' });
    const old = alert({ bucket: 'high', ts: '2026-11-18T09:00:00Z', tool: 'gemini' });
    const groups = groupAlerts([old, high, crit]);
    const ids = (m: Parameters<typeof sortAlertGroups>[1]) =>
      sortAlertGroups(groups, m).map((g) => g.latest.event_id);
    expect(ids('severity_desc')).toEqual([crit.event_id, high.event_id, old.event_id]);
    expect(ids('age_desc')).toEqual([high.event_id, old.event_id, crit.event_id]);
    expect(ids('age_asc')).toEqual([crit.event_id, old.event_id, high.event_id]);
  });
});

describe('alertTitleReason', () => {
  it('picks the heaviest reason, not the first one emitted', () => {
    const reasons: ReasonLike[] = [
      { kind: 'mcp_server_local_command' },
      { kind: 'destructive_in_inline_command' },
      { kind: 'no_sandbox' },
    ];
    expect(alertTitleReason(reasons)?.kind).toBe('destructive_in_inline_command');
  });

  it('keeps emit order between reasons of equal weight', () => {
    const reasons: ReasonLike[] = [{ kind: 'mcp_launcher_shell' }, { kind: 'sandbox_disabled' }];
    expect(alertTitleReason(reasons)?.kind).toBe('mcp_launcher_shell');
  });

  it('ranks a kind with no known weight below every weighted kind', () => {
    const reasons: ReasonLike[] = [{ kind: 'a_future_kind' }, { kind: 'mcp_server_local_command' }];
    expect(alertTitleReason(reasons)?.kind).toBe('mcp_server_local_command');
  });

  it('falls back to the first reason when no kind has a known weight', () => {
    expect(alertTitleReason([{ kind: 'x_new' }, { kind: 'y_new' }])?.kind).toBe('x_new');
  });

  it('returns undefined for no reasons', () => {
    expect(alertTitleReason([])).toBeUndefined();
    expect(alertTitleReason(undefined)).toBeUndefined();
  });
});
