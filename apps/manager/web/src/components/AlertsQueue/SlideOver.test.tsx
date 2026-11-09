import '@testing-library/jest-dom/vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { EventWithTriage, Evidence } from '@/api/fleet';
import { SlideOver } from './SlideOver';

beforeEach(() => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response('{"error":{"code":"not_found"}}', { status: 404 })),
  );
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const scope = { kind: 'user_global' };
const riskAssessed = {
  kind: 'ai_guard_risk_assessed',
  tool: 'claude_code',
  scope,
  score: 7.2,
  bucket: 'critical',
  reasons: [],
  is_reattestation: false,
};
const toggleDrift = {
  kind: 'ai_guard_toggle_drift',
  tool: 'claude_code',
  scope,
  toggle: 'auto_approval_enabled',
  rule_pack_id: 'acme-extended',
};

function renderDetail(evidence: Evidence) {
  const event: EventWithTriage = {
    schema_version: 1,
    event_id: 'e1',
    ts: '2026-11-09T00:00:00Z',
    host_id: 'h1',
    agent_version: '0.14.1',
    severity: 'warn',
    source: { kind: 'file_system' },
    subject: { kind: 'path', value: '/home/u/.claude/settings.json' },
    evidence,
    target_id: null,
    triage: null,
  };
  const client = new QueryClient();
  const noop = () => {};
  render(
    <QueryClientProvider client={client}>
      <SlideOver event={event} onClose={noop} registerFocusAssign={noop} registerFocusNote={noop} />
    </QueryClientProvider>,
  );
}

const fact = (label: string) => screen.getByText(label, { selector: 'dt' }).nextElementSibling;

const cases: [string, Evidence, string][] = [
  ['ai_guard_risk_assessed', riskAssessed, 'built-in rules'],
  ['ai_guard_toggle_drift', toggleDrift, 'rule pack acme-extended'],
];

describe('AI Guard event detail names the user whose home was assessed', () => {
  it.each(cases)('%s shows the user when the reading carries one', (_kind, evidence, rules) => {
    renderDetail({ ...evidence, user: 'alice' });
    expect(fact('Source')?.textContent).toBe(`user alice · ${rules}`);
  });

  it.each(cases)('%s names no user when the reading has none', (_kind, evidence, rules) => {
    renderDetail(evidence);
    expect(fact('Source')?.textContent).toBe(`agent's own home · ${rules}`);
    expect(screen.queryByText(/alice/)).toBeNull();
  });
});
