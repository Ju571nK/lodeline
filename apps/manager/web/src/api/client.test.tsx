import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ObservedControls } from '@/components/ObservedControls';
import { ReasonList } from '@/components/ReasonList';
import { api } from './client';
import type { AiGuardControl, ReasonLike } from './fleet';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

async function fromServer<T>(text: string): Promise<T> {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response(text, { headers: { 'Content-Type': 'application/json' } })),
  );
  return api<T>('/fleet/events');
}

const evidence =
  '{"kind":"x","z":1.50,"e":1e3,"long":0.1000000000000000055511151231257827,' +
  '"big":18446744073709551616,"neg":-0,"huge":1e400,"plain":2.5,' +
  '"nested":{"b":[1.50,{"y":1e3,"x":-0}],"a":"text"}}';

interface Page {
  total_estimated: number;
  events: { schema_version: number; evidence: unknown; source: unknown; subject: unknown }[];
}

describe('numbers in raw fleet fields', () => {
  it('shows the number text the server sent, in key order', async () => {
    const page = await fromServer<Page>(
      `{"total_estimated":3,"events":[{"schema_version":1,"evidence":${evidence},` +
        '"source":{"kind":"agent","n":1.50},"subject":-0}]}',
    );
    const [event] = page.events;
    expect(JSON.stringify(event.evidence)).toBe(evidence);
    expect(JSON.stringify(event.source)).toBe('{"kind":"agent","n":1.50}');
    expect(JSON.stringify(event.subject)).toBe('-0');
    expect(JSON.stringify(event.evidence, null, 2)).toContain('\n    "b": [\n      1.50,');
  });

  it('keeps typed fields as plain numbers', async () => {
    const page = await fromServer<Page>(
      '{"total_estimated":18446744073709551616,"events":[{"schema_version":1.0,"evidence":{}}]}',
    );
    expect(page.total_estimated).toBe(2 ** 64);
    expect(page.events[0].schema_version).toBe(1);
  });

  it('still computes with a re-spelled number', async () => {
    const page = await fromServer<Page>(
      '{"events":[{"evidence":{"kind":"ai_guard_risk_assessed","score":7.0,"w":1e3}}]}',
    );
    const ev = page.events[0].evidence as { score: number; w: number };
    expect(ev.score.toFixed(1)).toBe('7.0');
    expect([ev.w, ev.score].sort((a, b) => a - b).map(Number)).toEqual([7, 1000]);
    expect(String(ev.w)).toBe('1e3');
  });

  it('renders reason and control values as sent', async () => {
    const tool = await fromServer<{
      reasons: ReasonLike[];
      controls: AiGuardControl[];
    }>(
      '{"reasons":[{"kind":"x","limit":1.50,"ids":[18446744073709551616]}],' +
        '"controls":[{"id":"c1","source_path":"/p","setting":"s","value":1e400}]}',
    );
    render(<ReasonList reasons={tool.reasons} />);
    expect(screen.getByText('1.50')).toBeInTheDocument();
    expect(screen.getByText('[18446744073709551616]')).toBeInTheDocument();
    render(
      <ObservedControls
        controls={tool.controls}
        assessedAt="2026-09-13T00:00:00Z"
        scope={{ kind: 'user_global' }}
      />,
    );
    expect(screen.getByText('1e400')).toBeInTheDocument();
  });
});
