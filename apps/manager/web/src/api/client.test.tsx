import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ObservedControls } from '@/components/ObservedControls';
import { ReasonList } from '@/components/ReasonList';
import { api, JsonNumber } from './client';
import type { AiGuardControl, HostDetail, ReasonLike } from './fleet';

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

  it('keeps a by_tool score a plain number', async () => {
    const host = await fromServer<HostDetail>(
      '{"current_risk":{"max_score":7.0,"by_tool":{"claude":{"score":7.0}}},' +
        '"ai_guard":{"by_tool":{"claude":{"score":7.0,"scope":{"kind":"user_global","n":1.50}}}}}',
    );
    expect(host.current_risk?.by_tool.claude.score).toBe(7);
    expect(host.ai_guard?.by_tool.claude.score).toBe(7);
    expect(JSON.stringify(host.ai_guard?.by_tool.claude.scope)).toBe(
      '{"kind":"user_global","n":1.50}',
    );
  });
});

describe('engines without JSON.parse source text', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('parses as plain JSON.parse does', async () => {
    const parse = JSON.parse;
    vi.spyOn(JSON, 'parse').mockImplementation((text, reviver) =>
      parse(
        text,
        reviver &&
          function (this: unknown, key: string, value: unknown) {
            return reviver.call(this, key, value);
          },
      ),
    );
    const text = `{"events":[{"schema_version":1.0,"evidence":${evidence},"source":{"n":1.50},"subject":-0}]}`;
    const page = await fromServer<Page>(text);
    const members: unknown[] = [];
    // The replacer sees toJSON's result, so read the member from its holder.
    JSON.stringify(page, function (this: Record<string, unknown>, key, value) {
      members.push(this[key]);
      return value;
    });
    expect(members.some((member) => member instanceof JsonNumber)).toBe(false);
    expect(page).toEqual(parse(text));
  });
});
