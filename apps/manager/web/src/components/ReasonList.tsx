import { useState } from 'react';
import type { ReasonLike } from '@/api/fleet';
import { humanKind, shortPath } from '@/lib/labels';

const FIELD_LABELS: Record<string, string> = {
  pattern: 'pattern',
  executor: 'executor',
  server_name: 'server',
  server: 'server',
  tool: 'tool',
  servers: 'servers',
  url: 'url',
  command: 'command',
  shape: 'shape',
  evidence: 'match',
  mechanism: 'via',
  mode: 'mode',
  rule: 'rule',
  matcher: 'matcher',
  name: 'task',
  path: 'path',
  script_path: 'script path',
  hook_event: 'hook event',
  directive_kind: 'directive',
  snippet: 'snippet',
  text_kind: 'hidden text',
  baseline_hash: 'baseline hash',
  current_hash: 'current hash',
  list: 'replaced defaults',
  destination: 'destination',
  source: 'source',
};

const NOTES: Record<string, string> = {
  mcp_tool_surface_drift:
    'Compared with the first observed baseline, not an operator approval or signature.',
  mcp_unapproved_new_tool:
    'Not in the first observed baseline; this does not establish an approval violation.',
  mcp_schema_privilege_expansion:
    'Schema change relative to the first observed baseline; not proof of runtime execution.',
  mcp_read_only_hint_contradiction:
    'Metadata heuristic; not proof of a write or an approval override.',
};

interface Entry {
  reason: ReasonLike;
  count: number;
}

interface Group {
  kind: string;
  total: number;
  entries: Entry[];
}

/** Groups by kind in order of first appearance and folds identical entries into one with a count. */
function groupReasons(reasons: ReasonLike[]): Group[] {
  const groups = new Map<string, Group>();
  const entries = new Map<string, Entry>();
  for (const reason of reasons) {
    const kindKey = JSON.stringify(reason.kind);
    const identity = JSON.stringify(Object.entries(reason).sort(([a], [b]) => a.localeCompare(b)));
    let group = groups.get(kindKey);
    if (!group) {
      group = { kind: reason.kind, total: 0, entries: [] };
      groups.set(kindKey, group);
    }
    group.total += 1;
    const entry = entries.get(identity);
    if (entry) {
      entry.count += 1;
    } else {
      const created = { reason, count: 1 };
      entries.set(identity, created);
      group.entries.push(created);
    }
  }
  return [...groups.values()];
}

/** All reason fields remain inspectable, including unknown additive fields. */
export function ReasonList({ reasons }: { reasons: ReasonLike[] }) {
  return (
    <ul className="space-y-2">
      {groupReasons(reasons).map((group) => (
        <li key={JSON.stringify(group.kind)} className="min-w-0">
          {group.total === 1 || group.entries.length === 1 ? (
            <ReasonItem entry={group.entries[0]} />
          ) : (
            <ReasonGroup group={group} />
          )}
        </li>
      ))}
    </ul>
  );
}

function ReasonGroup({ group }: { group: Group }) {
  return (
    <details>
      <summary className="cursor-pointer text-text-primary">
        {`${humanKind(group.kind)} (${group.total})`}
      </summary>
      {NOTES[group.kind] && <p className="mt-1 text-text-muted">{NOTES[group.kind]}</p>}
      <ul className="mt-1 space-y-2 border-l border-border pl-3">
        {group.entries.map((entry) => (
          <li key={JSON.stringify(Object.entries(entry.reason))} className="min-w-0">
            <ReasonItem entry={entry} heading={false} />
          </li>
        ))}
      </ul>
    </details>
  );
}

function ReasonItem({ entry, heading = true }: { entry: Entry; heading?: boolean }) {
  const { reason, count } = entry;
  const chain = Array.isArray(reason.source_chain)
    ? reason.source_chain.filter((p): p is string => typeof p === 'string')
    : [];
  return (
    <>
      {(heading || count > 1) && (
        <div>
          {heading && <span className="text-text-primary">{humanKind(reason.kind)}</span>}
          {count > 1 && <span className="ml-1 text-text-subtle">×{count}</span>}
        </div>
      )}
      {Object.entries(reason)
        .filter(([key, value]) => key !== 'kind' && key !== 'source_chain' && value != null)
        .map(([key, value]) => (
          <div key={key} className="text-text-muted">
            <span>{FIELD_LABELS[key] ?? humanKind(key)}: </span>
            <EvidenceValue value={value} />
          </div>
        ))}
      {chain.length > 0 && (
        <div className="text-text-muted">
          <span>Source chain: </span>
          {chain.map((path, index) => (
            <span key={path}>
              {index > 0 && <span className="mx-1">→</span>}
              <code title={path} className="break-all">
                {shortPath(path)}
              </code>
            </span>
          ))}
          <details>
            <summary className="cursor-pointer">Full source paths</summary>
            <EvidenceValue value={chain} />
          </details>
        </div>
      )}
      {heading && NOTES[reason.kind] && (
        <p className="mt-1 text-text-muted">{NOTES[reason.kind]}</p>
      )}
    </>
  );
}

function EvidenceValue({ value }: { value: unknown }) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  const [copyState, setCopyState] = useState('Copy');
  if (!text || text.length <= 96)
    return <code className="whitespace-pre-wrap break-all font-mono">{text}</code>;
  return (
    <details className="inline">
      <summary className="cursor-pointer break-all font-mono">
        {text.slice(0, 64)}… (full value)
      </summary>
      <code className="block whitespace-pre-wrap break-all font-mono">{text}</code>
      <button
        type="button"
        className="text-accent"
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(text);
            setCopyState('Copied');
          } catch {
            setCopyState('Copy unavailable — select text above');
          }
        }}
      >
        {copyState}
      </button>
    </details>
  );
}
