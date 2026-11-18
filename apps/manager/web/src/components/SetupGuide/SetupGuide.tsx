import { type ReactNode, useEffect, useRef, useState } from 'react';
import { Button } from '@/components/ui/button';

const README = 'https://github.com/Ju571nK/lodeline/blob/main/apps/manager/README.md';

export interface GuideStep {
  text: ReactNode;
  snippet?: { label: string; code: string };
}

type CopyState = 'idle' | 'copied' | 'failed';

/** A snippet that scrolls inside its own box, with a button that copies its text. */
function Snippet({ label, code }: { label: string; code: string }) {
  const [state, setState] = useState<CopyState>('idle');
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);

  async function copy() {
    try {
      await navigator.clipboard.writeText(code);
      setState('copied');
    } catch {
      setState('failed');
    }
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setState('idle'), 2500);
  }

  return (
    <div className="mt-1 flex min-w-0 items-start gap-2 rounded border border-border-subtle bg-bg-page p-2">
      <pre className="min-w-0 flex-1 overflow-x-auto text-xs text-text-primary">
        <code>{code}</code>
      </pre>
      <Button
        type="button"
        variant="secondary"
        size="sm"
        aria-label={`Copy ${label}`}
        onClick={copy}
        className="shrink-0"
      >
        {state === 'copied' ? 'Copied' : state === 'failed' ? 'Copy failed' : 'Copy'}
      </Button>
    </div>
  );
}

/**
 * What to do, in order, when a console feature is off: a lead that says what is missing, numbered
 * steps with copyable snippets, and the README section that has the full text.
 */
export function SetupGuide({
  role,
  lead,
  steps,
  readme,
}: {
  role: 'alert' | 'status';
  lead: ReactNode;
  steps: GuideStep[];
  readme: { anchor: string; section: string };
}) {
  return (
    <section
      role={role}
      className="min-w-0 space-y-3 [overflow-wrap:anywhere] rounded-md border border-border bg-bg-surface p-6 text-sm"
    >
      <p>{lead}</p>
      <ol className="list-decimal space-y-3 pl-5">
        {steps.map((step, i) => (
          // The steps are fixed text in a fixed order.
          // biome-ignore lint/suspicious/noArrayIndexKey: static list
          <li key={i} className="min-w-0">
            {step.text}
            {step.snippet && <Snippet {...step.snippet} />}
          </li>
        ))}
      </ol>
      <p className="text-text-muted">
        Full steps:{' '}
        <a
          href={`${README}#${readme.anchor}`}
          target="_blank"
          rel="noopener noreferrer"
          className="text-accent hover:underline"
        >
          {readme.section} section of the console README
        </a>
        .
      </p>
    </section>
  );
}
