import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import type { ToolAiGuard } from '@/api/fleet';
import { AiGuardByTool } from './AiGuardByTool';

afterEach(cleanup);

function low(extra: Partial<ToolAiGuard> = {}): ToolAiGuard {
  return {
    score: 0,
    bucket: 'low',
    assessed_ts: '2026-09-13T00:00:00Z',
    is_reattestation: false,
    scope: { kind: 'user_global' },
    reasons: null,
    ...extra,
  };
}

describe('AiGuardByTool config_found', () => {
  it('moves tools without a config out of the Low strip into one line', () => {
    render(
      <AiGuardByTool
        byTool={{
          claude_code: low({ config_found: true }),
          codex: low(),
          gemini: low({ config_found: false }),
          cursor: low({ config_found: false }),
        }}
      />,
    );
    expect(screen.getByText(/^Low \(2\): /)).toHaveTextContent('Low (2): Claude Code · Codex');
    expect(screen.getByText(/^No config found \(2\): /)).toHaveTextContent(
      'No config found (2): Gemini · Cursor',
    );
    expect(screen.getByText(/^No config found/)).not.toHaveTextContent('Claude Code');
  });

  it('says a missing config does not mean the tool is not installed', () => {
    render(<AiGuardByTool byTool={{ gemini: low({ config_found: false }) }} />);
    expect(
      screen.getByText(
        'No watched config file was found on this host, which does not mean the tool is not installed.',
      ),
    ).toBeInTheDocument();
  });

  it('counts a missing field as present', () => {
    render(<AiGuardByTool byTool={{ claude_code: low(), codex: low() }} />);
    expect(screen.getByText(/^Low \(2\): /)).toBeInTheDocument();
    expect(screen.queryByText(/No config found/)).not.toBeInTheDocument();
  });

  it('does not render the Low strip when every tool has no config', () => {
    render(
      <AiGuardByTool
        byTool={{ gemini: low({ config_found: false }), cursor: low({ config_found: false }) }}
      />,
    );
    expect(screen.queryByText(/^Low \(/)).not.toBeInTheDocument();
    expect(screen.getByText(/^No config found \(2\): /)).toBeInTheDocument();
  });

  it('keeps the empty state when there are no tools', () => {
    render(<AiGuardByTool byTool={{}} />);
    expect(screen.getByText('No AI Guard assessments yet.')).toBeInTheDocument();
  });
});
