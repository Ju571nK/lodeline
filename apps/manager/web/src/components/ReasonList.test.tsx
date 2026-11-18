import '@testing-library/jest-dom/vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ReasonLike } from '@/api/fleet';
import { ReasonList } from './ReasonList';

afterEach(cleanup);
const reasons = [
  {
    kind: 'mcp_tool_instruction_override',
    server: 'server-a',
    tool: 'tool-a',
    pattern: 'ignore_previous',
  },
  { kind: 'mcp_tool_hidden_text', server: 'server-b', tool: 'tool-b', text_kind: 'zero_width' },
  { kind: 'mcp_tool_name_shadow', tool: 'shared', servers: ['server-a', 'server-b'] },
  {
    kind: 'mcp_tool_surface_drift',
    server: 'server-c',
    tool: 'tool-c',
    baseline_hash: 'oldhash',
    current_hash: 'newhash',
  },
  {
    kind: 'mcp_unapproved_new_tool',
    server: 'server-d',
    tool: 'tool-d',
    current_hash: 'addedhash',
  },
  { kind: 'mcp_schema_privilege_expansion', server: 'server-e', tool: 'tool-e' },
  { kind: 'mcp_read_only_hint_contradiction', server: 'server-f', tool: 'tool-f' },
  { kind: 'auto_mode_defaults_dropped', list: 'hard_deny' },
  { kind: 'hook_forwards_tool_calls', hook_event: 'PreToolUse', destination: 'external.example' },
  { kind: 'unattended_loop_prompt', source: 'project' },
  { kind: 'standing_command_approval', pattern: 'git push' },
];
describe('reason evidence', () => {
  it('renders the eleven additive reason payloads and advisory context', () => {
    render(<ReasonList reasons={reasons} />);
    for (const value of [
      'ignore_previous',
      'zero_width',
      'oldhash',
      'newhash',
      'addedhash',
      'tool-e',
      'tool-f',
      'hard_deny',
      'external.example',
      'PreToolUse',
      'project',
      'git push',
    ])
      expect(screen.getByText(value)).toBeInTheDocument();
    expect(screen.getByText('["server-a","server-b"]')).toBeInTheDocument();
    expect(screen.getByText(/not proof of a write/)).toBeInTheDocument();
    expect(screen.getByText(/does not establish an approval violation/)).toBeInTheDocument();
  });
  it('keeps distinct and identical repeated reasons without React key collisions', () => {
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {});
    render(
      <ReasonList reasons={[reasons[1], { ...reasons[1], server: 'other-server' }, reasons[1]]} />,
    );
    fireEvent.click(screen.getByText(/Mcp Tool Hidden Text/));
    expect(screen.getByText('×2')).toBeInTheDocument();
    expect(screen.getByText('other-server')).toBeInTheDocument();
    expect(errors).not.toHaveBeenCalled();
    errors.mockRestore();
  });
  it('shows script_path, future fields and full long evidence without interpreting markup', () => {
    const path = `/work/${'nested/'.repeat(25)}script.sh`;
    render(
      <ReasonList
        reasons={[
          {
            kind: 'external_script_unscanned',
            script_path: path,
            hook_event: 'Stop',
            future_value: false,
            source_chain: ['/entry.sh', path],
            snippet: '<script>alert(1)</script>',
          },
        ]}
      />,
    );
    fireEvent.click(screen.getAllByText(/full value/)[0]);
    expect(screen.getByText(path)).toBeVisible();
    expect(screen.getByText('false')).toBeInTheDocument();
    expect(screen.getByText('<script>alert(1)</script>')).toBeInTheDocument();
  });
  it('renders a reason whose kind is not a string', () => {
    render(<ReasonList reasons={[{ kind: 7, server: 'server-x' } as unknown as ReasonLike]} />);
    expect(screen.getByText('Unknown')).toBeInTheDocument();
    expect(screen.getByText('server-x')).toBeInTheDocument();
  });

  describe('grouping by kind', () => {
    const broad = (event: string) => ({ kind: 'broad_matcher', hook_event: event, matcher: '.*' });

    it('shows one collapsed header with a count for a kind that repeats', () => {
      render(
        <ReasonList
          reasons={[broad('PreToolUse'), { kind: 'no_sandbox', executor: 'x' }, broad('Stop')]}
        />,
      );
      const header = screen.getByText('Broad Matcher (2)');
      expect(header.closest('details')).not.toHaveAttribute('open');
      expect(screen.queryAllByText('Broad Matcher')).toHaveLength(0);
      expect(screen.getByText('No Sandbox')).toBeInTheDocument();
    });

    it('expands a group to show each entry detail', () => {
      render(<ReasonList reasons={[broad('PreToolUse'), broad('Stop')]} />);
      fireEvent.click(screen.getByText('Broad Matcher (2)'));
      expect(screen.getByText('Broad Matcher (2)').closest('details')).toHaveAttribute('open');
      expect(screen.getByText('PreToolUse')).toBeVisible();
      expect(screen.getByText('Stop')).toBeVisible();
    });

    it('shows identical entries once with a count', () => {
      render(<ReasonList reasons={[broad('Stop'), broad('Stop'), broad('Stop')]} />);
      expect(screen.getByText('Broad Matcher')).toBeInTheDocument();
      expect(screen.getByText('×3')).toBeInTheDocument();
      expect(screen.getAllByText('Stop')).toHaveLength(1);
    });

    it('counts a group by every reason it holds, duplicates included', () => {
      render(<ReasonList reasons={[broad('Stop'), broad('Stop'), broad('PreToolUse')]} />);
      expect(screen.getByText('Broad Matcher (3)')).toBeInTheDocument();
      fireEvent.click(screen.getByText('Broad Matcher (3)'));
      expect(screen.getByText('×2')).toBeInTheDocument();
    });

    it('orders groups by the first appearance of their kind', () => {
      render(
        <ReasonList
          reasons={[
            { kind: 'no_sandbox', executor: 'x' },
            broad('Stop'),
            { kind: 'no_sandbox', executor: 'y' },
          ]}
        />,
      );
      const text = document.body.textContent ?? '';
      expect(text.indexOf('No Sandbox (2)')).toBeLessThan(text.indexOf('Broad Matcher'));
    });
  });
});
