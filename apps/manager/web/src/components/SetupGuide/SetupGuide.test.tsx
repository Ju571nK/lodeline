import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { SetupGuide } from './SetupGuide';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const steps = [
  {
    text: <>Put this in server.yaml.</>,
    snippet: { label: 'server.yaml fragment', code: 'artifacts_dir: "/srv/artifacts"' },
  },
  { text: <>Restart the server.</> },
  {
    text: <>Set these.</>,
    snippet: {
      label: 'console variables',
      code: 'LODELINE_PUBLIC_ORIGIN=https://console.example.com',
    },
  },
];

function renderGuide(role: 'alert' | 'status' = 'status') {
  render(
    <SetupGuide
      role={role}
      lead={<>The feature is off.</>}
      steps={steps}
      readme={{ anchor: 'downloads', section: 'Downloads' }}
    />,
  );
}

describe('SetupGuide', () => {
  it('shows the lead, then the steps as a numbered list in order', () => {
    renderGuide();
    const box = screen.getByRole('status');
    expect(box).toHaveTextContent('The feature is off.');
    const items = within(screen.getByRole('list')).getAllByRole('listitem');
    expect(items.map((li) => li.textContent)).toEqual([
      expect.stringContaining('Put this in server.yaml.'),
      expect.stringContaining('Restart the server.'),
      expect.stringContaining('Set these.'),
    ]);
    expect(screen.getByRole('list').tagName).toBe('OL');
  });

  it('takes the role the page needs', () => {
    renderGuide('alert');
    expect(screen.getByRole('alert')).toHaveTextContent('The feature is off.');
  });

  it('shows each snippet whole and gives each one its own copy button', () => {
    renderGuide();
    expect(screen.getByText('artifacts_dir: "/srv/artifacts"')).toBeInTheDocument();
    expect(screen.getAllByRole('button')).toHaveLength(2);
    expect(screen.getByRole('button', { name: 'Copy server.yaml fragment' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy console variables' })).toBeInTheDocument();
  });

  it('copies the snippet text and says so', async () => {
    const writeText = vi.fn(async () => {});
    vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText } });
    renderGuide();
    fireEvent.click(screen.getByRole('button', { name: 'Copy console variables' }));
    expect(writeText).toHaveBeenCalledWith('LODELINE_PUBLIC_ORIGIN=https://console.example.com');
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Copy console variables' })).toHaveTextContent(
        'Copied',
      ),
    );
  });

  it('says the copy failed when the browser refuses the clipboard', async () => {
    const writeText = vi.fn(async () => {
      throw new Error('denied');
    });
    vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText } });
    renderGuide();
    fireEvent.click(screen.getByRole('button', { name: 'Copy server.yaml fragment' }));
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Copy server.yaml fragment' })).toHaveTextContent(
        'Copy failed',
      ),
    );
  });

  it('puts the copy buttons in the tab order and keeps a long snippet in a scrolling box', () => {
    renderGuide();
    for (const b of screen.getAllByRole('button')) {
      expect(b).not.toHaveAttribute('tabindex', '-1');
      expect(b).toHaveAttribute('type', 'button');
    }
    const pre = screen.getByText('artifacts_dir: "/srv/artifacts"').closest('pre');
    expect(pre).toHaveClass('overflow-x-auto');
  });

  it('links the README section', () => {
    renderGuide();
    const link = screen.getByRole('link', { name: /Downloads/ });
    expect(link).toHaveAttribute(
      'href',
      'https://github.com/Ju571nK/lodeline/blob/main/apps/manager/README.md#downloads',
    );
    expect(link).toHaveAttribute('rel', expect.stringContaining('noopener'));
  });
});
