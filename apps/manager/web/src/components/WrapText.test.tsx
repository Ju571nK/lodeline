import { cleanup, render } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { WrapText } from './WrapText';

afterEach(cleanup);

describe('WrapText', () => {
  it.each([
    'c0a80101-5b2e-4d6f-9a3c-1f2e3d4c5b6a',
    'a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718',
    '{\n  "path": "/home/alice/.claude/settings.json",\n  "n": 1\n}',
    'rm -rf /tmp/build  &&   echo done',
  ])('copies as exactly the input: %s', (text) => {
    const { container } = render(<pre>{<WrapText>{text}</WrapText>}</pre>);
    expect(container.textContent).toBe(text);
  });
});
