import { Fragment } from 'react';
import { wrapSegments } from '@/lib/wrapSegments';

/** Text that wraps at sensible points, with no lone character on a line. */
export function WrapText({ children }: { children: string }) {
  const segments = wrapSegments(children);
  return (
    <>
      {segments.map((segment, i) => (
        // biome-ignore lint/suspicious/noArrayIndexKey: segments are positional and never reorder
        <Fragment key={i}>
          {i > 0 && <wbr />}
          {segment}
        </Fragment>
      ))}
    </>
  );
}
