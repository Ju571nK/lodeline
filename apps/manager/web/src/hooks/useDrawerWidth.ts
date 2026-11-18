import { useCallback, useEffect, useState } from 'react';
import { clampWidth, defaultWidth, isFullWidth, loadWidth, saveWidth } from '@/lib/drawerWidth';

/** The drawer's width in px for this window, the viewer's saved choice when there is one. */
export function useDrawerWidth() {
  const [viewport, setViewport] = useState(() => window.innerWidth);
  const [chosen, setChosen] = useState<number | null>(() => loadWidth());

  useEffect(() => {
    const onResize = () => setViewport(window.innerWidth);
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, []);

  const width = clampWidth(chosen ?? defaultWidth(viewport), viewport);
  const resizeTo = useCallback((next: number, persist: boolean) => {
    const clamped = clampWidth(next, window.innerWidth);
    setChosen(clamped);
    if (persist) saveWidth(clamped);
  }, []);

  return {
    width,
    full: isFullWidth(viewport),
    min: clampWidth(0, viewport),
    max: clampWidth(Number.MAX_SAFE_INTEGER, viewport),
    resizeTo,
  };
}
