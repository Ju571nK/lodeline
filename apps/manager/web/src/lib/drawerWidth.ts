export const STORAGE_KEY = 'lodeline.alertDrawerWidth';
export const MIN_WIDTH = 420;
const FULL_WIDTH_BELOW = 900;
const LIST_MARGIN = 240;

type WidthStorage = Pick<Storage, 'getItem' | 'setItem'>;

function browserStorage(): WidthStorage | null {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

/** Half the window, kept between a readable minimum and a comfortable maximum. */
export function defaultWidth(viewport: number): number {
  return Math.min(Math.max(Math.round(viewport * 0.5), 520), 960);
}

export function isFullWidth(viewport: number): boolean {
  return viewport < FULL_WIDTH_BELOW;
}

/** Keeps the drawer at least MIN_WIDTH wide and leaves room for the list beside it. */
export function clampWidth(width: number, viewport: number): number {
  const max = Math.max(MIN_WIDTH, viewport - LIST_MARGIN);
  return Math.min(Math.max(Math.round(width), MIN_WIDTH), max);
}

export function loadWidth(storage: WidthStorage | null = browserStorage()): number | null {
  try {
    const raw = storage?.getItem(STORAGE_KEY);
    if (raw == null) return null;
    const n = Number(raw);
    return Number.isFinite(n) && n > 0 ? n : null;
  } catch {
    return null;
  }
}

export function saveWidth(width: number, storage: WidthStorage | null = browserStorage()): void {
  try {
    storage?.setItem(STORAGE_KEY, String(Math.round(width)));
  } catch {
    // Storage can be blocked; the width then lasts for this page view only.
  }
}
