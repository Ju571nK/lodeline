const BREAK_AFTER = /[-_/\\.:,=&?#@]/;
const MIN_PIECE = 4;
const MAX_PIECE = 12;
const GROUP = 8;

function splitAtPunctuation(run: string): string[] {
  const pieces: string[] = [];
  let cur = '';
  for (const ch of run) {
    cur += ch;
    if (BREAK_AFTER.test(ch)) {
      pieces.push(cur);
      cur = '';
    }
  }
  if (cur) pieces.push(cur);
  const merged: string[] = [];
  for (const piece of pieces) {
    const last = merged.length - 1;
    if (last >= 0 && (merged[last].length < MIN_PIECE || piece.length < MIN_PIECE)) {
      merged[last] += piece;
    } else {
      merged.push(piece);
    }
  }
  return merged;
}

function chop(piece: string): string[] {
  if (piece.length <= MAX_PIECE) return [piece];
  const groups = Math.ceil(piece.length / GROUP);
  const out: string[] = [];
  let start = 0;
  for (let i = 0; i < groups; i++) {
    const end = start + Math.ceil((piece.length - start) / (groups - i));
    out.push(piece.slice(start, end));
    start = end;
  }
  return out;
}

/**
 * Splits text into pieces that may break between them. Breaks fall after
 * punctuation, and a long unbroken run is cut into near-equal groups, so a
 * wrapped id or hash never leaves a lone character on a line. Whitespace runs
 * are their own pieces and joining the pieces gives back the text.
 */
export function wrapSegments(text: string): string[] {
  const out: string[] = [];
  for (const part of text.split(/(\s+)/)) {
    if (part === '') continue;
    if (/^\s+$/.test(part)) out.push(part);
    else out.push(...splitAtPunctuation(part).flatMap(chop));
  }
  return out;
}
