/**
 * Host enrollment files (#553). `POST /enrollment/files` answers with the file itself, which holds a
 * single-use token. It is a secret, so this module never parses it, never reads it as text and never
 * returns it: the browser saves the response's own bytes and only the two public headers come back.
 */

import { API_BASE, ApiError, api } from './client';

/** `GET /enrollment`: off, or on with what a file made now would hold. */
export type EnrollmentStatus =
  | { enabled: false; missing: string[] }
  | {
      enabled: true;
      can_enroll: boolean;
      server_url: string;
      enroll_url: string;
      ca: { subject: string; sha256: string }[];
      policy_keys: { id: string; sha256: string; valid_from: string; valid_until: string }[];
    };

export function enrollmentStatus(signal?: AbortSignal): Promise<EnrollmentStatus> {
  return api<EnrollmentStatus>('/enrollment', { signal });
}

/** What the page may keep of a made file: two values that are in the file and are not secret. */
export interface MadeFile {
  host_id: string;
  expires_at: string;
}

/** The server's rule for a host id: lower-case, hyphenated, version 4. */
export const isCanonicalV4 = (s: string) =>
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(s);

export const fileName = (hostId: string) => `lodeline-enroll-${hostId}.json`;

/** Asks for a file, hands its bytes to the browser's download, and returns only the headers. */
export async function makeEnrollmentFile(hostId?: string): Promise<MadeFile> {
  const res = await fetch(`${API_BASE}/enrollment/files`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(hostId ? { host_id: hostId } : {}),
  });
  if (!res.ok) throw await failure(res);
  const host_id = res.headers.get('X-Lodeline-Enroll-Host-Id') ?? '';
  const expires_at = res.headers.get('X-Lodeline-Enroll-Expires-At') ?? '';
  if (!isCanonicalV4(host_id) || !expires_at) {
    throw new ApiError(502, 'enroll_failed', 'the answer did not carry the file headers');
  }
  save(await res.blob(), fileName(host_id));
  return { host_id, expires_at };
}

function save(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    a.click();
  } finally {
    URL.revokeObjectURL(url);
  }
}

/** An error answer holds no secret, so it is read as the console's JSON error body. */
async function failure(res: Response): Promise<ApiError> {
  let code = 'unknown';
  let message = `${res.status} ${res.statusText}`;
  try {
    const body = (await res.json()) as { error?: { code?: string; message?: string } };
    code = body.error?.code ?? code;
    message = body.error?.message ?? message;
  } catch {
    // not JSON: keep the status text
  }
  if (res.status === 401) code = code === 'session_expired' ? code : 'unauthorized';
  return new ApiError(res.status, code, message);
}
