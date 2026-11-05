/**
 * lodeline-manager API client. Every fetch in the SPA goes through here so:
 *   - credentials are always 'include' (the session cookie is HttpOnly +
 *     SameSite=Lax; the browser handles it for us as long as we include),
 *   - JSON is always the wire format,
 *   - non-2xx responses surface as a typed [`ApiError`] subclass so
 *     callers can pattern-match without re-parsing the body.
 *
 * Base URL: relative `/api/v1/*` in both dev (Vite proxy → :8080) and prod
 * (same-origin to the Go binary).
 */

export const API_BASE = '/api/v1';

/** Wire shape of the contract §6.1 error body. */
interface ApiErrorBody {
  error?: { code?: string; message?: string };
}

/** Base class for every non-2xx response. Callers `instanceof` to branch. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

/** 401: cookie missing/invalid (NOT expired — see [`SessionExpiredError`]). */
export class UnauthorizedError extends ApiError {
  constructor(message = 'unauthorized') {
    super(401, 'unauthorized', message);
    this.name = 'UnauthorizedError';
  }
}

/** 401 with code=session_expired: cookie was valid but past `exp`. */
export class SessionExpiredError extends ApiError {
  constructor(message = 'session expired') {
    super(401, 'session_expired', message);
    this.name = 'SessionExpiredError';
  }
}

/** 404: id-lookup miss (event/host doesn't exist). */
export class NotFoundError extends ApiError {
  constructor(message = 'not found') {
    super(404, 'not_found', message);
    this.name = 'NotFoundError';
  }
}

/** 503: upstream lodeline-server is rebuilding its index (F15). */
export class ServiceUnavailableError extends ApiError {
  constructor(message = 'service unavailable') {
    super(503, 'service_unavailable', message);
    this.name = 'ServiceUnavailableError';
  }
}

/** Anything we didn't map specifically. */
export class UnknownApiError extends ApiError {}

/**
 * Issues a request to the consumer-side API. Always JSON in, always JSON
 * out (or an [`ApiError`] subclass thrown).
 *
 * @param path — appended to [`API_BASE`]. Starts with `/`.
 * @param init — standard fetch init; method/body/headers stay as-is.
 */
export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    credentials: 'include',
    headers: {
      Accept: 'application/json',
      ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
      ...init?.headers,
    },
  });

  if (res.status === 204) return undefined as T;

  const body = await safeJSON(res);

  if (res.ok) return body as T;

  const errBody = body as ApiErrorBody | undefined;
  const code = errBody?.error?.code ?? 'unknown';
  const message = errBody?.error?.message ?? `${res.status} ${res.statusText}`;

  if (res.status === 401) {
    throw code === 'session_expired'
      ? new SessionExpiredError(message)
      : new UnauthorizedError(message);
  }
  if (res.status === 404) throw new NotFoundError(message);
  if (res.status === 503) throw new ServiceUnavailableError(message);
  throw new UnknownApiError(res.status, code, message);
}

/** Reads the body as JSON, returning undefined on empty / non-JSON. */
async function safeJSON(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!text) return undefined;
  try {
    return parseJSON(text);
  } catch {
    return text;
  }
}

/** Keys whose values the server relays as the fleet server wrote them (`RAW_KEYS` in wire.rs). */
const RAW_KEYS = new Set(['source', 'subject', 'evidence', 'scope', 'reasons', 'value']);

/**
 * A number under a raw key that JSON.parse would spell differently (`1.50`, `1e3`, `-0`, `1e400`,
 * integers past 2^53). It computes as the parsed value; `String` and `JSON.stringify` give the
 * server's text.
 */
export class JsonNumber extends Number {
  readonly source: string;

  constructor(value: number, source: string) {
    super(value);
    this.source = source;
  }

  override toString(): string {
    return this.source;
  }

  toJSON(): unknown {
    // Only made where the reviver gets source text, which ships together with JSON.rawJSON.
    return (JSON as unknown as { rawJSON(text: string): unknown }).rawJSON(this.source);
  }
}

/**
 * JSON.parse that keeps the server's number text under raw keys. It needs the reviver's source
 * text (Chrome 114, Firefox 135, Safari 18.4, Node 21); older engines parse as JSON.parse does.
 */
function parseJSON(text: string): unknown {
  const respelled = new Map<object, Map<string, string>>();
  return JSON.parse(
    text,
    function (this: object, key: string, value: unknown, context?: { source?: string }) {
      const source = context?.source;
      if (typeof value === 'number' && source !== undefined && String(value) !== source) {
        if (RAW_KEYS.has(key)) return new JsonNumber(value, source);
        respelled.set(this, (respelled.get(this) ?? new Map()).set(key, source));
      } else if (RAW_KEYS.has(key)) {
        keepText(value, respelled);
      }
      return value;
    },
  );
}

/** Replaces the re-spelled numbers inside one raw value; typed fields stay plain numbers. */
function keepText(value: unknown, respelled: Map<object, Map<string, string>>): void {
  if (typeof value !== 'object' || value === null) return;
  const sources = respelled.get(value);
  respelled.delete(value);
  const holder = value as Record<string, unknown>;
  for (const [key, member] of Object.entries(holder)) {
    const source = sources?.get(key);
    if (source === undefined) keepText(member, respelled);
    else holder[key] = new JsonNumber(member as number, source);
  }
}
