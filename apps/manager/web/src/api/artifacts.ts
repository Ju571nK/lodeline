/**
 * The release files in lodeline-server's `artifacts_dir`. The console lists their names and
 * streams each file from the server under its own read token, so the browser never holds it.
 */

import { API_BASE, api } from './client';

/** The server's index, passed through: names only, in the server's order. */
export interface ArtifactsIndex {
  artifacts: string[];
}

export function fleetArtifacts(signal?: AbortSignal): Promise<ArtifactsIndex> {
  return api<ArtifactsIndex>('/fleet/artifacts', { signal });
}

/** A same-origin link, so the browser sends the session cookie and saves the file itself. */
export const artifactURL = (name: string) =>
  `${API_BASE}/fleet/artifacts/${encodeURIComponent(name)}`;
