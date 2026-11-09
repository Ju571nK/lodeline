import { ApiError, ServiceUnavailableError } from '@/api/client';

export const certificateRefused =
  'Client certificate refused. Issue the certificate in LODELINE_SERVER_CLIENT_CERT_PATH from the host client CA of lodeline-server.';

export function readAPIError(error: unknown): string {
  if (error instanceof ServiceUnavailableError) return 'Rebuilding index (503). Retry shortly.';
  if (error instanceof ApiError) {
    if (error.code === 'upstream_unauthorized')
      return 'Read API token rejected. Check the server read token configuration.';
    if (error.code === 'read_api_disabled')
      return 'Read API disabled. Configure LODELINE_SERVER_READ_TOKEN on lodeline-server.';
    if (error.code === 'certificate_refused') return certificateRefused;
    if (error.status === 401) return 'Session unavailable. Sign in again.';
  }
  return 'Read API unavailable. Check the connection and retry.';
}
