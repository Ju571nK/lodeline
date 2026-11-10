import type { ReactNode } from 'react';

const enrollToken = <code>lodeline-server enroll-token</code>;

/** The host-side recovery steps. Shown after a file is made and, in part, in the matching errors. */
export const stoppedHost = (
  <>
    If <code>lodeline-sender enroll</code> on the host stopped after it stored the host id (an exit
    code 3 when you run it again with another file means that), make a new file for that host id:
    run <code>lodeline show host-id</code> on the host, paste its output into the host id field
    above, and make the file again.
  </>
);
export const hostIdExists = (
  <>
    If the answer is that the host id already exists on the server, the console cannot help: run{' '}
    {enrollToken} on the server.
  </>
);
export const fileStillValid = (
  <>
    If the answer is that a file for this host id is still valid, use that file, wait until it
    expires, or run {enrollToken} on the server.
  </>
);

/** One cause and one action for each code the console's enrollment routes answer. */
const byCode: Record<string, ReactNode> = {
  not_an_enroller: (
    <>
      This account is not on the enroll list. Ask the operator of the console to add your subject to{' '}
      <code>LODELINE_ENROLL_SUBJECTS</code>.
    </>
  ),
  origin_not_allowed: (
    <>
      The request did not come from the console's own address. Open the console at the address in{' '}
      <code>LODELINE_PUBLIC_ORIGIN</code> and try again.
    </>
  ),
  invalid_host_id: <>The host id is not a lower-case, hyphenated version 4 UUID. Correct it.</>,
  invalid_request: <>The console did not accept the request. Reload the page and try again.</>,
  host_exists: (
    <>
      The server already knows this host id, so the console cannot make a file for it. Run{' '}
      {enrollToken} on the server, or leave the host id empty to make a new one.
    </>
  ),
  token_outstanding: (
    <>
      A file for this host id is still valid. Use that file, wait until it expires (one hour unless
      the server was set otherwise), or run {enrollToken} on the server, which has no such rule.
    </>
  ),
  enrollment_limit_reached: (
    <>
      The server holds the most tokens it allows. Wait and try again, or ask the operator of the
      server to raise <code>enroll_mint.max_tokens</code>.
    </>
  ),
  enroll_unavailable: (
    <>
      The server has no enrollment mint, or does not accept this console's mint certificate. The
      operator of the server should check section 3.6 of <code>docs/install-server.md</code>.
    </>
  ),
  enroll_refused: (
    <>
      The server refused this console's mint credential. The operator of the console should check{' '}
      <code>LODELINE_ENROLL_MINT_TOKEN</code> against the server's mint verifier file.
    </>
  ),
  enroll_failed: (
    <>
      No file was made, because the console did not get a usable answer from the server. The server
      may have made a token and the answer may have been lost. Asking again for the same host id can
      answer that a file is still valid, until that token expires. Leave the host id empty to make a
      new one, or run {enrollToken} on the server.
    </>
  ),
  enrollment_not_configured: (
    <>
      Host enrollment is not configured on this console. The operator of the console sets the
      variables in the Enroll a host section of the README.
    </>
  ),
  unsupported_media_type: (
    <>The console did not accept the request. Reload the page and try again.</>
  ),
  body_too_large: <>The console did not accept the request. Reload the page and try again.</>,
  request_timeout: <>The request took too long. Try again.</>,
  internal: <>The console could not make a host id. Try again.</>,
  network: (
    <>
      The console did not answer. A token may have been made and lost: asking again for the same
      host id can answer that a file is still valid, until that token expires.
    </>
  ),
};

/** Console settings that it cannot read: the server's message names the variable. */
export function enrollErrorText(code: string, message: string): ReactNode {
  if (code === 'enroll_misconfigured') {
    return (
      <>
        The console cannot read one of its enrollment settings: {message}. The operator of the
        console must fix it and restart.
      </>
    );
  }
  if (code === 'unauthorized' || code === 'session_expired') {
    return (
      <>
        Your session ended. <a href="/login">Sign in again</a>.
      </>
    );
  }
  return byCode[code] ?? <>The console answered an error ({code}). Try again.</>;
}
