import { useQuery } from '@tanstack/react-query';
import { artifactURL, fleetArtifacts } from '@/api/artifacts';
import { ApiError } from '@/api/client';
import { readAPIError } from '@/lib/server-status';

const box = 'rounded-md border border-border bg-bg-surface p-6 text-sm';

/** The release files that lodeline-server serves, each a plain download link. */
export function Downloads() {
  const files = useQuery({
    queryKey: ['fleet', 'artifacts'],
    queryFn: ({ signal }) => fleetArtifacts(signal),
    retry: false,
  });
  const notConfigured =
    files.error instanceof ApiError && files.error.code === 'artifacts_not_configured';
  return (
    <div className="space-y-3">
      <h1 className="text-lg font-semibold text-text-primary">Downloads</h1>
      <p className="text-sm text-text-muted">
        Release files that the operator of lodeline-server put in its <code>artifacts_dir</code>.
        The console gets each file from the server with its own credentials and passes it on as the
        server sends it. It does not check the files. Before you install a file, check it against
        the <code>SHA256SUMS</code> on the GitHub release page and its attestation, because a{' '}
        <code>SHA256SUMS</code> from this page comes from the same server as the file.
      </p>
      {files.isPending ? (
        <p role="status" className={`${box} text-text-muted`}>
          Loading the file list…
        </p>
      ) : notConfigured ? (
        <p role="status" className={box}>
          lodeline-server does not serve release files. To serve them, its operator sets{' '}
          <code>artifacts_dir</code> in <code>server.yaml</code> and copies the release files into
          that folder. See section 5.1 of <code>docs/install-server.md</code>.
        </p>
      ) : files.isError ? (
        <p role="alert" className={box}>
          Could not load the file list. {readAPIError(files.error)}
        </p>
      ) : files.data.artifacts.length === 0 ? (
        <p role="status" className={`${box} text-text-muted`}>
          The <code>artifacts_dir</code> of lodeline-server holds no files.
        </p>
      ) : (
        <ul className="divide-y divide-border-subtle rounded-md border border-border bg-bg-surface">
          {files.data.artifacts.map((name) => (
            <li key={name} className="px-3 py-2 text-xs">
              <a
                href={artifactURL(name)}
                download={name}
                className="font-mono text-accent hover:underline"
              >
                {name}
              </a>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
