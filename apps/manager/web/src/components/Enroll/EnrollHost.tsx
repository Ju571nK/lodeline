import { useMutation, useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { type FormEvent, type ReactNode, useEffect, useRef, useState } from 'react';
import { me } from '@/api/auth';
import { ApiError } from '@/api/client';
import {
  type EnrollmentStatus,
  enrollmentStatus,
  isCanonicalV4,
  type MadeFile,
  makeEnrollmentFile,
} from '@/api/enrollment';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { enrollErrorText, fileStillValid, hostIdExists, stoppedHost } from './enrollErrors';

const box = 'rounded-md border border-border bg-bg-surface p-6 text-sm';
const cell = 'px-3 py-2 align-top';
const mono = 'font-mono text-xs break-all';

type Ready = Extract<EnrollmentStatus, { enabled: true }>;

/** The page for a signed-in operator who makes a host's single-use enrollment file (#553). */
export function EnrollHost() {
  const status = useQuery({
    queryKey: ['enrollment'],
    queryFn: ({ signal }) => enrollmentStatus(signal),
    retry: false,
    // The status holds no secret, but a stale one could hide that the settings changed.
    gcTime: 0,
  });
  return (
    <div className="space-y-3">
      <h1 className="text-lg font-semibold text-text-primary">Enroll a host</h1>
      {status.isPending ? (
        <p role="status" className={`${box} text-text-muted`}>
          Loading the enrollment settings…
        </p>
      ) : status.isError ? (
        <p role="alert" className={box}>
          Could not load the enrollment settings.{' '}
          {enrollErrorText(
            status.error instanceof ApiError ? status.error.code : 'network',
            status.error.message,
          )}
        </p>
      ) : !status.data.enabled ? (
        <p role="status" className={box}>
          This console cannot make enrollment files yet. Its operator sets{' '}
          {status.data.missing.map((name, i) => (
            <span key={name}>
              {i > 0 && ', '}
              <code>{name}</code>
            </span>
          ))}
          . See the Enroll a host section of the console's <code>README.md</code>.
        </p>
      ) : !status.data.can_enroll ? (
        <NotAllowed />
      ) : (
        <Ready info={status.data} />
      )}
    </div>
  );
}

function NotAllowed() {
  const who = useQuery({ queryKey: ['auth', 'me'], queryFn: me, retry: false });
  return (
    <p role="status" className={box}>
      The signed-in subject{' '}
      {who.data ? <code className={mono}>{who.data.username}</code> : 'of this session'} is not on
      the enroll list, so it cannot make enrollment files. The operator of the console adds it to{' '}
      <code>LODELINE_ENROLL_SUBJECTS</code>.
    </p>
  );
}

/** A box that takes the focus when it appears, so a keyboard user lands on the answer. */
function Answer({
  role,
  label,
  className,
  children,
}: {
  role: 'alert' | 'status';
  label?: string;
  className: string;
  children: ReactNode;
}) {
  const ref = useRef<HTMLElement>(null);
  useEffect(() => ref.current?.focus(), []);
  return (
    <section ref={ref} tabIndex={-1} role={role} aria-label={label} className={className}>
      {children}
    </section>
  );
}

function Ready({ info }: { info: Ready }) {
  const [hostId, setHostId] = useState('');
  const [badHostId, setBadHostId] = useState(false);
  const busy = useRef(false);
  const make = useMutation({
    mutationFn: makeEnrollmentFile,
    onSettled: () => {
      busy.current = false;
    },
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    if (busy.current) return;
    const given = hostId.trim();
    if (given && !isCanonicalV4(given)) {
      setBadHostId(true);
      return;
    }
    setBadHostId(false);
    busy.current = true;
    make.mutate(given || undefined);
  }

  const error = make.error;
  return (
    <form onSubmit={submit} className="space-y-3">
      <p className="text-sm text-text-muted">
        The enrollment file is a JSON file with a single-use token, and what a new host needs to
        trust: the server's CA certificates and its policy keys. It holds no private key. Copy it to
        the host, and <code>lodeline-sender enroll</code> turns it into the host's certificate.
      </p>
      <FileTable info={info} />
      <div className="space-y-1">
        <Label htmlFor="enroll-host-id">Host id (only to repeat an enrollment that stopped)</Label>
        <Input
          id="enroll-host-id"
          value={hostId}
          onChange={(e) => setHostId(e.target.value)}
          className="max-w-md border-border bg-bg-surface font-mono text-text-primary"
          autoComplete="off"
          spellCheck={false}
          aria-describedby="enroll-host-id-help"
          aria-invalid={badHostId}
        />
        <p id="enroll-host-id-help" className="text-xs text-text-muted">
          Leave it empty to make a new host id. {stoppedHost}
        </p>
        {badHostId && (
          <p role="alert" className="text-xs">
            {enrollErrorText('invalid_host_id', '')}
          </p>
        )}
      </div>
      <Button type="submit" disabled={make.isPending}>
        {make.isPending ? 'Making the file…' : 'Make an enrollment file'}
      </Button>
      {error && (
        <Answer role="alert" className={box}>
          {enrollErrorText(error instanceof ApiError ? error.code : 'network', error.message)}
        </Answer>
      )}
      {make.data && <Made file={make.data} />}
    </form>
  );
}

function FileTable({ info }: { info: Ready }) {
  return (
    <section aria-labelledby="enroll-holds" className="space-y-1">
      <h2 id="enroll-holds" className="text-sm font-semibold text-text-primary">
        What the file will hold
      </h2>
      <table className="w-full rounded-md border border-border bg-bg-surface text-xs">
        <thead>
          <tr className="border-b border-border-subtle text-left text-text-muted">
            <th scope="col" className={cell}>
              Item
            </th>
            <th scope="col" className={cell}>
              Value
            </th>
            <th scope="col" className={cell}>
              SHA-256
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border-subtle">
          <tr>
            <th scope="row" className={`${cell} text-left font-normal`}>
              Server URL
            </th>
            <td className={`${cell} ${mono}`}>{info.server_url}</td>
            <td className={cell} />
          </tr>
          <tr>
            <th scope="row" className={`${cell} text-left font-normal`}>
              Enrollment URL
            </th>
            <td className={`${cell} ${mono}`}>{info.enroll_url}</td>
            <td className={cell} />
          </tr>
          {info.ca.map((c) => (
            <tr key={c.sha256}>
              <th scope="row" className={`${cell} text-left font-normal`}>
                CA certificate
              </th>
              <td className={`${cell} ${mono}`}>{c.subject}</td>
              <td className={`${cell} ${mono}`}>{c.sha256}</td>
            </tr>
          ))}
          {info.policy_keys.map((k) => (
            <tr key={`${k.id}-${k.sha256}`}>
              <th scope="row" className={`${cell} text-left font-normal`}>
                Policy key
              </th>
              <td className={cell}>
                <span className={mono}>{k.id}</span>, valid from {when(k.valid_from)} until{' '}
                {when(k.valid_until)}
              </td>
              <td className={`${cell} ${mono}`}>{k.sha256}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

const when = (iso: string) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, { timeZoneName: 'short' });
};

/** After a file was made: what it is, and the steps on the host. Shows no token. */
function Made({ file }: { file: MadeFile }) {
  const { name, host_id: hostId, expires_at: expiresAt } = file;
  const missing = [hostId ? '' : 'host id', expiresAt ? '' : 'expiry']
    .filter(Boolean)
    .map((w) => `the ${w}`)
    .join(' and ');
  return (
    <Answer role="status" label="The file was made" className={`${box} space-y-3`}>
      <p>
        Your browser was given <code>{name}</code> to save.
        {hostId && (
          <>
            {' '}
            Host id: <code className={mono}>{hostId}</code>.
          </>
        )}
        {expiresAt && <> Valid until {when(expiresAt)}.</>}
      </p>
      {missing && (
        <p>
          The answer did not carry {missing}. A proxy in front of the console may have removed the
          headers <code>X-Lodeline-Enroll-Host-Id</code> and{' '}
          <code>X-Lodeline-Enroll-Expires-At</code>. The values are the <code>host_id</code> and{' '}
          <code>expires_at</code> fields of the saved file.
        </p>
      )}
      <p>
        This file is a secret until the host uses it or it expires. It works once. The console did
        not keep a copy.
      </p>
      <ol className="list-decimal space-y-1 pl-5">
        <li>Copy the file to the host over a channel you trust, and keep it at mode 0600.</li>
        <li>
          Install <code>lodeline</code> and <code>lodeline-sender</code> on the host from the
          packages, which you can get from{' '}
          <Link to="/downloads" className="text-accent hover:underline">
            Downloads
          </Link>
          .
        </li>
        <li>
          Run <code>sudo lodeline-sender enroll {name}</code>. It prints the CA and policy key
          fingerprints before it writes anything. Compare them with the table above.
        </li>
        <li>
          Run <code>sudo systemctl enable --now lodeline lodeline-sender</code>.
        </li>
      </ol>
      <p className="text-text-muted">
        This is the command for a Linux host installed from the packages. On macOS,{' '}
        <code>enroll</code> needs its path flags (section 3.3 of <code>docs/install-server.md</code>
        ). Windows is not supported yet.
      </p>
      <div className="space-y-1">
        <h2 className="font-semibold text-text-primary">When it does not work</h2>
        <p>{stoppedHost}</p>
        <p>{hostIdExists}</p>
        <p>{fileStillValid}</p>
      </div>
    </Answer>
  );
}
