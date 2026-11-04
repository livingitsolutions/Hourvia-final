import { useCallback, useEffect, useState } from 'react';
import { Link, Outlet } from 'react-router-dom';
import { ShieldCheck } from 'lucide-react';
import { useAuth } from '../application/auth';
import { platformScreens } from '../application/navigation';
import { platformPrivilegeLabels, roleLabels } from '../domain/permissions';
import { platformAuthorization, type PlatformAuditEvent, type PlatformOverview as Overview } from '../domain/platform';
import { AuthRequestError } from '../infrastructure/server-session-auth';

/**
 * Platform Administration console (Sprint 1.8): read-only. Shown only for the platform.console permission, which
 * comes from the platform privilege alone, never from the workspace role. The server and the database re-authorize
 * every request; this gate only avoids offering what would be refused.
 */
export function PlatformRestricted() {
  return <section className="page"><span className="eyebrow muted">ACCESS RESTRICTED</span><h1>This page isn’t available to you.</h1><p>Platform Administration is available only to the Platform Super Admin.</p><Link to="/dashboard">Back to dashboard</Link></section>;
}

export function PlatformArea() {
  const { user } = useAuth();
  return platformAuthorization.can(user, 'platform.console') ? <Outlet/> : <PlatformRestricted/>;
}

const operatorNote = <p className="platform-note" role="note"><ShieldCheck size={16}/> <span>This console is read-only. Platform privileges are granted, revoked and reinstated only through the approved operator procedures, never from the application.</span></p>;
const when = (iso: string | null) => iso ? new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC' }) + ' UTC' : '—';
const organizationNames: Record<string, string> = { thrivesource: 'ThriveSource' };
function failure(cause: unknown): { restricted: boolean; message: string } {
  if (cause instanceof AuthRequestError && cause.status === 403) return { restricted: true, message: cause.message };
  return { restricted: false, message: cause instanceof AuthRequestError ? cause.message : 'Something went wrong. Try again.' };
}

export function PlatformOverview() {
  const { platform } = useAuth();
  const screen = platformScreens[0]!;
  const [data, setData] = useState<Overview | null>(null);
  const [error, setError] = useState<{ restricted: boolean; message: string } | null>(null);
  useEffect(() => {
    let active = true;
    if (!platform) { setError({ restricted: false, message: 'Platform Administration is not connected in this environment.' }); return; }
    platform.overview().then(o => { if (active) setData(o); }).catch(cause => { if (active) setError(failure(cause)); });
    return () => { active = false; };
  }, [platform]);
  if (error?.restricted) return <PlatformRestricted/>;
  return <section className="page">
    <span className="eyebrow muted">HOURVIA PLATFORM</span><h1>{screen.title}</h1><p>{screen.description}</p>
    {operatorNote}
    {error && <p className="form-error" role="alert">{error.message}</p>}
    {!data && !error && <p role="status">Loading platform overview…</p>}
    {data && <div className="platform-grid">
      <div className="settings-card">
        <h2>Privilege</h2>
        <dl className="platform-facts">
          <dt>Privilege</dt><dd>{platformPrivilegeLabels[data.grant.privilege]}</dd>
          <dt>Granted</dt><dd>{when(data.grant.grantedAt)}</dd>
          <dt>Approval reference</dt><dd><code>{data.grant.approvalRef}</code></dd>
          <dt>Identity designated</dt><dd>{when(data.designatedAt)}</dd>
          <dt>Grant history</dt><dd>{data.grantHistory.granted} granted · {data.grantHistory.revoked} revoked</dd>
        </dl>
      </div>
      <div className="settings-card">
        <h2>Platform audit</h2>
        <dl className="platform-facts">
          <dt>Recorded events</dt><dd>{data.audit.events}</dd>
          <dt>Latest event</dt><dd>{when(data.audit.lastEventAt)}</dd>
        </dl>
        <Link className="text-button" to="/platform/audit">Open the platform audit</Link>
      </div>
      <div className="settings-card platform-wide">
        <h2>Organizations</h2>
        <p>Aggregate counts only. Member records stay inside each organization’s own workspace administration.</p>
        <table className="platform-table">
          <thead><tr><th scope="col">Organization</th><th scope="col">Active</th><th scope="col">Invited</th><th scope="col">Disabled</th><th scope="col">{roleLabels.workspace_admin}s</th><th scope="col">{roleLabels.workspace_manager}s</th><th scope="col">{roleLabels.contractor}s</th></tr></thead>
          <tbody>{data.organizations.map(org => <tr key={org.id}>
            <th scope="row">{organizationNames[org.id] ?? org.id}</th><td>{org.members.active}</td><td>{org.members.invited}</td><td>{org.members.disabled}</td>
            <td>{org.activeRoles.workspace_admin}</td><td>{org.activeRoles.workspace_manager}</td><td>{org.activeRoles.contractor}</td>
          </tr>)}</tbody>
        </table>
      </div>
    </div>}
  </section>;
}

const eventLabels: Record<string, string> = {
  platform_designation_set: 'Identity designated',
  platform_privilege_granted: 'Privilege granted',
  platform_privilege_revoked: 'Privilege revoked',
  platform_audit_read: 'Platform audit viewed',
};
const PAGE_SIZE = 25;

export function PlatformAudit() {
  const { platform } = useAuth();
  const screen = platformScreens[1]!;
  const [events, setEvents] = useState<PlatformAuditEvent[] | null>(null);
  const [next, setNext] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<{ restricted: boolean; message: string } | null>(null);
  const load = useCallback(async (before: number | null) => {
    if (!platform) { setError({ restricted: false, message: 'Platform Administration is not connected in this environment.' }); return; }
    setBusy(true); setError(null);
    try {
      const page = await platform.audit({ before, limit: PAGE_SIZE });
      setEvents(current => before === null ? [...page.events] : [...(current ?? []), ...page.events]);
      setNext(page.nextBefore);
    } catch (cause) { setError(failure(cause)); }
    finally { setBusy(false); }
  }, [platform]);
  useEffect(() => { void load(null); }, [load]);
  if (error?.restricted) return <PlatformRestricted/>;
  return <section className="page">
    <span className="eyebrow muted">HOURVIA PLATFORM</span><h1>{screen.title}</h1><p>{screen.description}</p>
    {operatorNote}
    {error && <p className="form-error" role="alert">{error.message}</p>}
    {events === null && !error && <p role="status">Loading platform audit…</p>}
    {events && <div className="settings-card platform-wide">
      {!events.length ? <p>No platform events recorded.</p> : <table className="platform-table">
        <thead><tr><th scope="col">Time</th><th scope="col">Event</th><th scope="col">Outcome</th><th scope="col">Subject</th><th scope="col">Details</th></tr></thead>
        <tbody>{events.map(event => <tr key={event.id}>
          <td>{when(event.occurredAt)}</td>
          <th scope="row">{eventLabels[event.eventType] ?? event.eventType}</th>
          <td>{event.outcome}</td>
          <td>{event.subjectIsHolder ? 'You' : event.subjectSuffix ? `Identity …${event.subjectSuffix}` : '—'}</td>
          <td className="platform-details">{Object.entries(event.details).map(([key, value]) => <span key={key}><b>{key.replaceAll('_', ' ')}</b> {String(value)}</span>)}</td>
        </tr>)}</tbody>
      </table>}
      {next !== null && <button type="button" className="platform-more" disabled={busy} onClick={() => void load(next)}>{busy ? 'Loading…' : 'Load older events'}</button>}
    </div>}
  </section>;
}
