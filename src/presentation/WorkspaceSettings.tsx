import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { useAuth } from '../application/auth';
import type { screens } from '../application/navigation';
import { adminInviteSchema } from '../domain/contracts';
import { assignableRoles, canManageMember, hasPlatformPrivilege, roleLabels, type AssignableRole } from '../domain/permissions';
import { AuthRequestError, type WorkspaceMember } from '../infrastructure/server-session-auth';

const roleHelp: Record<AssignableRole, string> = {
  workspace_admin: 'Manages Managers, Contractors and workspace settings.',
  workspace_manager: 'Reviews assigned Contractors.',
  contractor: 'Tracks their own time.',
};

/**
 * Membership console. Every action is re-authorized by the server and by database guards; this view only offers
 * the actions the signed-in member may take: Administrators manage Managers and Contractors, and an Administrator
 * who also holds the Platform Super Admin privilege manages Administrators too. Platform privileges are never
 * offered here: they are granted only by the approved operator procedure.
 */
export function WorkspaceSettings({ screen }: { screen: typeof screens[number] }) {
  const { admin, user } = useAuth();
  const [members, setMembers] = useState<WorkspaceMember[] | null>(null);
  const [error, setError] = useState(''); const [notice, setNotice] = useState(''); const [fields, setFields] = useState<Record<string, string>>({}); const [busy, setBusy] = useState(false);
  const roles = assignableRoles(user);
  const platform = hasPlatformPrivilege(user, 'platform_super_admin');
  const report = (cause: unknown) => setError(cause instanceof AuthRequestError ? cause.message : 'Something went wrong. Try again.');
  const load = useCallback(async () => { if (!admin) return; try { setMembers(await admin.listMembers()); } catch (cause) { report(cause); } }, [admin]);
  useEffect(() => { void load(); }, [load]);
  async function invite(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setError(''); setNotice('');
    const form = event.currentTarget; const data = new FormData(form);
    const parsed = adminInviteSchema.safeParse({ email: data.get('invite-email'), role: data.get('invite-role'), displayName: String(data.get('invite-name') ?? '').trim() || undefined });
    if (!parsed.success) return setFields(Object.fromEntries(parsed.error.issues.map(i => [String(i.path[0]), i.message])));
    if (!roles.includes(parsed.data.role)) return setFields({ role: 'Your role cannot grant that access.' });
    if (!admin) return setError('Workspace administration is not connected in this environment.');
    setFields({}); setBusy(true);
    try { const member = await admin.invite(parsed.data); setNotice(`Invitation sent to ${member.email} as ${roleLabels[member.role]}.`); form.reset(); await load(); } catch (cause) { report(cause); } finally { setBusy(false); }
  }
  async function act(member: WorkspaceMember, action: 'disable' | 'revokeSessions') {
    if (!admin) return;
    if (action === 'disable' && !window.confirm(`Disable ${member.email}? They are signed out everywhere and cannot sign in again.`)) return;
    setError(''); setNotice('');
    try { await admin[action](member.id); setNotice(action === 'disable' ? `${member.email} was disabled and signed out.` : `All sessions for ${member.email} were ended.`); await load(); } catch (cause) { report(cause); }
  }
  async function changeRole(member: WorkspaceMember, role: AssignableRole) {
    if (!admin || role === member.role) return;
    const label = roleLabels[role];
    if (!window.confirm(`Change ${member.email} from ${roleLabels[member.role]} to ${label}? The new access applies immediately.`)) return;
    setError(''); setNotice('');
    try { await admin.changeRole(member.id, role); setNotice(`${member.email} is now ${label === 'Administrator' ? 'an' : 'a'} ${label}.`); await load(); } catch (cause) { report(cause); }
  }
  return <section className="page">
    <span className="eyebrow muted">THRIVESOURCE WORKSPACE</span><h1>{screen.title}</h1><p>{screen.description}</p>
    {user && <p className="settings-role" role="note">Signed in as <strong>{roleLabels[user.role]}</strong>{platform && <> with the <strong>Platform Super Admin</strong> privilege</>}. {platform ? 'You can invite, promote, demote and revoke Administrators, Managers and Contractors in this organization.' : 'You can manage Managers and Contractors. Only an Administrator with the Platform Super Admin privilege can grant or change Administrator access.'}</p>}
    <div className="settings-grid">
      <form className="settings-card" noValidate onSubmit={invite}>
        <h2>Invite a member</h2><p>Invitees receive an email and create their own password. Access is invitation-only.</p>
        <label htmlFor="invite-email">Work email</label><input id="invite-email" name="invite-email" type="email" placeholder="name@company.com" aria-invalid={!!fields.email}/>{fields.email && <p className="field-error">{fields.email}</p>}
        <label htmlFor="invite-name">Display name (optional)</label><input id="invite-name" name="invite-name" maxLength={120}/>
        <label htmlFor="invite-role">Role</label><select id="invite-role" name="invite-role" defaultValue="contractor" aria-invalid={!!fields.role}>{roles.map(role => <option key={role} value={role}>{roleLabels[role]} — {roleHelp[role]}</option>)}</select>{fields.role && <p className="field-error">{fields.role}</p>}
        <button className="primary-button" disabled={busy} type="submit">{busy ? 'Sending…' : 'Send invitation'}</button>
      </form>
      <div className="settings-card">
        <h2>Members</h2>
        {notice && <p className="form-notice" role="status">{notice}</p>}{error && <p className="form-error" role="alert">{error}</p>}
        {!members ? <p>Loading members…</p> : !members.length ? <p>No members yet.</p> : <ul className="member-list">{members.map(member => {
          const manageable = member.status !== 'disabled' && canManageMember(user, member);
          return <li key={member.id}>
            <div><strong>{member.name}</strong><span>{member.email}</span><small>{roleLabels[member.role] ?? member.role} · {member.status}{member.id === user?.id ? ' · you' : ''}</small></div>
            {manageable && <div className="member-actions">
              {member.status === 'active' && <select aria-label={`Role for ${member.email}`} value={member.role} onChange={event => void changeRole(member, event.target.value as AssignableRole)}>{roles.map(role => <option key={role} value={role}>{roleLabels[role]}</option>)}</select>}
              <button type="button" onClick={() => void act(member, 'revokeSessions')}>End sessions</button>
              <button type="button" className="danger" onClick={() => void act(member, 'disable')}>{member.role === 'workspace_admin' ? 'Revoke access' : 'Disable'}</button>
            </div>}
          </li>;
        })}</ul>}
      </div>
    </div>
  </section>;
}
