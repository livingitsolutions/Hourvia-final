import { THRIVESOURCE_ORGANIZATION_ID, THRIVESOURCE_SYSTEM_CONTEXT, parseOrganizationId, type Organization, type OrganizationContext, type OrganizationId } from '../../src/domain/organization';
import type { PlatformPrivilege, Role } from '../../src/domain/permissions';
import { isPlatformPrivilege, type PlatformAuditDetail, type PlatformAuditEvent, type PlatformAuditPage, type PlatformOverview } from '../../src/domain/platform';
import { organizationScopedSqlClient } from './tenant-sql';
import type { AuditEvent, AuthStore, MemberRecord, SessionRecord, SqlClient } from './types';

interface MemberRow { id: string; workspace_id: string; organization_id: string; auth_user_id: string | null; email: string; display_name: string; role: Role; status: MemberRecord['status']; approval_authorized: boolean; created_at: Date | string }
const MEMBER_COLUMNS = 'm.id, m.workspace_id, m.organization_id, m.auth_user_id, m.email, m.display_name, m.role, m.status, m.approval_authorized, m.created_at';
function rowOrganization(value: string): OrganizationId {
  const id = parseOrganizationId(value);
  if (!id) throw new Error('invalid_organization_id');
  return id;
}
const toMember = (row: MemberRow): MemberRecord => ({
  id: row.id, workspaceId: row.workspace_id, organizationId: rowOrganization(row.organization_id), authUserId: row.auth_user_id, email: row.email, displayName: row.display_name,
  role: row.role, status: row.status, approvalAuthorized: row.approval_authorized, createdAt: new Date(row.created_at),
});

interface OverviewJson {
  grant: { privilege: string; granted_at: string; approval_ref: string } | null; designated_at: string | null;
  grant_history?: { granted?: number; revoked?: number };
  organizations?: ({ id: string; members?: Record<string, number>; active_roles?: Record<string, number> } | null)[];
  audit?: { events?: number; last_event_at?: string | null };
}
interface AuditPageJson { events: { id: number; occurred_at: string; event_type: string; outcome: string; subject_is_holder: boolean; subject_suffix: string | null; details: unknown }[]; has_more: boolean }
const num = (value: unknown) => { const n = Number(value ?? 0); return Number.isFinite(n) ? n : 0; };
const iso = (value: unknown) => (value == null ? null : new Date(String(value)).toISOString());
/** Only known, scalar audit detail keys leave the server; anything else in the jsonb is dropped. */
const AUDIT_DETAIL_KEYS = ['privilege', 'grant_id', 'approval_ref', 'reason', 'source', 'before_id', 'limit', 'returned'] as const;
function auditDetails(value: unknown): Record<string, PlatformAuditDetail> {
  const out: Record<string, PlatformAuditDetail> = {};
  if (!value || typeof value !== 'object' || Array.isArray(value)) return out;
  for (const key of AUDIT_DETAIL_KEYS) {
    const v = (value as Record<string, unknown>)[key];
    if (v === null || typeof v === 'number' || typeof v === 'boolean') out[key] = v;
    else if (typeof v === 'string') out[key] = v.slice(0, 120);
  }
  return out;
}

/**
 * Every query is parameterized and pinned by the server, never by input, to the store's organization context and its
 * legacy workspace key (Sprint 2.0B; Sprint 3.0 derives the workspace key from the context instead of a constant). All statements pass through organizationScopedSqlClient, which refuses any
 * tenant-table statement without an organization predicate bound to that context, before the statement policy runs.
 */
export class PostgresAuthStore implements AuthStore {
  private readonly sql: SqlClient;
  private readonly org: OrganizationId;
  /** The context's legacy workspace key (its immutable slug). 'thrivesource' in the ThriveSource context. */
  private readonly ws: string;
  /**
   * Sprint 3.0: outside ThriveSource, INSERTs name organization_id explicitly (bound to the context by tenant-sql).
   * That needs the M8 INSERT grant; without M8 such an INSERT is refused by the database (fail closed). ThriveSource
   * keeps the M7 default-derived INSERTs, so the current production schema and grants are unaffected.
   */
  private readonly explicitOrganization: boolean;
  constructor(sql: SqlClient, readonly context: OrganizationContext = THRIVESOURCE_SYSTEM_CONTEXT) {
    this.sql = organizationScopedSqlClient(sql, context);
    this.explicitOrganization = context.organizationId !== THRIVESOURCE_ORGANIZATION_ID;
    this.org = context.organizationId;
    this.ws = context.legacyWorkspaceId;
  }

  async organization(): Promise<Organization | null> {
    const { rows } = await this.sql.query<{ id: string; slug: string; name: string; kind: Organization['kind']; status: Organization['status'] }>(
      `SELECT o.id, o.slug, o.name, o.kind, o.status FROM organizations o WHERE o.id = $1`, [this.org]);
    const row = rows[0];
    return row ? { id: rowOrganization(row.id), slug: row.slug, name: row.name, kind: row.kind, status: row.status } : null;
  }

  private async member(where: string, value: unknown): Promise<MemberRecord | null> {
    const { rows } = await this.sql.query<MemberRow>(`SELECT ${MEMBER_COLUMNS} FROM workspace_members m WHERE m.workspace_id = $1 AND m.organization_id = $3 AND ${where} LIMIT 1`, [this.ws, value, this.org]);
    return rows[0] ? toMember(rows[0]) : null;
  }
  findMemberById(id: string) { return this.member('m.id = $2', id); }
  findMemberByEmail(email: string) { return this.member('m.email = $2', email.toLowerCase()); }
  findMemberByAuthUserId(authUserId: string) { return this.member('m.auth_user_id = $2', authUserId); }

  async listMembers() {
    const { rows } = await this.sql.query<MemberRow>(`SELECT ${MEMBER_COLUMNS} FROM workspace_members m WHERE m.workspace_id = $1 AND m.organization_id = $2 ORDER BY m.created_at, m.email`, [this.ws, this.org]);
    return rows.map(toMember);
  }

  async assignedContractorIds(managerMemberId: string) {
    const { rows } = await this.sql.query<{ id: string }>(
      `SELECT c.id FROM manager_assignments a JOIN workspace_members c ON c.id = a.contractor_member_id
       WHERE a.workspace_id = $1 AND c.workspace_id = $1 AND a.organization_id = $3 AND c.organization_id = $3
         AND a.manager_member_id = $2 AND c.role = 'contractor' AND c.status = 'active' ORDER BY c.id`,
      [this.ws, managerMemberId, this.org]);
    return rows.map(row => row.id);
  }

  async platformPrivileges(authUserId: string) {
    const { rows } = await this.sql.query<{ privilege: PlatformPrivilege }>(
      `SELECT DISTINCT privilege FROM platform_privileges WHERE auth_user_id = $1 AND revoked_at IS NULL ORDER BY privilege`, [authUserId]);
    // Allowlist on top of the database CHECK: an unknown value can never become a privilege in the principal.
    return rows.map(row => row.privilege).filter(isPlatformPrivilege);
  }

  async platformOverview(sessionTokenHash: string): Promise<PlatformOverview | null> {
    const { rows } = await this.sql.query<{ o: OverviewJson | null }>(`SELECT hourvia_platform_overview($1) AS o`, [sessionTokenHash]);
    const o = rows[0]?.o;
    if (!o || !o.grant || !isPlatformPrivilege(o.grant.privilege)) return null;
    return {
      grant: { privilege: o.grant.privilege, grantedAt: iso(o.grant.granted_at)!, approvalRef: String(o.grant.approval_ref) },
      designatedAt: iso(o.designated_at),
      grantHistory: { granted: num(o.grant_history?.granted), revoked: num(o.grant_history?.revoked) },
      organizations: (o.organizations ?? []).flatMap(org => org ? [org] : []).map(org => ({
        id: String(org.id),
        members: { active: num(org.members?.active), invited: num(org.members?.invited), disabled: num(org.members?.disabled) },
        activeRoles: { workspace_admin: num(org.active_roles?.workspace_admin), workspace_manager: num(org.active_roles?.workspace_manager), contractor: num(org.active_roles?.contractor) },
      })),
      audit: { events: num(o.audit?.events), lastEventAt: iso(o.audit?.last_event_at) },
    };
  }

  async platformAuditPage(sessionTokenHash: string, page: { beforeId: number | null; limit: number }): Promise<PlatformAuditPage | null> {
    const { rows } = await this.sql.query<{ p: AuditPageJson | null }>(`SELECT hourvia_platform_audit_page($1, $2::bigint, $3::integer) AS p`, [sessionTokenHash, page.beforeId, page.limit]);
    const p = rows[0]?.p;
    if (!p || !Array.isArray(p.events)) return null;
    const events: PlatformAuditEvent[] = p.events.map(e => ({
      id: num(e.id), occurredAt: iso(e.occurred_at)!, eventType: String(e.event_type),
      outcome: e.outcome === 'success' || e.outcome === 'denied' ? e.outcome : 'error',
      subjectIsHolder: e.subject_is_holder === true, subjectSuffix: typeof e.subject_suffix === 'string' ? e.subject_suffix : null,
      details: auditDetails(e.details),
    }));
    return { events, hasMore: p.has_more === true, nextBefore: p.has_more === true && events.length ? events[events.length - 1]!.id : null };
  }

  upsertInvitation(input: { email: string; role: Role; displayName: string; authUserId: string; invitedBy: string | null; now: Date; expiresAt: Date }) {
    return this.sql.transaction(async tx => {
      const { rows } = await tx.query<MemberRow>(
        `INSERT INTO workspace_members AS m (workspace_id, auth_user_id, email, display_name, role, status, created_at${this.explicitOrganization ? ', organization_id' : ''})
         VALUES ($1, $2, $3, $4, $5, 'invited', $6${this.explicitOrganization ? ', $8' : ''})
         ON CONFLICT (workspace_id, email) DO UPDATE SET role = EXCLUDED.role, display_name = EXCLUDED.display_name,
           role_changed_by = CASE WHEN m.role IS DISTINCT FROM EXCLUDED.role THEN $7::uuid ELSE m.role_changed_by END,
           role_changed_at = CASE WHEN m.role IS DISTINCT FROM EXCLUDED.role THEN $6 ELSE m.role_changed_at END
           WHERE m.status = 'invited' AND m.auth_user_id = EXCLUDED.auth_user_id
         RETURNING ${MEMBER_COLUMNS}`,
        [this.ws, input.authUserId, input.email.toLowerCase(), input.displayName, input.role, input.now, input.invitedBy, ...(this.explicitOrganization ? [this.org] : [])]);
      const row = rows[0];
      if (!row) throw new Error('member_not_invitable');
      // The member row (new or existing) must belong to this store's organization before anything is attached to it.
      if (row.organization_id !== this.org) throw new Error('member_organization_mismatch');
      await tx.query(`UPDATE workspace_invitations SET status = 'revoked' WHERE workspace_id = $1 AND organization_id = $3 AND member_id = $2 AND status = 'pending'`, [this.ws, row.id, this.org]);
      await tx.query(
        `INSERT INTO workspace_invitations (workspace_id, member_id, email, role, status, invited_by_member_id, created_at, expires_at${this.explicitOrganization ? ', organization_id' : ''})
         VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7${this.explicitOrganization ? ', $8' : ''})`,
        [this.ws, row.id, row.email, input.role, input.invitedBy, input.now, input.expiresAt, ...(this.explicitOrganization ? [this.org] : [])]);
      return toMember(row);
    });
  }

  async hasPendingInvitation(memberId: string, now: Date) {
    const { rows } = await this.sql.query(`SELECT 1 FROM workspace_invitations WHERE workspace_id = $1 AND organization_id = $4 AND member_id = $2 AND status = 'pending' AND expires_at > $3`, [this.ws, memberId, now, this.org]);
    return rows.length > 0;
  }

  acceptInvitation(memberId: string, now: Date) {
    return this.sql.transaction(async tx => {
      // Sprint 1.9C.1 lock order, shared by every membership write (upsertInvitation, disableMember, this): the
      // workspace_members row first, then its invitations. Without it, accept (invitation → member) and disable
      // (member → invitation) on the same member could deadlock. FOR NO KEY UPDATE is the lock the activation UPDATE
      // below takes anyway, so foreign-key inserts that reference the member (sessions, audit) are not blocked.
      const locked = await tx.query(`SELECT id FROM workspace_members WHERE workspace_id = $1 AND organization_id = $3 AND id = $2 FOR NO KEY UPDATE`, [this.ws, memberId, this.org]);
      if (locked.rows.length !== 1) return false;
      const accepted = await tx.query(
        `UPDATE workspace_invitations SET status = 'accepted', accepted_at = $3
         WHERE workspace_id = $1 AND organization_id = $4 AND member_id = $2 AND status = 'pending' AND expires_at > $3 RETURNING id`, [this.ws, memberId, now, this.org]);
      if (accepted.rows.length !== 1) return false;
      const activated = await tx.query(
        `UPDATE workspace_members SET status = 'active', activated_at = $3
         WHERE workspace_id = $1 AND organization_id = $4 AND id = $2 AND status = 'invited' AND auth_user_id IS NOT NULL RETURNING id`, [this.ws, memberId, now, this.org]);
      if (activated.rows.length !== 1) throw new Error('member_not_activatable');
      return true;
    });
  }

  /** Sprint 1.9C: one transaction, so a disabled member can never be left with a pending invitation. */
  async disableMember(memberId: string, disabledBy: string, now: Date) {
    return (await this.disableMemberAndRevokeSessions(memberId, disabledBy, now)).changed;
  }

  /**
   * Sprint 3.0.2 (G1): disabling a member and ending its sessions are ONE transaction. Before, they were two, so a
   * failure between them left a disabled member with live session rows, which an operator reinstatement would bring
   * back into force.
   *
   * Sprint 3.0.3 lock order. The database-wide order for session revocation is: member row, then the per-organization
   * 'hourvia_sessions:<org>' advisory lock (M8), then session rows. Organization suspension takes the advisory lock and
   * then the session rows. Sprint 3.0.2 swept the session rows BEFORE the member UPDATE, whose M8 trigger then waited
   * for the advisory lock. Suspension, holding that lock and waiting for the same session rows, deadlocked with it.
   * The order is now:
   *   1. lock the member row FOR NO KEY UPDATE (the lock the status UPDATE takes anyway). If the member is already
   *      disabled, sweep any leftover unrevoked session (from a pre-3.0.2 disable or an M7 login race) and stop;
   *   2. disable the member. On M8 its trigger takes the exclusive session lock and revokes every unrevoked session,
   *      including one committed concurrently, attributed to disabled_by;
   *   3. count the sessions that trigger revoked in this transaction (revoked_at = now(), the trigger's timestamp);
   *   4. explicitly sweep anything still unrevoked. On M7, which has no trigger, this does all the work. On M8 it finds
   *      nothing, because the exclusive lock is held until COMMIT and the insert guard refuses sessions for a disabled member;
   *   5. revoke pending invitations.
   * Any failure rolls back everything, leaving the member, its sessions and its invitations exactly as they were.
   */
  disableMemberAndRevokeSessions(memberId: string, disabledBy: string, now: Date): Promise<{ changed: boolean; sessionsRevoked: number }> {
    return this.sql.transaction(async tx => {
      const locked = await tx.query<{ id: string; status: string }>(
        `SELECT id, status FROM workspace_members WHERE workspace_id = $1 AND organization_id = $3 AND id = $2 AND id <> $4 FOR NO KEY UPDATE`, [this.ws, memberId, this.org, disabledBy]);
      if (locked.rows.length !== 1) return { changed: false, sessionsRevoked: 0 };
      const sweep = () => tx.query(
        `UPDATE auth_sessions SET revoked_at = $2, revoked_reason = 'member_disabled', revoked_by_member_id = $3
         WHERE member_id = $1 AND organization_id = $4 AND revoked_at IS NULL RETURNING id`, [memberId, now, disabledBy, this.org]);
      if (locked.rows[0]!.status === 'disabled') return { changed: false, sessionsRevoked: (await sweep()).rows.length };
      const { rows } = await tx.query(
        `UPDATE workspace_members SET status = 'disabled', disabled_at = $3, disabled_by = $4
         WHERE workspace_id = $1 AND organization_id = $5 AND id = $2 AND status <> 'disabled' AND id <> $4 RETURNING id`, [this.ws, memberId, now, disabledBy, this.org]);
      if (rows.length !== 1) throw new Error('member_not_disableable');
      // Read before the sweep, so a sweep row can never be counted twice, even if the application clock equals now().
      const byTrigger = await tx.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM auth_sessions WHERE member_id = $1 AND organization_id = $3 AND revoked_reason = 'member_disabled'
           AND revoked_by_member_id = $2 AND revoked_at = now()`, [memberId, disabledBy, this.org]);
      const swept = await sweep();
      await tx.query(`UPDATE workspace_invitations SET status = 'revoked' WHERE workspace_id = $1 AND organization_id = $3 AND member_id = $2 AND status = 'pending'`, [this.ws, memberId, this.org]);
      return { changed: true, sessionsRevoked: Number(byTrigger.rows[0]?.n ?? 0) + swept.rows.length };
    });
  }

  async changeMemberRole(input: { memberId: string; expectedRole: Role; role: Role; changedBy: string; now: Date }) {
    // The guard trigger re-checks the actor's authority, so a bug here cannot grant Administrator access.
    const { rows } = await this.sql.query(
      `UPDATE workspace_members SET role = $3, role_changed_by = $5, role_changed_at = $6
       WHERE workspace_id = $1 AND organization_id = $7 AND id = $2 AND role = $4 AND status = 'active' AND id <> $5 RETURNING id`,
      [this.ws, input.memberId, input.role, input.expectedRole, input.changedBy, input.now, this.org]);
    return rows.length === 1;
  }

  async createSession(input: { tokenHash: string; memberId: string; now: Date; idleExpiresAt: Date; absoluteExpiresAt: Date }) {
    await this.sql.query(
      `INSERT INTO auth_sessions (token_hash, member_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at${this.explicitOrganization ? ', organization_id' : ''}) VALUES ($1, $2, $3, $3, $4, $5${this.explicitOrganization ? ', $6' : ''})`,
      [input.tokenHash, input.memberId, input.now, input.idleExpiresAt, input.absoluteExpiresAt, ...(this.explicitOrganization ? [this.org] : [])]);
  }

  async resolveSession(tokenHash: string, now: Date): Promise<SessionRecord | null> {
    const { rows } = await this.sql.query<MemberRow & { session_id: string; last_seen_at: Date | string; absolute_expires_at: Date | string }>(
      `SELECT s.id AS session_id, s.last_seen_at, s.absolute_expires_at, ${MEMBER_COLUMNS}
       FROM auth_sessions s JOIN workspace_members m ON m.id = s.member_id AND m.organization_id = s.organization_id
         JOIN organizations o ON o.id = m.organization_id
       WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.idle_expires_at > $2 AND s.absolute_expires_at > $2
         AND m.workspace_id = $3 AND m.status = 'active'
         AND s.organization_id = $4 AND m.organization_id = $4 AND o.id = $4 AND o.status = 'active' LIMIT 1`, [tokenHash, now, this.ws, this.org]);
    const row = rows[0];
    return row ? { sessionId: row.session_id, member: toMember(row), lastSeenAt: new Date(row.last_seen_at), absoluteExpiresAt: new Date(row.absolute_expires_at) } : null;
  }

  async touchSession(sessionId: string, now: Date, idleExpiresAt: Date) {
    await this.sql.query(`UPDATE auth_sessions SET last_seen_at = $2, idle_expires_at = LEAST($3, absolute_expires_at) WHERE id = $1 AND organization_id = $4 AND revoked_at IS NULL`, [sessionId, now, idleExpiresAt, this.org]);
  }

  async revokeSession(tokenHash: string, reason: string, now: Date) {
    const { rows } = await this.sql.query<{ member_id: string }>(`UPDATE auth_sessions SET revoked_at = $2, revoked_reason = $3, revoked_by_member_id = member_id WHERE token_hash = $1 AND organization_id = $4 AND revoked_at IS NULL RETURNING member_id`, [tokenHash, now, reason, this.org]);
    return rows[0]?.member_id ?? null;
  }

  /**
   * Sprint 3.0.1 (organization switching): revokes this session only if it is still valid AND belongs to memberId, and
   * returns its absolute expiry. Exactly one caller can win: a concurrent UPDATE of the same row waits for the winner,
   * then re-evaluates "revoked_at IS NULL" and matches nothing. Null means the session was already revoked (logout,
   * administrator, suspension, another switch), expired, or is not memberId's. Meant to run inside the transaction that
   * issues the replacement, so either both happen or neither does.
   */
  async consumeSession(tokenHash: string, memberId: string, reason: string, now: Date): Promise<{ absoluteExpiresAt: Date } | null> {
    const { rows } = await this.sql.query<{ absolute_expires_at: Date | string }>(
      `UPDATE auth_sessions SET revoked_at = $2, revoked_reason = $3, revoked_by_member_id = member_id
       WHERE token_hash = $1 AND organization_id = $5 AND member_id = $4 AND revoked_at IS NULL
         AND idle_expires_at > $2 AND absolute_expires_at > $2 RETURNING absolute_expires_at`,
      [tokenHash, now, reason, memberId, this.org]);
    return rows.length === 1 ? { absoluteExpiresAt: new Date(rows[0]!.absolute_expires_at) } : null;
  }

  async revokeMemberSessions(memberId: string, reason: string, now: Date, revokedBy: string) {
    const { rows } = await this.sql.query(`UPDATE auth_sessions SET revoked_at = $2, revoked_reason = $3, revoked_by_member_id = $4 WHERE member_id = $1 AND organization_id = $5 AND revoked_at IS NULL RETURNING id`, [memberId, now, reason, revokedBy, this.org]);
    return rows.length;
  }

  async hitRateLimit(bucket: string, windowStart: Date) {
    const { rows } = await this.sql.query<{ hits: number }>(
      `INSERT INTO auth_rate_limits AS r (bucket, window_start, hits) VALUES ($1, $2, 1)
       ON CONFLICT (bucket, window_start) DO UPDATE SET hits = r.hits + 1 RETURNING hits`, [bucket, windowStart]);
    return Number(rows[0]?.hits ?? Number.MAX_SAFE_INTEGER);
  }

  async audit(event: AuditEvent, now: Date) {
    await this.sql.query(
      `INSERT INTO auth_audit_events (workspace_id, occurred_at, event_type, outcome, actor_member_id, subject_member_id, email_hmac, ip_hmac, details${this.explicitOrganization ? ', organization_id' : ''})
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb${this.explicitOrganization ? ', $10' : ''})`,
      [this.ws, now, event.eventType, event.outcome, event.actorMemberId ?? null, event.subjectMemberId ?? null, event.emailHmac ?? null, event.ipHmac ?? null, JSON.stringify(event.details ?? {}), ...(this.explicitOrganization ? [this.org] : [])]);
  }
}

