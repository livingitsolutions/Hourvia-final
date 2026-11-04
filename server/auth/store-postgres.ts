import { WORKSPACE_ID, type PlatformPrivilege, type Role } from '../../src/domain/permissions';
import type { AuditEvent, AuthStore, MemberRecord, SessionRecord, SqlClient } from './types';

interface MemberRow { id: string; workspace_id: string; auth_user_id: string | null; email: string; display_name: string; role: Role; status: MemberRecord['status']; approval_authorized: boolean; created_at: Date | string }
const MEMBER_COLUMNS = 'm.id, m.workspace_id, m.auth_user_id, m.email, m.display_name, m.role, m.status, m.approval_authorized, m.created_at';
const toMember = (row: MemberRow): MemberRecord => ({
  id: row.id, workspaceId: row.workspace_id, authUserId: row.auth_user_id, email: row.email, displayName: row.display_name,
  role: row.role, status: row.status, approvalAuthorized: row.approval_authorized, createdAt: new Date(row.created_at),
});

/** Every query is parameterized and pinned to the ThriveSource workspace by the server, never by input. */
export class PostgresAuthStore implements AuthStore {
  constructor(private readonly sql: SqlClient) {}

  private async member(where: string, value: unknown): Promise<MemberRecord | null> {
    const { rows } = await this.sql.query<MemberRow>(`SELECT ${MEMBER_COLUMNS} FROM workspace_members m WHERE m.workspace_id = $1 AND ${where} LIMIT 1`, [WORKSPACE_ID, value]);
    return rows[0] ? toMember(rows[0]) : null;
  }
  findMemberById(id: string) { return this.member('m.id = $2', id); }
  findMemberByEmail(email: string) { return this.member('m.email = $2', email.toLowerCase()); }
  findMemberByAuthUserId(authUserId: string) { return this.member('m.auth_user_id = $2', authUserId); }

  async listMembers() {
    const { rows } = await this.sql.query<MemberRow>(`SELECT ${MEMBER_COLUMNS} FROM workspace_members m WHERE m.workspace_id = $1 ORDER BY m.created_at, m.email`, [WORKSPACE_ID]);
    return rows.map(toMember);
  }

  async assignedContractorIds(managerMemberId: string) {
    const { rows } = await this.sql.query<{ id: string }>(
      `SELECT c.id FROM manager_assignments a JOIN workspace_members c ON c.id = a.contractor_member_id
       WHERE a.workspace_id = $1 AND c.workspace_id = $1 AND a.manager_member_id = $2 AND c.role = 'contractor' AND c.status = 'active' ORDER BY c.id`,
      [WORKSPACE_ID, managerMemberId]);
    return rows.map(row => row.id);
  }

  async platformPrivileges(authUserId: string) {
    const { rows } = await this.sql.query<{ privilege: PlatformPrivilege }>(
      `SELECT DISTINCT privilege FROM platform_privileges WHERE auth_user_id = $1 AND revoked_at IS NULL ORDER BY privilege`, [authUserId]);
    return rows.map(row => row.privilege);
  }

  upsertInvitation(input: { email: string; role: Role; displayName: string; authUserId: string; invitedBy: string | null; now: Date; expiresAt: Date }) {
    return this.sql.transaction(async tx => {
      const { rows } = await tx.query<MemberRow>(
        `INSERT INTO workspace_members AS m (workspace_id, auth_user_id, email, display_name, role, status, created_at)
         VALUES ($1, $2, $3, $4, $5, 'invited', $6)
         ON CONFLICT (workspace_id, email) DO UPDATE SET role = EXCLUDED.role, display_name = EXCLUDED.display_name,
           role_changed_by = CASE WHEN m.role IS DISTINCT FROM EXCLUDED.role THEN $7::uuid ELSE m.role_changed_by END,
           role_changed_at = CASE WHEN m.role IS DISTINCT FROM EXCLUDED.role THEN $6 ELSE m.role_changed_at END
           WHERE m.status = 'invited' AND m.auth_user_id = EXCLUDED.auth_user_id
         RETURNING ${MEMBER_COLUMNS}`,
        [WORKSPACE_ID, input.authUserId, input.email.toLowerCase(), input.displayName, input.role, input.now, input.invitedBy]);
      const row = rows[0];
      if (!row) throw new Error('member_not_invitable');
      await tx.query(`UPDATE workspace_invitations SET status = 'revoked' WHERE workspace_id = $1 AND member_id = $2 AND status = 'pending'`, [WORKSPACE_ID, row.id]);
      await tx.query(
        `INSERT INTO workspace_invitations (workspace_id, member_id, email, role, status, invited_by_member_id, created_at, expires_at)
         VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7)`,
        [WORKSPACE_ID, row.id, row.email, input.role, input.invitedBy, input.now, input.expiresAt]);
      return toMember(row);
    });
  }

  async hasPendingInvitation(memberId: string, now: Date) {
    const { rows } = await this.sql.query(`SELECT 1 FROM workspace_invitations WHERE workspace_id = $1 AND member_id = $2 AND status = 'pending' AND expires_at > $3`, [WORKSPACE_ID, memberId, now]);
    return rows.length > 0;
  }

  acceptInvitation(memberId: string, now: Date) {
    return this.sql.transaction(async tx => {
      const accepted = await tx.query(
        `UPDATE workspace_invitations SET status = 'accepted', accepted_at = $3
         WHERE workspace_id = $1 AND member_id = $2 AND status = 'pending' AND expires_at > $3 RETURNING id`, [WORKSPACE_ID, memberId, now]);
      if (accepted.rows.length !== 1) return false;
      const activated = await tx.query(
        `UPDATE workspace_members SET status = 'active', activated_at = $3
         WHERE workspace_id = $1 AND id = $2 AND status = 'invited' AND auth_user_id IS NOT NULL RETURNING id`, [WORKSPACE_ID, memberId, now]);
      if (activated.rows.length !== 1) throw new Error('member_not_activatable');
      return true;
    });
  }

  async disableMember(memberId: string, disabledBy: string, now: Date) {
    const { rows } = await this.sql.query(
      `UPDATE workspace_members SET status = 'disabled', disabled_at = $3, disabled_by = $4
       WHERE workspace_id = $1 AND id = $2 AND status <> 'disabled' AND id <> $4 RETURNING id`, [WORKSPACE_ID, memberId, now, disabledBy]);
    if (rows.length) await this.sql.query(`UPDATE workspace_invitations SET status = 'revoked' WHERE workspace_id = $1 AND member_id = $2 AND status = 'pending'`, [WORKSPACE_ID, memberId]);
    return rows.length === 1;
  }

  async changeMemberRole(input: { memberId: string; expectedRole: Role; role: Role; changedBy: string; now: Date }) {
    // The guard trigger re-checks the actor's authority, so a bug here cannot grant Administrator access.
    const { rows } = await this.sql.query(
      `UPDATE workspace_members SET role = $3, role_changed_by = $5, role_changed_at = $6
       WHERE workspace_id = $1 AND id = $2 AND role = $4 AND status = 'active' AND id <> $5 RETURNING id`,
      [WORKSPACE_ID, input.memberId, input.role, input.expectedRole, input.changedBy, input.now]);
    return rows.length === 1;
  }

  async createSession(input: { tokenHash: string; memberId: string; now: Date; idleExpiresAt: Date; absoluteExpiresAt: Date }) {
    await this.sql.query(
      `INSERT INTO auth_sessions (token_hash, member_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at) VALUES ($1, $2, $3, $3, $4, $5)`,
      [input.tokenHash, input.memberId, input.now, input.idleExpiresAt, input.absoluteExpiresAt]);
  }

  async resolveSession(tokenHash: string, now: Date): Promise<SessionRecord | null> {
    const { rows } = await this.sql.query<MemberRow & { session_id: string; last_seen_at: Date | string; absolute_expires_at: Date | string }>(
      `SELECT s.id AS session_id, s.last_seen_at, s.absolute_expires_at, ${MEMBER_COLUMNS}
       FROM auth_sessions s JOIN workspace_members m ON m.id = s.member_id
       WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.idle_expires_at > $2 AND s.absolute_expires_at > $2
         AND m.workspace_id = $3 AND m.status = 'active' LIMIT 1`, [tokenHash, now, WORKSPACE_ID]);
    const row = rows[0];
    return row ? { sessionId: row.session_id, member: toMember(row), lastSeenAt: new Date(row.last_seen_at), absoluteExpiresAt: new Date(row.absolute_expires_at) } : null;
  }

  async touchSession(sessionId: string, now: Date, idleExpiresAt: Date) {
    await this.sql.query(`UPDATE auth_sessions SET last_seen_at = $2, idle_expires_at = LEAST($3, absolute_expires_at) WHERE id = $1 AND revoked_at IS NULL`, [sessionId, now, idleExpiresAt]);
  }

  async revokeSession(tokenHash: string, reason: string, now: Date) {
    const { rows } = await this.sql.query<{ member_id: string }>(`UPDATE auth_sessions SET revoked_at = $2, revoked_reason = $3, revoked_by_member_id = member_id WHERE token_hash = $1 AND revoked_at IS NULL RETURNING member_id`, [tokenHash, now, reason]);
    return rows[0]?.member_id ?? null;
  }

  async revokeMemberSessions(memberId: string, reason: string, now: Date, revokedBy: string) {
    const { rows } = await this.sql.query(`UPDATE auth_sessions SET revoked_at = $2, revoked_reason = $3, revoked_by_member_id = $4 WHERE member_id = $1 AND revoked_at IS NULL RETURNING id`, [memberId, now, reason, revokedBy]);
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
      `INSERT INTO auth_audit_events (workspace_id, occurred_at, event_type, outcome, actor_member_id, subject_member_id, email_hmac, ip_hmac, details)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)`,
      [WORKSPACE_ID, now, event.eventType, event.outcome, event.actorMemberId ?? null, event.subjectMemberId ?? null, event.emailHmac ?? null, event.ipHmac ?? null, JSON.stringify(event.details ?? {})]);
  }
}
