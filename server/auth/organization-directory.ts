import { parseOrganizationId, type OrganizationId, type OrganizationKind, type OrganizationStatus } from '../../src/domain/organization';
import { ORGANIZATION_ROLES, type Role } from '../../src/domain/permissions';
import { MEMBERSHIP_STATUSES, type MembershipStatus, type OrganizationMembership } from '../../src/domain/tenancy';
import { assertAllowedStatement } from './sql-role';
import type { SqlClient } from './types';

/**
 * Identity-scoped reads (Sprint 3.0): the only statements that read tenant tables ACROSS organizations.
 *
 * Organization selection needs two cross-organization reads: which membership a session belongs to, and which
 * memberships the session's identity holds. They cannot go through organizationScopedSqlClient (there is no
 * organization yet), so they get a stricter rule instead: the directory issues exactly the two fixed statements below
 * and nothing else (the client rejects any other text), and no method accepts an identity. The identity comes only from
 * the session row the first statement returns. The existing statement policy still applies to both.
 */
export const LOCATE_SESSION_SQL = `SELECT s.id AS session_id, s.member_id, s.organization_id, m.auth_user_id, m.workspace_id
 FROM auth_sessions s JOIN workspace_members m ON m.id = s.member_id AND m.organization_id = s.organization_id
 JOIN organizations o ON o.id = s.organization_id AND o.slug = m.workspace_id
 WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.idle_expires_at > $2 AND s.absolute_expires_at > $2
 AND m.status = 'active' AND m.auth_user_id IS NOT NULL AND o.status = 'active' LIMIT 1`;
export const IDENTITY_MEMBERSHIPS_SQL = `SELECT m.id AS member_id, m.organization_id, m.workspace_id, m.role, m.status,
 o.slug, o.name, o.kind, o.status AS organization_status
 FROM workspace_members m JOIN organizations o ON o.id = m.organization_id AND o.slug = m.workspace_id
 WHERE m.auth_user_id = $1 AND m.status IN ('active', 'suspended') ORDER BY o.name, o.id LIMIT 200`;
const IDENTITY_STATEMENTS = new Set([LOCATE_SESSION_SQL, IDENTITY_MEMBERSHIPS_SQL]);

export class IdentityStatementRejectedError extends Error {
  constructor(reason: string) { super(`identity_statement_rejected:${reason}`); this.name = 'IdentityStatementRejectedError'; }
}
/** Accepts only the two directory statements, with well-formed parameters. Never wraps a transaction. */
export function identityScopedSqlClient(inner: SqlClient): SqlClient {
  return {
    query: <T = Record<string, unknown>>(text: string, params?: unknown[]) => {
      try {
        assertAllowedStatement(text);
        if (!IDENTITY_STATEMENTS.has(text)) throw new IdentityStatementRejectedError('not_allowlisted');
        if (text === LOCATE_SESSION_SQL && !(typeof params?.[0] === 'string' && /^[0-9a-f]{64}$/.test(params[0]) && params[1] instanceof Date && params.length === 2)) {
          throw new IdentityStatementRejectedError('parameters');
        }
        if (text === IDENTITY_MEMBERSHIPS_SQL && !(typeof params?.[0] === 'string' && parseOrganizationId(params[0]) !== null && params.length === 1)) {
          throw new IdentityStatementRejectedError('parameters');
        }
      } catch (error) { return Promise.reject(error); }
      return inner.query<T>(text, params);
    },
    transaction: () => Promise.reject(new IdentityStatementRejectedError('transaction')),
  };
}

export interface LocatedSession { sessionId: string; memberId: string; organizationId: OrganizationId; workspaceId: string }
export interface ResolvedIdentity { session: LocatedSession; memberships: OrganizationMembership[] }

interface MembershipRow { member_id: string; organization_id: string; workspace_id: string; role: string; status: string; slug: string; name: string; kind: string; organization_status: string }
const ORG_KINDS: readonly string[] = ['internal', 'customer'];
const ORG_STATUSES: readonly string[] = ['provisioning', 'active', 'suspended', 'closed'];
/** Unknown values never become a membership: the row is dropped (fail closed). */
function toMembership(row: MembershipRow): OrganizationMembership | null {
  const organizationId = parseOrganizationId(row.organization_id);
  if (!organizationId || row.workspace_id !== row.slug || !(ORGANIZATION_ROLES as readonly string[]).includes(row.role)
    || !(MEMBERSHIP_STATUSES as readonly string[]).includes(row.status) || !ORG_KINDS.includes(row.kind) || !ORG_STATUSES.includes(row.organization_status)) return null;
  return {
    memberId: row.member_id, organizationId, role: row.role as Role, status: row.status as MembershipStatus,
    organization: { slug: row.slug, name: row.name, kind: row.kind as OrganizationKind, status: row.organization_status as OrganizationStatus },
  };
}

/** Requires the M8 schema (per-organization identities). Before M8 the identity has at most one membership anyway. */
export class IdentityDirectory {
  private readonly sql: SqlClient;
  /** inner is normally statementGuardedSqlClient(roleScopedSqlClient(pool)), exactly like the auth store. */
  constructor(inner: SqlClient) { this.sql = identityScopedSqlClient(inner); }

  /** The session's own membership and every active or suspended membership of the same identity. Null if the session is not valid. */
  async resolve(tokenHash: string, now: Date): Promise<ResolvedIdentity | null> {
    const located = await this.sql.query<{ session_id: string; member_id: string; organization_id: string; auth_user_id: string; workspace_id: string }>(LOCATE_SESSION_SQL, [tokenHash, now]);
    const row = located.rows[0];
    const organizationId = row ? parseOrganizationId(row.organization_id) : null;
    if (!row || !organizationId || !parseOrganizationId(row.auth_user_id)) return null;
    const listed = await this.sql.query<MembershipRow>(IDENTITY_MEMBERSHIPS_SQL, [row.auth_user_id]);
    const memberships = listed.rows.map(toMembership).filter((m): m is OrganizationMembership => m !== null);
    // The session's membership must be among them (same identity, same organization, active), or nothing is trusted.
    if (!memberships.some(m => m.memberId === row.member_id && m.organizationId === organizationId && m.status === 'active')) return null;
    return { session: { sessionId: row.session_id, memberId: row.member_id, organizationId, workspaceId: row.workspace_id }, memberships };
  }
}
