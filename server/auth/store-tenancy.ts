import { parseOrganizationId, type OrganizationContext, type OrganizationId } from '../../src/domain/organization';
import type { SeatCounts, SeatEntitlement, SeatPlan } from '../../src/domain/tenancy';
import { organizationScopedSqlClient } from './tenant-sql';
import type { SqlClient } from './types';
/**
 * Sprint 3.0 seat accounting, bound to one organization context like PostgresAuthStore. Reads the M8
 * organization_seat_entitlements table, so it is usable only once M8 is applied; before that every call fails
 * (relation missing), which callers treat as unavailable. Read-only: seats are enforced by the M8 guards.
 */
export class PostgresTenancyStore {
  private readonly scoped: SqlClient;
  private readonly org: OrganizationId;
  constructor(sql: SqlClient, readonly context: OrganizationContext) {
    this.scoped = organizationScopedSqlClient(sql, context);
    this.org = context.organizationId;
  }

  async seatEntitlement(): Promise<SeatEntitlement | null> {
    const { rows } = await this.scoped.query<{ organization_id: string; plan: SeatPlan; seat_limit: number | null; billing_expires_at: Date | string | null }>(
      `SELECT e.organization_id, e.plan, e.seat_limit, e.billing_expires_at FROM organization_seat_entitlements e WHERE e.organization_id = $1`, [this.org]);
    const row = rows[0];
    if (!row || parseOrganizationId(row.organization_id) !== this.org || (row.plan !== 'internal_unlimited' && row.plan !== 'standard')) return null;
    return { organizationId: this.org, plan: row.plan, seatLimit: row.seat_limit === null ? null : Number(row.seat_limit), billingExpiresAt: row.billing_expires_at === null ? null : new Date(row.billing_expires_at) };
  }

  async seatCounts(now: Date): Promise<SeatCounts> {
    const { rows } = await this.scoped.query<{ active: number; pending: number }>(
      `SELECT (SELECT count(*) FROM workspace_members m WHERE m.organization_id = $1 AND m.status = 'active')::int AS active,
              (SELECT count(*) FROM workspace_invitations i JOIN workspace_members w ON w.id = i.member_id AND w.organization_id = $1
                WHERE i.organization_id = $1 AND i.status = 'pending' AND i.expires_at > $2 AND w.status = 'invited')::int AS pending`, [this.org, now]);
    return { activeMembers: Number(rows[0]?.active ?? 0), pendingInvitations: Number(rows[0]?.pending ?? 0) };
  }
}
