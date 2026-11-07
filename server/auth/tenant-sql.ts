import { THRIVESOURCE_ORGANIZATION_ID, type OrganizationContext } from '../../src/domain/organization';
import { assertAllowedStatement } from './sql-role';
import type { SqlClient } from './types';

/**
 * Organization-scoped SQL foundation (Sprint 2.0B).
 *
 * Every statement the auth store issues passes through organizationScopedSqlClient. Before it reaches the existing
 * statement policy (statementGuardedSqlClient, unchanged) and the database, the statement is checked lexically:
 *
 *   * every reference to a tenant table must be constrained by a positional predicate
 *     `<alias>.organization_id = $n` (for organizations itself, `<alias>.id = $n`) in a WHERE or ON clause;
 *   * the bound value of every such $n must equal the request's server-derived OrganizationContext, so a predicate
 *     cannot be satisfied with a different organization or an input value;
 *   * tenant statements may not contain OR, so a predicate cannot be bypassed with a disjunction;
 *   * organization_id may never be written: not in an INSERT column list, not in UPDATE … SET, not in
 *     ON CONFLICT … DO UPDATE SET. Tenant INSERTs take the column default, which M7 pins to ThriveSource, so they are
 *     accepted only while the context is ThriveSource. Sprint 2.0C replaces the default with an explicit, checked value;
 *   * schema-qualified or otherwise unrecognized references to a tenant table are refused;
 *   * INSERT, UPDATE or DELETE on organizations is refused (the database also denies it to the runtime role).
 *
 * Like the statement policy, this is a conservative lexical rule set, not a SQL parser. It enforces a coding
 * invariant for fixed-text store SQL; the database constraints added by M7 (composite foreign keys, legacy bridge
 * CHECKs, single-tenant CHECK, no runtime write privilege on organization_id) remain the authoritative boundary.
 */
export const TENANT_TABLES = ['workspace_members', 'workspace_invitations', 'manager_assignments', 'auth_sessions', 'auth_audit_events'] as const;
/** Sprint 3.0: tenant tables created by the M8 proposal (absent until M8 is applied). */
export const M8_TENANT_TABLES = ['organization_seat_entitlements'] as const;
/**
 * Reserved names for future organization-owned business tables (projects, time records, timesheets, billing). Any
 * statement that names one is held to the same organization predicate rules today, so they are tenant-scoped from the
 * first line of code that touches them.
 */
export const RESERVED_TENANT_TABLES = ['projects', 'time_entries', 'timesheets', 'clients', 'invoices', 'billing_rates'] as const;
/** Tables keyed by organization but scoped by their own primary key. */
export const ORGANIZATION_ROOT_TABLES = ['organizations'] as const;
/** Tables that are global by design: HMAC rate-limit buckets and the platform plane (keyed by Supabase identity). */
export const GLOBAL_TABLES = ['auth_rate_limits', 'platform_privileges', 'platform_super_admin_designation', 'platform_audit_events'] as const;

type ScopedTable = typeof TENANT_TABLES[number] | typeof M8_TENANT_TABLES[number] | typeof RESERVED_TENANT_TABLES[number] | typeof ORGANIZATION_ROOT_TABLES[number];
const SCOPE_COLUMN: Record<ScopedTable, string> = {
  workspace_members: 'organization_id', workspace_invitations: 'organization_id', manager_assignments: 'organization_id',
  auth_sessions: 'organization_id', auth_audit_events: 'organization_id', organizations: 'id',
  organization_seat_entitlements: 'organization_id',
  projects: 'organization_id', time_entries: 'organization_id', timesheets: 'organization_id', clients: 'organization_id',
  invoices: 'organization_id', billing_rates: 'organization_id',
};
const SCOPED = Object.keys(SCOPE_COLUMN) as ScopedTable[];
const NOT_AN_ALIAS = new Set(['where', 'set', 'on', 'join', 'left', 'right', 'inner', 'outer', 'cross', 'full', 'values', 'order', 'group',
  'limit', 'returning', 'using', 'for', 'select', 'default', 'natural', 'lateral', 'having', 'union', 'window', 'offset']);

export class TenantStatementRejectedError extends Error {
  constructor(reason: string) { super(`tenant_statement_rejected:${reason}`); this.name = 'TenantStatementRejectedError'; }
}

export interface TenantStatementAnalysis {
  /**
   * 'global': touches no tenant table. 'scoped': every tenant reference carries a predicate. 'default_insert': INSERT
   * relying on the M7 default. 'organization_insert' (Sprint 3.0, needs M8 grants): INSERT naming organization_id as a
   * bare positional parameter that must equal the context.
   */
  kind: 'global' | 'scoped' | 'default_insert' | 'organization_insert';
  tables: ScopedTable[];
  /** 1-based parameter positions that must carry the context's organization id. */
  organizationParams: number[];
}

interface Reference { table: ScopedTable; qualifier: string; clause: string; index: number }

/**
 * Options. allowOrganizationInsert (Sprint 3.0, default false) permits INSERTs that name organization_id as a bare
 * parameter, and (Sprint 3.0.1) REQUIRES it: with the option set, an INSERT without organization_id is rejected.
 * assertTenantStatement enables it exactly for contexts other than ThriveSource (they need the M8 grant); the
 * ThriveSource context keeps the Sprint 2.0B rule that organization_id is never written.
 */
export interface TenantStatementOptions { allowOrganizationInsert?: boolean }

/** Static (parameter-free) validation of one statement. Throws TenantStatementRejectedError on any violation. */
export function analyzeTenantStatement(text: string, options: TenantStatementOptions = {}): TenantStatementAnalysis {
  // The existing statement policy runs first and is never relaxed: one statement, no comments, no quoted identifiers,
  // SELECT/INSERT/UPDATE only, no set_config/pg_settings.
  assertAllowedStatement(text);
  const sql = text.replace(/\s+/g, ' ').trim();
  const lower = sql.toLowerCase();

  const mentioned = SCOPED.filter(t => new RegExp(`\\b${t}\\b`).test(lower));
  if (mentioned.length === 0) return { kind: 'global', tables: [], organizationParams: [] };
  if (new RegExp(`\\.\\s*(?:${SCOPED.join('|')})\\b|\\b(?:${SCOPED.join('|')})\\s*\\.`).test(lower)) {
    throw new TenantStatementRejectedError('qualified_tenant_reference');
  }
  if (/\bor\b/.test(lower)) throw new TenantStatementRejectedError('disjunction');

  const refs: Reference[] = [];
  const refPattern = new RegExp(`\\b(from|join|update|into)\\s+(${SCOPED.join('|')})\\b(?:\\s+(?:as\\s+)?([a-z_][a-z0-9_]*))?`, 'g');
  for (const m of lower.matchAll(refPattern)) {
    const alias = m[3] && !NOT_AN_ALIAS.has(m[3]) ? m[3] : null;
    refs.push({ table: m[2] as ScopedTable, qualifier: alias ?? m[2]!, clause: m[1]!, index: m.index! });
  }
  const occurrences = SCOPED.reduce((n, t) => n + (lower.match(new RegExp(`\\b${t}\\b`, 'g'))?.length ?? 0), 0);
  if (occurrences !== refs.length) throw new TenantStatementRejectedError('unrecognized_tenant_reference');

  // organization_id is never written by the application.
  if (refs.some(r => r.table === 'organizations' && (r.clause === 'into' || r.clause === 'update'))) {
    throw new TenantStatementRejectedError('organization_write');
  }
  const setClauses = [...lower.matchAll(/\bset\b(.*?)(?=\bwhere\b|\breturning\b|$)/g)].map(m => m[1]!);
  if (setClauses.some(s => /\borganization_id\b/.test(s))) throw new TenantStatementRejectedError('organization_id_assignment');

  const isInsert = lower.startsWith('insert');
  if (isInsert) {
    const target = refs[0];
    if (!target || target.clause !== 'into' || refs.length !== 1) throw new TenantStatementRejectedError('insert_shape');
    const columns = lower.slice(target.index).match(/^into\s+[a-z_]+(?:\s+as\s+[a-z_]+)?\s*\(([^)]*)\)/);
    if (!columns) throw new TenantStatementRejectedError('insert_column_list');
    const names = columns[1]!.split(',').map(c => c.trim());
    const position = names.indexOf('organization_id');
    if (!options.allowOrganizationInsert) {
      if (/\borganization_id\b/.test(columns[1]!)) throw new TenantStatementRejectedError('organization_id_assignment');
      return { kind: 'default_insert', tables: [target.table], organizationParams: [] };
    }
    // Sprint 3.0.1 (M3): outside ThriveSource the M7 column default (ThriveSource) is never acceptable, so the analyzer
    // itself refuses an INSERT that omits organization_id, not only the run-time check in assertTenantStatement.
    if (position < 0) throw new TenantStatementRejectedError('organization_id_required');
    // Explicit organization: exactly one VALUES row, and the organization_id item must be a bare $n (no expression,
    // no subquery, no literal), so the run-time check below binds it to the context.
    if (names.filter(n => n === 'organization_id').length !== 1 || /\bselect\b/.test(lower.slice(target.index + columns[0].length))) {
      throw new TenantStatementRejectedError('organization_id_assignment');
    }
    // A single row only: nothing but whitespace, ON CONFLICT or RETURNING may follow the one VALUES tuple.
    const values = lower.slice(target.index + columns[0].length).match(/^\s*values\s*\(([^()]*)\)\s*(?:$|on conflict\b|returning\b)/);
    const items = values?.[1]!.split(',').map(v => v.trim());
    const bound = items && items.length === names.length ? items[position]!.match(/^\$(\d+)$/) : null;
    if (!bound) throw new TenantStatementRejectedError('organization_id_assignment');
    return { kind: 'organization_insert', tables: [target.table], organizationParams: [Number(bound[1])] };
  }

  // Every SELECT/UPDATE reference needs its own predicate, after the first WHERE or ON (never in a SET list).
  const firstFilter = lower.search(/\b(where|on)\b/);
  if (firstFilter < 0) throw new TenantStatementRejectedError('missing_tenant_predicate');
  const filter = lower.slice(firstFilter);
  const params = new Set<number>();
  for (const ref of refs) {
    const column = SCOPE_COLUMN[ref.table];
    const qualified = new RegExp(`\\b${ref.qualifier}\\.${column}\\s*=\\s*\\$(\\d+)\\b`, 'g');
    let found = [...filter.matchAll(qualified)];
    // An unaliased, single-table statement may use the bare column name.
    if (found.length === 0 && ref.qualifier === ref.table && refs.length === 1) {
      found = [...filter.matchAll(new RegExp(`(?<![.\\w])${column}\\s*=\\s*\\$(\\d+)\\b`, 'g'))];
    }
    if (found.length === 0) throw new TenantStatementRejectedError(`missing_tenant_predicate:${ref.table}`);
    for (const f of found) params.add(Number(f[1]));
  }
  return { kind: 'scoped', tables: refs.map(r => r.table), organizationParams: [...params].sort((a, b) => a - b) };
}

/** Full check of one statement and its parameters against a context. */
export function assertTenantStatement(text: string, params: readonly unknown[] | undefined, context: OrganizationContext): TenantStatementAnalysis {
  // Explicit organization INSERTs exist only outside ThriveSource (Sprint 3.0, M8 grants). In the ThriveSource context the
  // Sprint 2.0B rule stands unchanged: organization_id is never written, and INSERTs take the M7 default.
  const analysis = analyzeTenantStatement(text, { allowOrganizationInsert: context.organizationId !== THRIVESOURCE_ORGANIZATION_ID });
  for (const position of analysis.organizationParams) {
    if (!params || params[position - 1] !== context.organizationId) throw new TenantStatementRejectedError('organization_parameter');
  }
  // The M7 column default is ThriveSource; a default-derived INSERT is correct only in the ThriveSource context.
  if (analysis.kind === 'default_insert' && context.organizationId !== THRIVESOURCE_ORGANIZATION_ID) {
    throw new TenantStatementRejectedError('default_organization_insert');
  }
  return analysis;
}

/** Wraps a client (normally statementGuardedSqlClient(roleScopedSqlClient(pool))) so that every statement is tenant-checked. */
export function organizationScopedSqlClient(inner: SqlClient, context: OrganizationContext): SqlClient {
  const scope = (client: SqlClient): SqlClient => ({
    query: <T = Record<string, unknown>>(text: string, params?: unknown[]) => {
      try { assertTenantStatement(text, params, context); } catch (error) { return Promise.reject(error); }
      return client.query<T>(text, params);
    },
    transaction: <T>(fn: (tx: SqlClient) => Promise<T>) => client.transaction(tx => fn(scope(tx))),
  });
  return scope(inner);
}
