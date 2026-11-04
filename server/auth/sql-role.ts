import type { SqlClient } from './types';

/** Least-privilege database role for auth (db/proposals/sprint-1.7-auth/002_restricted_auth_runtime_role.sql). */
export const AUTH_DB_ROLE = 'hourvia_auth_runtime';

/**
 * Runs every statement inside a transaction that first switches to the restricted role with SET LOCAL ROLE,
 * so the role reverts at COMMIT/ROLLBACK and never leaks to other users of a pooled connection. If the role is
 * missing or not granted, the SET fails and the caller fails closed. Not configurable on purpose: an env var
 * could be pointed back at the owner role.
 */
export function roleScopedSqlClient(inner: SqlClient): SqlClient {
  const enter = async (tx: SqlClient) => { await tx.query(`SET LOCAL ROLE ${AUTH_DB_ROLE}`); return tx; };
  return {
    query: <T = Record<string, unknown>>(text: string, params?: unknown[]) => inner.transaction(async tx => (await enter(tx)).query<T>(text, params)),
    transaction: <T>(fn: (tx: SqlClient) => Promise<T>) => inner.transaction(async tx => fn(await enter(tx))),
  };
}

export class SqlStatementRejectedError extends Error {
  constructor(reason: string) { super(`sql_statement_rejected:${reason}`); this.name = 'SqlStatementRejectedError'; }
}

/** The only statement kinds the auth store issues. DELETE, TRUNCATE, DDL, SET/RESET, DO, COPY and CALL never are. */
const ALLOWED_FIRST_KEYWORD = /^(SELECT|INSERT|UPDATE)\b/i;

/**
 * Application statement policy (Sprint 1.9C, corrected in 1.9C.1), enforced before anything reaches the database.
 *
 * The session user is netlifydb_owner, so a statement that reached the database with RESET ROLE, SET ROLE or
 * set_config('role', …) would leave the restricted role inside the very transaction roleScopedSqlClient opened.
 * Store SQL is fixed text and never does this; this guard makes that a checked invariant instead of a convention.
 * Every rule is a conservative scan of the WHOLE text (including anything inside string literals), so quoting cannot
 * hide a token from it:
 *   * one statement only (no ";"), so nothing can be appended after a legitimate statement;
 *   * no SQL comments ("--", "/*"), so nothing can be hidden from review or from this check;
 *   * no double quotes and no U& escapes: quoted or Unicode-escaped identifiers ("set_config", U&"set\005fconfig")
 *     are the only way to spell a function or relation name that the token rules below would not see. Store SQL uses
 *     neither, so a quoted identifier is never needed;
 *   * it must start with SELECT, INSERT or UPDATE, which excludes SET/RESET ROLE, SET SESSION AUTHORIZATION,
 *     transaction control, DISCARD, DO, CALL, COPY, EXPLAIN, WITH and DDL;
 *   * "set_config" and "pg_settings" are refused anywhere, in any case, with or without a schema prefix or
 *     parenthesis: set_config() changes role and search_path from inside a SELECT, and UPDATE pg_settings calls it.
 * Parameters are sent separately and are not inspected. Violations throw before the database is contacted, so the
 * request fails closed (HTTP 503).
 *
 * This is a lexical rule set, not a SQL parser. It does not protect against code execution inside the Function.
 * Applied to the store only. The test harness also probes the raw role-scoped client to prove the database itself
 * denies what this guard blocks earlier.
 */
export function assertAllowedStatement(text: string): void {
  const sql = text.trim();
  if (sql.includes(';')) throw new SqlStatementRejectedError('multiple_statements');
  if (sql.includes('--') || sql.includes('/*')) throw new SqlStatementRejectedError('comment');
  if (sql.includes('"')) throw new SqlStatementRejectedError('quoted_identifier');
  if (/u&/i.test(sql)) throw new SqlStatementRejectedError('unicode_escape');
  if (!ALLOWED_FIRST_KEYWORD.test(sql)) throw new SqlStatementRejectedError('statement_kind');
  if (/set_config/i.test(sql)) throw new SqlStatementRejectedError('set_config');
  if (/pg_settings/i.test(sql)) throw new SqlStatementRejectedError('pg_settings');
}

export function statementGuardedSqlClient(inner: SqlClient): SqlClient {
  const guard = (client: SqlClient): SqlClient => ({
    query: <T = Record<string, unknown>>(text: string, params?: unknown[]) => {
      try { assertAllowedStatement(text); } catch (error) { return Promise.reject(error); }
      return client.query<T>(text, params);
    },
    transaction: <T>(fn: (tx: SqlClient) => Promise<T>) => client.transaction(tx => fn(guard(tx))),
  });
  return guard(inner);
}
