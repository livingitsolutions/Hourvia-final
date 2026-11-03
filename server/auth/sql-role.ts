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
