import { productionDatabaseReady, targetDigest } from './production-database';
import type { RuntimeIdentity } from './production-policy';
import { getDatabase, getConnectionString } from '@netlify/database';
import { readServerEnv, type EnvReader } from './config';
import type { DepsFactory } from './http';
import { SupabaseIdentityProvider } from './provider-supabase';
import { roleScopedSqlClient, statementGuardedSqlClient } from './sql-role';
import { logDatabaseError } from './runtime-log';
import { PostgresAuthStore } from './store-postgres';
import type { SqlClient } from './types';

interface PgLikeResult { rows: unknown[]; command?: string }
interface PgLikeClient { query(text: string, params?: unknown[]): Promise<PgLikeResult>; release(destroy?: boolean | Error): void }
interface PgLikePool { query(text: string, params?: unknown[]): Promise<PgLikeResult>; connect(): Promise<PgLikeClient>; on?(event: 'error', listener: (error: unknown) => void): unknown; end?(): Promise<void> }

export class TransactionClosedError extends Error {
  constructor() { super('transaction_closed'); this.name = 'TransactionClosedError'; }
}

/**
 * Wraps a pg-compatible pool. Transaction lifecycle (Sprint 1.9C, corrected in 1.9C.1):
 *   1. BEGIN, then the callback runs with a transaction handle.
 *   2. The handle is CLOSED the moment the callback settles (resolves or rejects), before COMMIT or ROLLBACK is sent.
 *      Any later tx.query (a delayed timer, a detached continuation, a sibling Promise branch still running after
 *      another branch threw, or a retained reference) is rejected with TransactionClosedError and never reaches the
 *      connection. Without this, pg would queue it after COMMIT/ROLLBACK, where it would run outside the transaction
 *      as the owner session user, possibly after the connection was handed to another request.
 *   3. Queries the callback issued but did not await are drained first. If any of them failed, the transaction is
 *      rolled back and that error is thrown, so a failed write can never be reported as a success.
 *   4. A COMMIT that the server reports as ROLLBACK (the transaction was already aborted) is treated as a failure.
 *   5. If ROLLBACK itself fails, the connection's state is unknown (it may still be inside the transaction with the
 *      restricted role set), so it is destroyed instead of being returned to the pool.
 */
export function poolSqlClient(pool: PgLikePool): SqlClient {
  const wrap = (q: PgLikePool['query']): SqlClient['query'] => async <T>(text: string, params?: unknown[]) => ({ rows: (await q(text, params)).rows as T[] });
  return {
    query: wrap(pool.query.bind(pool)),
    async transaction(fn) {
      const client = await pool.connect();
      let open = true;
      let destroy: Error | undefined;
      const inflight = new Set<Promise<unknown>>();
      let inflightFailure: { error: unknown } | null = null;
      const query = wrap(client.query.bind(client));
      const tx: SqlClient = {
        query: <T>(text: string, params?: unknown[]) => {
          if (!open) return Promise.reject(new TransactionClosedError());
          const pending = query<T>(text, params);
          const tracked = pending.then(() => undefined, (error: unknown) => { inflightFailure ??= { error }; });
          inflight.add(tracked);
          void tracked.finally(() => inflight.delete(tracked));
          return pending;
        },
        transaction: () => Promise.reject(new Error('nested_transaction')),
      };
      try {
        await client.query('BEGIN');
        let result: Awaited<ReturnType<typeof fn>>;
        try { result = await fn(tx); } finally { open = false; }
        await Promise.all(inflight);
        if (inflightFailure) throw (inflightFailure as { error: unknown }).error;
        const committed = await client.query('COMMIT');
        if (committed.command === 'ROLLBACK') throw new Error('transaction_rolled_back');
        return result;
      } catch (e) {
        open = false;
        await Promise.all(inflight);
        await client.query('ROLLBACK').catch((rollbackError: unknown) => {
          destroy = rollbackError instanceof Error ? rollbackError : new Error('rollback_failed');
        });
        throw e;
      } finally {
        open = false;
        client.release(destroy);
      }
    },
  };
}

let sharedPool: { target: string; binding: string; pool: PgLikePool } | null = null;
/**
 * Returns the platform pool for the verified target. The target digest (endpoint, port, database) must equal the
 * evidence-bound target. A warm instance whose binding moves to a different target fails closed and never reuses or
 * rebuilds a pool for it. A changed binding for the same target (credential rotation or connection parameters) safely
 * replaces the pool: the old pool is drained in the background and the readiness cache misses on the new pool object.
 */
export function platformPool(expectedTarget: string): PgLikePool {
  const binding = getConnectionString();
  const target = targetDigest(binding);
  if (!target || target !== expectedTarget) throw new Error('database_binding_mismatch');
  if (sharedPool) {
    if (sharedPool.target !== target) throw new Error('database_target_changed');
    if (sharedPool.binding === binding) return sharedPool.pool;
    const retired = sharedPool.pool;
    sharedPool = null;
    void Promise.resolve().then(() => retired.end?.()).catch(error => logDatabaseError('pool_retire', error));
  }
  const pool = getDatabase().pool as unknown as PgLikePool;
  // An idle pooled connection that errors (e.g. dropped by the server) emits 'error' on the pool; without a
  // listener Node treats it as unhandled and crashes the function instance. The pool discards that client itself.
  pool.on?.('error', error => logDatabaseError('pool_idle_client', error));
  sharedPool = { target, binding, pool };
  return pool;
}
/** Offline tests only. */
export function resetPlatformPoolForTests(): void { sharedPool = null; }
// Every auth statement runs as the restricted hourvia_auth_runtime role, never with the owner's privileges, and only
// after passing the store statement policy (single SELECT/INSERT/UPDATE, no role or setting changes).
const store = (pool: PgLikePool) => new PostgresAuthStore(statementGuardedSqlClient(roleScopedSqlClient(poolSqlClient(pool))));

/** Production wiring for Netlify Functions. All secrets come from protected environment variables. */
export function runtimeDeps(env: EnvReader, deployContext: string | undefined, identity?: RuntimeIdentity): DepsFactory {
  return async () => {
    const serverEnv = readServerEnv(env, deployContext, identity);
    if ('unavailable' in serverEnv) return serverEnv;
    let verifiedPool: PgLikePool | undefined;
    const expectedTarget = targetDigest(env('NETLIFY_DB_URL'));
    if (!expectedTarget || !await productionDatabaseReady(() => (verifiedPool = platformPool(expectedTarget)), env, identity)
      || !verifiedPool) return { unavailable: 'database_not_verified' };
    const { supabase, config } = serverEnv;
    return {
      config,
      store: store(verifiedPool),
      provider: new SupabaseIdentityProvider(supabase.url, supabase.anonKey, supabase.serviceRoleKey),
      now: () => new Date(),
      sleep: ms => new Promise(resolve => setTimeout(resolve, ms)),
    };
  };
}
