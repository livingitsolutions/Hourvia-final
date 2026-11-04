import { getDatabase } from '@netlify/database';
import { readServerEnv, type EnvReader } from './config';
import type { DepsFactory } from './http';
import { SupabaseIdentityProvider } from './provider-supabase';
import { roleScopedSqlClient, statementGuardedSqlClient } from './sql-role';
import { logDatabaseError } from './runtime-log';
import { PostgresAuthStore } from './store-postgres';
import type { SqlClient } from './types';

interface PgLikeClient { query(text: string, params?: unknown[]): Promise<{ rows: unknown[] }>; release(destroy?: boolean | Error): void }
interface PgLikePool { query(text: string, params?: unknown[]): Promise<{ rows: unknown[] }>; connect(): Promise<PgLikeClient>; on?(event: 'error', listener: (error: unknown) => void): unknown }

/**
 * Wraps a pg-compatible pool. Sprint 1.9C hardening:
 *   * The transaction handle is closed when the transaction ends. A stale reference (an un-awaited or retained
 *     tx.query) can therefore never run on a connection that is back in the pool, where it would execute as the
 *     owner session user outside SET LOCAL ROLE.
 *   * If ROLLBACK itself fails, the connection's state is unknown (it may still be inside the transaction with the
 *     restricted role set), so it is destroyed instead of being returned to the pool.
 */
export function poolSqlClient(pool: PgLikePool): SqlClient {
  const wrap = (q: PgLikePool['query']): SqlClient['query'] => async <T>(text: string, params?: unknown[]) => ({ rows: (await q(text, params)).rows as T[] });
  return {
    query: wrap(pool.query.bind(pool)),
    async transaction(fn) {
      const client = await pool.connect();
      let open = true;
      let destroy: Error | undefined;
      const query = wrap(client.query.bind(client));
      const tx: SqlClient = {
        query: <T>(text: string, params?: unknown[]) => open ? query<T>(text, params) : Promise.reject(new Error('transaction_closed')),
        transaction: () => Promise.reject(new Error('nested_transaction')),
      };
      try {
        await client.query('BEGIN');
        const result = await fn(tx);
        await client.query('COMMIT');
        return result;
      } catch (e) {
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

let sharedStore: PostgresAuthStore | null = null;
function platformPool(): PgLikePool {
  const pool = getDatabase().pool as unknown as PgLikePool;
  // An idle pooled connection that errors (e.g. dropped by the server) emits 'error' on the pool; without a
  // listener Node treats it as unhandled and crashes the function instance. The pool discards that client itself.
  pool.on?.('error', error => logDatabaseError('pool_idle_client', error));
  return pool;
}
// Every auth statement runs as the restricted hourvia_auth_runtime role, never with the owner's privileges, and only
// after passing the store statement policy (single SELECT/INSERT/UPDATE, no role or setting changes).
const store = () => (sharedStore ??= new PostgresAuthStore(statementGuardedSqlClient(roleScopedSqlClient(poolSqlClient(platformPool())))));

/** Production wiring for Netlify Functions. All secrets come from protected environment variables. */
export function runtimeDeps(env: EnvReader, deployContext: string | undefined): DepsFactory {
  return async () => {
    const serverEnv = readServerEnv(env, deployContext);
    if ('unavailable' in serverEnv) return serverEnv;
    const { supabase, config } = serverEnv;
    return {
      config,
      store: store(),
      provider: new SupabaseIdentityProvider(supabase.url, supabase.anonKey, supabase.serviceRoleKey),
      now: () => new Date(),
      sleep: ms => new Promise(resolve => setTimeout(resolve, ms)),
    };
  };
}
