import { getDatabase } from '@netlify/database';
import { readServerEnv, type EnvReader } from './config';
import type { DepsFactory } from './http';
import { SupabaseIdentityProvider } from './provider-supabase';
import { roleScopedSqlClient } from './sql-role';
import { PostgresAuthStore } from './store-postgres';
import type { SqlClient } from './types';

interface PgLikePool { query(text: string, params?: unknown[]): Promise<{ rows: unknown[] }>; connect(): Promise<{ query(text: string, params?: unknown[]): Promise<{ rows: unknown[] }>; release(): void }> }

export function poolSqlClient(pool: PgLikePool): SqlClient {
  const wrap = (q: PgLikePool['query']): SqlClient['query'] => async <T>(text: string, params?: unknown[]) => ({ rows: (await q(text, params)).rows as T[] });
  return {
    query: wrap(pool.query.bind(pool)),
    async transaction(fn) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const result = await fn({ query: wrap(client.query.bind(client)), transaction: () => Promise.reject(new Error('nested_transaction')) });
        await client.query('COMMIT');
        return result;
      } catch (e) { await client.query('ROLLBACK').catch(() => undefined); throw e; }
      finally { client.release(); }
    },
  };
}

let sharedStore: PostgresAuthStore | null = null;
// Every auth statement runs as the restricted hourvia_auth_runtime role, never with the owner's privileges.
const store = () => (sharedStore ??= new PostgresAuthStore(roleScopedSqlClient(poolSqlClient(getDatabase().pool as unknown as PgLikePool))));

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
