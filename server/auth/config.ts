import type { AuthConfig } from './types';

export type EnvReader = (name: string) => string | undefined;

export interface ServerEnv { config: AuthConfig; supabase: { url: string; anonKey: string; serviceRoleKey: string } }

const bounded = (raw: string | undefined, fallback: number, min: number, max: number): number => {
  const value = Number(raw);
  return Number.isInteger(value) && value >= min && value <= max ? value : fallback;
};

/**
 * Reads protected server-only environment variables. Returns a reason string instead of a config when
 * anything required is missing, so callers fail closed. Nothing here is ever sent to the browser.
 */
export function readServerEnv(env: EnvReader, deployContext: string | undefined): ServerEnv | { unavailable: string } {
  if (deployContext === 'production' && env('HOURVIA_AUTH_ALLOW_PRODUCTION') !== 'true') return { unavailable: 'production_not_enabled' };
  const url = env('SUPABASE_URL');
  const anonKey = env('SUPABASE_ANON_KEY');
  const serviceRoleKey = env('SUPABASE_SERVICE_ROLE_KEY');
  const hashKey = env('HOURVIA_AUTH_HASH_KEY');
  if (!url || !anonKey || !serviceRoleKey || !hashKey) return { unavailable: 'not_configured' };
  if (!url.startsWith('https://') || hashKey.length < 32 || anonKey === serviceRoleKey) return { unavailable: 'misconfigured' };
  const origin = env('HOURVIA_APP_ORIGIN');
  const appOrigin = origin && /^https:\/\/[a-z0-9.-]+(:\d+)?$/i.test(origin) ? origin : null;
  const idle = bounded(env('HOURVIA_SESSION_IDLE_SECONDS'), 1800, 300, 7200);
  return {
    supabase: { url, anonKey, serviceRoleKey },
    config: {
      hashKey,
      appOrigin,
      emailDeliveryAuthorized: env('HOURVIA_EMAIL_DELIVERY_AUTHORIZED') === 'true' && appOrigin !== null,
      idleTimeoutSeconds: idle,
      absoluteTimeoutSeconds: Math.max(idle, bounded(env('HOURVIA_SESSION_ABSOLUTE_SECONDS'), 43200, 3600, 86400)),
      invitationTtlSeconds: 7 * 24 * 3600,
      recoveryMinimumMs: 750,
    },
  };
}
