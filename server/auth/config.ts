import type { AuthConfig } from './types';
import { deploymentAllowed, PRODUCTION_ORIGIN, type RuntimeIdentity } from './production-policy';
import { parseIdentityPolicy } from './synthetic-policy';

export type EnvReader = (name: string) => string | undefined;

export interface ServerEnv { config: AuthConfig; supabase: { url: string; anonKey: string; serviceRoleKey: string } }

const bounded = (raw: string | undefined, fallback: number, min: number, max: number): number => {
  const value = Number(raw);
  return Number.isInteger(value) && value >= min && value <= max ? value : fallback;
};

const EMAIL = /^[^\s@,]+@[^\s@,]+\.[^\s@,]+$/;
const MAX_SMOKE_TEST_EMAILS = 20;

/** Parses the designated smoke-test accounts. Any malformed entry invalidates the whole list (fail closed). */
function parseSmokeTestEmails(raw: string | undefined): ReadonlySet<string> | null {
  const emails = (raw ?? '').split(',').map(e => e.trim().toLowerCase()).filter(Boolean);
  if (emails.length === 0 || emails.length > MAX_SMOKE_TEST_EMAILS || !emails.every(e => EMAIL.test(e))) return null;
  return new Set(emails);
}

/**
 * Reads protected server-only environment variables. Returns a reason string instead of a config when
 * anything required is missing, so callers fail closed. Nothing here is ever sent to the browser.
 *
 * Supabase keys: the new-style names (SUPABASE_PUBLISHABLE_KEY / SUPABASE_SECRET_KEY) take precedence over
 * the legacy names (SUPABASE_ANON_KEY / SUPABASE_SERVICE_ROLE_KEY). VITE_-prefixed variables are never read:
 * anything VITE_ can be inlined into the browser bundle.
 *
 * Production requires trusted artifact identity, explicit authorization, the canonical origin, smoke stage,
 * and a complete exact synthetic/protected identity policy. No dev or preview provider access is allowed.
 */
export function readServerEnv(env: EnvReader, deployContext: string | undefined, identity?: RuntimeIdentity): ServerEnv | { unavailable: string } {
  if (deployContext !== 'production') return { unavailable: 'context_not_enabled' };
  if (!deploymentAllowed(identity)) return { unavailable: 'deployment_not_verified' };
  if (env('HOURVIA_AUTH_ALLOW_PRODUCTION') !== 'true') return { unavailable: 'production_not_enabled' };
  const url = env('SUPABASE_URL');
  const anonKey = env('SUPABASE_PUBLISHABLE_KEY') || env('SUPABASE_ANON_KEY');
  const serviceRoleKey = env('SUPABASE_SECRET_KEY') || env('SUPABASE_SERVICE_ROLE_KEY');
  const hashKey = env('HOURVIA_AUTH_HASH_KEY');
  if (!url || !anonKey || !serviceRoleKey || !hashKey) return { unavailable: 'not_configured' };
  if (!url.startsWith('https://') || hashKey.length < 32 || anonKey === serviceRoleKey
    || anonKey.startsWith('sb_secret_') || serviceRoleKey.startsWith('sb_publishable_')) return { unavailable: 'misconfigured' };
  const origin = env('HOURVIA_APP_ORIGIN');
  const appOrigin = origin && /^https:\/\/[a-z0-9.-]+(:\d+)?$/i.test(origin) ? origin : null;
  if (appOrigin !== PRODUCTION_ORIGIN) return { unavailable: 'misconfigured' };

  if (env('HOURVIA_AUTH_LAUNCH_STAGE') !== 'smoke') return { unavailable: 'smoke_required' };
  const smokeTestEmails = parseSmokeTestEmails(env('HOURVIA_AUTH_SMOKE_TEST_EMAILS'));
  const prelaunch = parseIdentityPolicy(env('HOURVIA_SYNTHETIC_IDENTITY_POLICY'), smokeTestEmails);
  if (!prelaunch) return { unavailable: 'synthetic_policy_invalid' };

  const idle = bounded(env('HOURVIA_SESSION_IDLE_SECONDS'), 1800, 300, 7200);
  return {
    supabase: { url, anonKey, serviceRoleKey },
    config: {
      prelaunch,
      hashKey,
      appOrigin,
      emailDeliveryAuthorized: env('HOURVIA_EMAIL_DELIVERY_AUTHORIZED') === 'true' && appOrigin !== null,
      smokeTestEmails,
      idleTimeoutSeconds: idle,
      absoluteTimeoutSeconds: Math.max(idle, bounded(env('HOURVIA_SESSION_ABSOLUTE_SECONDS'), 43200, 3600, 86400)),
      invitationTtlSeconds: 7 * 24 * 3600,
      recoveryMinimumMs: 750,
    },
  };
}
