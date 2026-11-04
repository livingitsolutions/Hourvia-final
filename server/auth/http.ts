import { AuthService, type Outcome, type RequestMeta } from './service';
import type { AuthDeps } from './types';

export const SESSION_COOKIE = '__Host-hourvia_session';
const MAX_BODY_BYTES = 8 * 1024;

const baseHeaders = (): Headers => new Headers({
  'Cache-Control': 'no-store', Pragma: 'no-cache', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', Vary: 'Cookie',
});
function sessionCookie(cookie: NonNullable<Outcome['cookie']>): string {
  // __Host- prefix forces Secure, Path=/ and no Domain. HttpOnly keeps it away from browser JavaScript.
  return cookie === 'clear'
    ? `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`
    : `${SESSION_COOKIE}=${cookie.set}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${cookie.maxAge}`;
}
export function respond(outcome: Outcome): Response {
  const headers = baseHeaders();
  if (outcome.cookie) headers.append('Set-Cookie', sessionCookie(outcome.cookie));
  if (outcome.body === undefined) return new Response(null, { status: outcome.status, headers });
  headers.set('Content-Type', 'application/json; charset=utf-8');
  return new Response(JSON.stringify(outcome.body), { status: outcome.status, headers });
}
const error = (status: number, code: string, message: string) => respond({ status, body: { error: code, message } });

export function readSessionCookie(header: string | null): string | null {
  if (!header) return null;
  const values = header.split(';').map(part => part.trim()).filter(part => part.startsWith(`${SESSION_COOKIE}=`));
  // Duplicate session cookies (e.g. cookie tossing) are treated as no session.
  return values.length === 1 ? values[0]!.slice(SESSION_COOKIE.length + 1) : null;
}

/** CSRF defence in depth on top of SameSite=Strict: exact same-origin Origin and JSON content type. */
function sameOriginJson(req: Request): boolean {
  const origin = req.headers.get('origin');
  const site = req.headers.get('sec-fetch-site');
  const type = (req.headers.get('content-type') ?? '').split(';')[0]!.trim().toLowerCase();
  return origin === new URL(req.url).origin && (site === null || site === 'same-origin') && type === 'application/json';
}
async function readJson(req: Request): Promise<{ value: unknown } | null> {
  const text = await req.text();
  if (new TextEncoder().encode(text).length > MAX_BODY_BYTES) return null;
  try { return { value: JSON.parse(text) as unknown }; } catch { return null; }
}

export type DepsFactory = () => Promise<AuthDeps | { unavailable: string }>;

const routes: { method: 'GET' | 'POST'; pattern: RegExp; run(s: AuthService, meta: RequestMeta, body: unknown, match: RegExpMatchArray): Promise<Outcome> }[] = [
  { method: 'GET', pattern: /^\/api\/auth\/session$/, run: (s, m) => s.session(m) },
  { method: 'POST', pattern: /^\/api\/auth\/login$/, run: (s, m, b) => s.login(b, m) },
  { method: 'POST', pattern: /^\/api\/auth\/logout$/, run: (s, m) => s.logout(m) },
  { method: 'POST', pattern: /^\/api\/auth\/recovery\/request$/, run: (s, m, b) => s.requestRecovery(b, m) },
  { method: 'POST', pattern: /^\/api\/auth\/recovery\/complete$/, run: (s, m, b) => s.completeRecovery(b, m) },
  { method: 'POST', pattern: /^\/api\/auth\/invitations\/accept$/, run: (s, m, b) => s.acceptInvitation(b, m) },
  { method: 'GET', pattern: /^\/api\/admin\/members$/, run: (s, m) => s.listMembers(m) },
  { method: 'POST', pattern: /^\/api\/admin\/invitations$/, run: (s, m, b) => s.invite(b, m) },
  { method: 'POST', pattern: /^\/api\/admin\/members\/([^/]+)\/disable$/, run: (s, m, _b, x) => s.disableMember(x[1]!, m) },
  { method: 'POST', pattern: /^\/api\/admin\/members\/([^/]+)\/revoke-sessions$/, run: (s, m, _b, x) => s.revokeMemberSessions(x[1]!, m) },
  { method: 'POST', pattern: /^\/api\/admin\/members\/([^/]+)\/role$/, run: (s, m, b, x) => s.changeMemberRole(x[1]!, b, m) },
];

export async function handleAuthRequest(req: Request, ip: string | undefined, makeDeps: DepsFactory): Promise<Response> {
  const path = new URL(req.url).pathname;
  const candidates = routes.map(route => ({ route, match: path.match(route.pattern) })).filter(c => c.match);
  if (!candidates.length) return error(404, 'not_found', 'Not found.');
  const found = candidates.find(c => c.route.method === req.method);
  if (!found) return error(405, 'method_not_allowed', 'Method not allowed.');
  let body: unknown;
  if (found.route.method === 'POST') {
    if (!sameOriginJson(req)) return error(403, 'origin_rejected', 'Request rejected.');
    const parsed = await readJson(req);
    if (!parsed) return error(400, 'invalid_request', 'Request body must be JSON under 8 KB.');
    body = parsed.value;
  }
  try {
    const deps = await makeDeps();
    if ('unavailable' in deps) return error(503, 'auth_unavailable', 'Workspace sign-in is temporarily unavailable. Contact your workspace administrator.');
    // Pin auth to the canonical origin (the one Supabase email links use). Requests to other hostnames that
    // serve the same deploy, such as *.netlify.app, are refused.
    if (deps.config.appOrigin && new URL(req.url).origin !== deps.config.appOrigin) return error(421, 'wrong_origin', 'Open Hourvia at its main address to sign in.');
    const meta: RequestMeta = { ip: ip || 'unknown', sessionToken: readSessionCookie(req.headers.get('cookie')) };
    return respond(await found.route.run(new AuthService(deps), meta, body, found.match!));
  } catch {
    // Missing tables, database or provider outages: fail closed without leaking internals.
    return error(503, 'auth_unavailable', 'Workspace sign-in is temporarily unavailable. Contact your workspace administrator.');
  }
}
