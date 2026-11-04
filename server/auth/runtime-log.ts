/**
 * Sprint 1.9C: server-side error signal for fail-closed paths. Logs only the error class and a SQLSTATE-shaped code,
 * never a message or stack: Postgres and driver messages can carry parameter values, hostnames or usernames.
 */
export function logDatabaseError(where: string, error: unknown): void {
  const raw = error && typeof error === 'object' ? (error as { code?: unknown }).code : undefined;
  const code = typeof raw === 'string' && /^[0-9A-Z]{5}$/.test(raw) ? raw : null;
  const kind = error instanceof Error ? error.name.slice(0, 64) : typeof error;
  console.error(JSON.stringify({ event: 'hourvia_auth_error', where, kind, code }));
}
