// Runtime defense in depth after the operator verifies the exact staging endpoint and M1–M7 history.
// Only catalog/organization-seed metadata is read; no personal records, migrations or data writes.
interface Client {
  query(text: string): Promise<{ rows: unknown[] }>;
  release(destroy?: boolean | Error): void;
}
interface Pool { connect(): Promise<Client> }
export const STAGING_DATABASE_CHECK = `SELECT
  EXISTS (SELECT 1 FROM public.organizations WHERE id = '5adff49b-11d5-4b45-bb4f-2f76cfcca0c6'
    AND slug = 'thrivesource' AND kind = 'internal' AND status = 'active')
  AND (SELECT count(*) FROM information_schema.columns WHERE table_schema = 'public'
    AND table_name IN ('workspace_members','workspace_invitations','manager_assignments','auth_sessions','auth_audit_events')
    AND column_name = 'organization_id' AND data_type = 'uuid' AND is_nullable = 'NO'
    AND column_default = '''5adff49b-11d5-4b45-bb4f-2f76cfcca0c6''::uuid') = 5
  AND (SELECT count(*) FROM pg_constraint WHERE connamespace = 'public'::regnamespace
    AND conname LIKE '%\\_org\\_fk' AND convalidated) = 11
  AND EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = 'public.organizations'::regclass
    AND tgname = 'organizations_guard' AND tgenabled = 'O') AS ok`;

export async function stagingDatabaseReady(pool: Pool): Promise<boolean> {
  const client = await pool.connect();
  let destroy: Error | undefined;
  try {
    await client.query('BEGIN READ ONLY');
    const { rows } = await client.query(STAGING_DATABASE_CHECK);
    return (rows[0] as { ok?: unknown } | undefined)?.ok === true;
  } finally {
    try { await client.query('ROLLBACK'); } catch { destroy = new Error('staging_check_rollback_failed'); }
    client.release(destroy);
    // An unknown transaction state never authorizes authentication.
    if (destroy) throw destroy;
  }
}
