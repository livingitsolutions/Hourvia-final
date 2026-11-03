-- Hourvia — restricted runtime role for the auth tables (PROPOSAL, NOT AUTO-APPLIED)
--
-- Scope: the six tables created by 001_create_auth_foundation.sql only. Promote it in the SAME pull request
-- as 001, as the next-numbered migration, so production never runs auth with full owner privileges.
--
-- Model: Netlify Database migrations and functions use the netlifydb_owner credential (CREATEROLE, CREATEDB,
-- BYPASSRLS, member of neon_superuser, owner of every table it creates; NOT a superuser). Hourvia's auth code
-- runs every statement inside a transaction that first executes SET LOCAL ROLE hourvia_auth_runtime
-- (server/auth/sql-role.ts). Until this role exists and is granted, SET LOCAL ROLE fails and auth returns 503.
--
-- Sprint 1.7 readiness revision:
--   * Written for a NON-superuser migration role. The previous ALTER ROLE ... NOSUPERUSER NOREPLICATION
--     NOBYPASSRLS fails with "permission denied to alter role" for netlifydb_owner (only superusers may name
--     those attributes, even to clear them). A role created by a non-superuser cannot hold them anyway; a
--     pre-existing role is now verified instead of altered, and the migration aborts if it is unsafe.
--   * netlifydb_readonly (CLI/dashboard credential) is stripped of the platform default SELECT grant.
--   * The file ends with a self-check of EFFECTIVE privileges (has_*_privilege, which includes inherited
--     memberships such as pg_read_all_data) and aborts the migration if any expectation fails.
--
-- Limits: defence in depth against application bugs, not a hard boundary. The session user is still
-- netlifydb_owner, so code that can run arbitrary SQL can RESET ROLE. Hourvia's SQL is parameterized,
-- fixed-text and single-statement. A dedicated LOGIN role with its own credential would be a hard boundary.
-- RLS is not used (no policies; owner roles bypass RLS). Tenant isolation is CHECK (workspace_id =
-- 'thrivesource') plus workspace_id predicates in every query.

DO $$
DECLARE
  r pg_roles%ROWTYPE;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'netlifydb_owner') THEN
    RAISE EXCEPTION 'netlifydb_owner (runtime connection role) does not exist; refusing to continue';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hourvia_auth_runtime') THEN
    -- Only attributes a CREATEROLE (non-superuser) role may set. SUPERUSER/REPLICATION/BYPASSRLS default off.
    CREATE ROLE hourvia_auth_runtime NOLOGIN NOINHERIT NOCREATEDB NOCREATEROLE;
  END IF;
  SELECT * INTO r FROM pg_roles WHERE rolname = 'hourvia_auth_runtime';
  IF r.rolsuper OR r.rolcanlogin OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls OR r.rolinherit THEN
    RAISE EXCEPTION 'hourvia_auth_runtime exists with unsafe attributes; refusing to continue';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_auth_members WHERE member = r.oid) THEN
    RAISE EXCEPTION 'hourvia_auth_runtime is a member of another role; refusing to continue';
  END IF;
  -- The runtime connection user may switch into the role but does not inherit its privileges (it doesn't need to).
  GRANT hourvia_auth_runtime TO netlifydb_owner WITH INHERIT FALSE, SET TRUE;
END
$$;

REVOKE ALL ON workspace_members, manager_assignments, workspace_invitations, auth_sessions, auth_audit_events, auth_rate_limits
  FROM PUBLIC, hourvia_auth_runtime;
REVOKE ALL ON SEQUENCE auth_audit_events_id_seq FROM PUBLIC, hourvia_auth_runtime;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'netlifydb_readonly') THEN
    REVOKE ALL ON workspace_members, manager_assignments, workspace_invitations, auth_sessions, auth_audit_events, auth_rate_limits
      FROM netlifydb_readonly;
    REVOKE ALL ON SEQUENCE auth_audit_events_id_seq FROM netlifydb_readonly;
  END IF;
END
$$;
GRANT USAGE ON SCHEMA public TO hourvia_auth_runtime;

-- Members: read; create invited members; change only the columns the auth flows change.
GRANT SELECT ON workspace_members TO hourvia_auth_runtime;
GRANT INSERT (workspace_id, auth_user_id, email, display_name, role, status, created_at) ON workspace_members TO hourvia_auth_runtime;
GRANT UPDATE (role, display_name, status, activated_at, disabled_at, disabled_by) ON workspace_members TO hourvia_auth_runtime;

-- Assignments are read-only for auth (no writer exists yet).
GRANT SELECT ON manager_assignments TO hourvia_auth_runtime;

GRANT SELECT ON workspace_invitations TO hourvia_auth_runtime;
GRANT INSERT (workspace_id, member_id, email, role, status, invited_by_member_id, created_at, expires_at) ON workspace_invitations TO hourvia_auth_runtime;
GRANT UPDATE (status, accepted_at) ON workspace_invitations TO hourvia_auth_runtime;

GRANT SELECT ON auth_sessions TO hourvia_auth_runtime;
GRANT INSERT (token_hash, member_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at) ON auth_sessions TO hourvia_auth_runtime;
GRANT UPDATE (last_seen_at, idle_expires_at, revoked_at, revoked_reason) ON auth_sessions TO hourvia_auth_runtime;

GRANT SELECT ON auth_rate_limits TO hourvia_auth_runtime;
GRANT INSERT (bucket, window_start, hits) ON auth_rate_limits TO hourvia_auth_runtime;
GRANT UPDATE (hits) ON auth_rate_limits TO hourvia_auth_runtime;

-- Audit: write-only. No SELECT, UPDATE, DELETE or TRUNCATE (triggers also block mutation for every role).
-- Identity values come from the column default; no sequence privilege is needed or granted.
GRANT INSERT (workspace_id, occurred_at, event_type, outcome, actor_member_id, subject_member_id, email_hmac, ip_hmac, details) ON auth_audit_events TO hourvia_auth_runtime;

-- Integrity guard for every role (including mistakes by the owner): identity binding and workspace are
-- immutable, roles change only before activation, and disabling is terminal.
CREATE FUNCTION hourvia_guard_member_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR NEW.email IS DISTINCT FROM OLD.email
     OR (OLD.auth_user_id IS NOT NULL AND NEW.auth_user_id IS DISTINCT FROM OLD.auth_user_id) THEN
    RAISE EXCEPTION 'workspace_members identity columns are immutable';
  END IF;
  IF NEW.role IS DISTINCT FROM OLD.role AND OLD.status <> 'invited' THEN
    RAISE EXCEPTION 'workspace_members role can change only while invited';
  END IF;
  IF OLD.status = 'disabled' AND NEW.status <> 'disabled' THEN
    RAISE EXCEPTION 'disabled workspace members cannot be re-enabled by the runtime';
  END IF;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION hourvia_guard_member_update() FROM PUBLIC;
CREATE TRIGGER workspace_members_guard BEFORE UPDATE ON workspace_members
  FOR EACH ROW EXECUTE FUNCTION hourvia_guard_member_update();

-- Self-check of EFFECTIVE privileges. has_table_privilege / has_any_column_privilege resolve inherited
-- memberships (for example pg_read_all_data), table and column grants, and grants to PUBLIC. Any surprise
-- aborts this migration (and the deploy) instead of silently exposing data.
DO $$
DECLARE
  t text;
  grantee text;
  tables constant text[] := ARRAY['workspace_members', 'manager_assignments', 'workspace_invitations', 'auth_sessions', 'auth_audit_events', 'auth_rate_limits'];
  grantees text[] := ARRAY['public', 'hourvia_auth_runtime'];
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'netlifydb_readonly') THEN
    grantees := array_append(grantees, 'netlifydb_readonly');
  END IF;
  FOREACH t IN ARRAY tables LOOP
    FOREACH grantee IN ARRAY grantees LOOP
      IF grantee <> 'hourvia_auth_runtime' AND (
           has_table_privilege(grantee, 'public.' || t, 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN')
           OR has_any_column_privilege(grantee, 'public.' || t, 'SELECT, INSERT, UPDATE, REFERENCES')) THEN
        RAISE EXCEPTION 'privilege check failed: % still has access to %', grantee, t;
      END IF;
    END LOOP;
    IF has_table_privilege('hourvia_auth_runtime', 'public.' || t, 'DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN') THEN
      RAISE EXCEPTION 'privilege check failed: hourvia_auth_runtime has DELETE/TRUNCATE/REFERENCES/TRIGGER/MAINTAIN on %', t;
    END IF;
  END LOOP;
  IF has_any_column_privilege('hourvia_auth_runtime', 'public.auth_audit_events', 'SELECT, UPDATE')
     OR has_any_column_privilege('hourvia_auth_runtime', 'public.manager_assignments', 'INSERT, UPDATE')
     OR has_column_privilege('hourvia_auth_runtime', 'public.workspace_members', 'approval_authorized', 'UPDATE')
     OR has_column_privilege('hourvia_auth_runtime', 'public.workspace_members', 'auth_user_id', 'UPDATE')
     OR has_column_privilege('hourvia_auth_runtime', 'public.workspace_members', 'email', 'UPDATE')
     OR has_column_privilege('hourvia_auth_runtime', 'public.workspace_members', 'workspace_id', 'UPDATE') THEN
    RAISE EXCEPTION 'privilege check failed: hourvia_auth_runtime has a forbidden column privilege';
  END IF;
  IF has_schema_privilege('hourvia_auth_runtime', 'public', 'CREATE')
     OR has_database_privilege('hourvia_auth_runtime', current_database(), 'CREATE') THEN
    RAISE EXCEPTION 'privilege check failed: hourvia_auth_runtime can create objects';
  END IF;
  IF NOT pg_has_role('netlifydb_owner', 'hourvia_auth_runtime', 'SET') THEN
    RAISE EXCEPTION 'privilege check failed: netlifydb_owner cannot SET ROLE hourvia_auth_runtime';
  END IF;
  -- No explicit grant to any other role (e.g. token_roles or a future platform role) on tables, columns or
  -- the audit sequence: ACL entries may name only the table owner and the runtime role.
  IF EXISTS (
    SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a
    WHERE c.oid IN (SELECT ('public.' || x)::regclass FROM unnest(tables || 'auth_audit_events_id_seq'::text) x)
      AND a.grantee NOT IN (c.relowner, 'hourvia_auth_runtime'::regrole)
    UNION ALL
    SELECT 1 FROM pg_attribute at JOIN pg_class c ON c.oid = at.attrelid CROSS JOIN LATERAL aclexplode(at.attacl) a
    WHERE c.oid IN (SELECT ('public.' || x)::regclass FROM unnest(tables) x)
      AND a.grantee NOT IN (c.relowner, 'hourvia_auth_runtime'::regrole)
  ) THEN
    RAISE EXCEPTION 'privilege check failed: an unexpected role is granted access to an auth table';
  END IF;
END
$$;
