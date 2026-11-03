-- Hourvia — restricted runtime role for the auth tables (PROPOSAL, NOT AUTO-APPLIED)
--
-- Stands in for the Sprint 1.6 restricted-role proposal, which is not in this repository. Scope: the six
-- tables created by 001_create_auth_foundation.sql only. Promote it in the SAME pull request as 001, as the
-- next-numbered migration, so production never runs auth with full owner privileges.
--
-- Model: Netlify Database gives functions the netlifydb_owner credential (CREATEROLE, CREATEDB, BYPASSRLS,
-- member of neon_superuser, owner of every table). Hourvia's auth code runs every statement inside a
-- transaction that first executes SET LOCAL ROLE hourvia_auth_runtime (server/auth/sql-role.ts). Until this
-- role exists and is granted, SET LOCAL ROLE fails and auth returns 503 (fail closed).
--
-- Limits (read before relying on it): this is defence in depth against application bugs, not a hard
-- boundary. The session user is still netlifydb_owner, so code that can run arbitrary SQL can RESET ROLE.
-- Hourvia's SQL is parameterized only and sent as single statements, which makes that impractical through
-- request input. A separate LOGIN role with its own credential would be a hard boundary (see the preflight
-- report). RLS is not used: there are no policies, and owner roles bypass RLS anyway. Tenant isolation is
-- enforced by CHECK (workspace_id = 'thrivesource') plus workspace_id predicates in every query.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hourvia_auth_runtime') THEN
    CREATE ROLE hourvia_auth_runtime NOLOGIN NOINHERIT;
  END IF;
  ALTER ROLE hourvia_auth_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
  -- The runtime connection user may switch into the role but does not inherit its privileges (it doesn't need to).
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'netlifydb_owner') THEN
    GRANT hourvia_auth_runtime TO netlifydb_owner WITH INHERIT FALSE, SET TRUE;
  END IF;
END
$$;

REVOKE ALL ON workspace_members, manager_assignments, workspace_invitations, auth_sessions, auth_audit_events, auth_rate_limits
  FROM PUBLIC, hourvia_auth_runtime;
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
CREATE TRIGGER workspace_members_guard BEFORE UPDATE ON workspace_members
  FOR EACH ROW EXECUTE FUNCTION hourvia_guard_member_update();
