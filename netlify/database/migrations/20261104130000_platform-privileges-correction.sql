-- Hourvia Sprint 1.8A — platform privilege correction (forward-only; 20261104120000 stays unchanged)
--
-- 20261104120000 modelled Super Admin as a workspace membership role. This migration corrects that:
--   * workspace_members.role goes back to the organization roles only (workspace_admin, workspace_manager,
--     contractor). No organization role can name, imply or grant a platform privilege.
--   * Platform authority lives in platform_privileges, keyed by Supabase Auth UID, not by membership. The only
--     privilege is 'platform_super_admin'; at most one holder is active, and only the designated UID is eligible.
--     The designation can be made only for the UID bound to the active, invitation-verified Living IT Solutions
--     membership. Nothing is granted here: grants are separate, approved operator procedures.
--   * Administrator management (invite, promote, demote, disable, end sessions) requires an active
--     workspace_admin membership in the SAME organization plus an active platform_super_admin privilege. Platform
--     authority therefore never reaches into an organization the holder is not an Administrator of.
--   * Session revocation records the acting member, and every revocation is audited by the database.
--   * Disabled members can be reinstated only by an approved operator procedure (no longer terminal for operators).
--
-- Compatibility: changes no existing workspace_members, invitation, session or audit row. Aborts if any row still
-- holds the withdrawn 'super_admin' role (none can: its promotion script never ran in any environment).

-- 0. Preconditions -----------------------------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hourvia_auth_runtime') THEN
    RAISE EXCEPTION 'hourvia_auth_runtime does not exist; apply 20261103170100 first';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = 'public.workspace_members'::regclass AND attname = 'role_changed_by' AND NOT attisdropped) THEN
    RAISE EXCEPTION 'workspace_members.role_changed_by does not exist; apply 20261104120000 first';
  END IF;
  IF EXISTS (SELECT 1 FROM workspace_members WHERE role = 'super_admin') THEN
    RAISE EXCEPTION 'a workspace_members row holds the withdrawn super_admin role; stop and review before correcting';
  END IF;
END
$$;

-- 1. Withdraw the workspace-scoped super_admin role ------------------------------------------------------------------
ALTER TABLE workspace_members DROP CONSTRAINT workspace_members_super_admin_designated;
DROP INDEX workspace_members_one_super_admin;
ALTER TABLE workspace_members DROP CONSTRAINT workspace_members_role_check;
ALTER TABLE workspace_members ADD CONSTRAINT workspace_members_role_check
  CHECK (role IN ('workspace_admin', 'workspace_manager', 'contractor'));
-- workspace_invitations_no_super_admin (from 20261104120000) stays as an extra guard.

-- 2. Platform privilege tables --------------------------------------------------------------------------------------
-- The single eligible identity. Written once by the approved grant procedure; immutable afterwards.
CREATE TABLE platform_super_admin_designation (
  singleton     boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  auth_user_id  uuid NOT NULL UNIQUE,
  designated_at timestamptz NOT NULL DEFAULT now(),
  approval_ref  text NOT NULL CHECK (approval_ref ~ '^[A-Za-z0-9._:-]{3,64}$')
);

-- Grant history. A row is revoked at most once and never deleted; reinstatement inserts a new row.
CREATE TABLE platform_privileges (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  auth_user_id        uuid NOT NULL,
  privilege           text NOT NULL CHECK (privilege = 'platform_super_admin'),
  granted_at          timestamptz NOT NULL DEFAULT now(),
  grant_approval_ref  text NOT NULL CHECK (grant_approval_ref ~ '^[A-Za-z0-9._:-]{3,64}$'),
  revoked_at          timestamptz,
  revoke_approval_ref text CHECK (revoke_approval_ref ~ '^[A-Za-z0-9._:-]{3,64}$'),
  revoked_reason      text CHECK (revoked_reason ~ '^[a-z_]{1,64}$'),
  CHECK ((revoked_at IS NULL) = (revoke_approval_ref IS NULL)),
  CHECK ((revoked_at IS NULL) = (revoked_reason IS NULL)),
  CHECK (revoked_at IS NULL OR revoked_at >= granted_at)
);
CREATE UNIQUE INDEX platform_privileges_one_active ON platform_privileges (privilege) WHERE revoked_at IS NULL;
CREATE INDEX platform_privileges_holder ON platform_privileges (auth_user_id) WHERE revoked_at IS NULL;

-- Platform-level, append-only audit (organization events stay in auth_audit_events).
CREATE TABLE platform_audit_events (
  id                   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  occurred_at          timestamptz NOT NULL DEFAULT now(),
  event_type           text NOT NULL CHECK (event_type ~ '^[a-z_]{1,64}$'),
  outcome              text NOT NULL CHECK (outcome IN ('success', 'denied', 'error')),
  subject_auth_user_id uuid,
  details              jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details) = 'object' AND pg_column_size(details) <= 4096)
);
CREATE TRIGGER platform_audit_events_no_update_delete BEFORE UPDATE OR DELETE ON platform_audit_events
  FOR EACH ROW EXECUTE FUNCTION hourvia_reject_audit_mutation();
CREATE TRIGGER platform_audit_events_no_truncate BEFORE TRUNCATE ON platform_audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION hourvia_reject_audit_mutation();

-- 3. Eligibility and immutability guards for the platform tables ------------------------------------------------------
-- The verified Living IT Solutions identity: the auth UID bound to the active membership of the designated mailbox
-- that was activated through Supabase invitation verification.
CREATE FUNCTION hourvia_is_verified_platform_candidate(candidate uuid) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT EXISTS (
    SELECT 1 FROM workspace_members m
    WHERE m.auth_user_id = candidate AND m.email = 'livingitsolutions@gmail.com'
      AND m.status = 'active' AND m.activated_at IS NOT NULL);
$$;

CREATE FUNCTION hourvia_guard_platform_designation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF TG_OP <> 'INSERT' THEN
    RAISE EXCEPTION 'platform_super_admin_designation is immutable; changing it requires a reviewed forward migration';
  END IF;
  IF NOT hourvia_is_verified_platform_candidate(NEW.auth_user_id) THEN
    RAISE EXCEPTION 'only the verified Living IT Solutions identity can be designated';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER platform_super_admin_designation_guard BEFORE INSERT OR UPDATE OR DELETE ON platform_super_admin_designation
  FOR EACH ROW EXECUTE FUNCTION hourvia_guard_platform_designation();
CREATE TRIGGER platform_super_admin_designation_no_truncate BEFORE TRUNCATE ON platform_super_admin_designation
  FOR EACH STATEMENT EXECUTE FUNCTION hourvia_reject_audit_mutation();

CREATE FUNCTION hourvia_guard_platform_privilege() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'platform_privileges history cannot be deleted; revoke instead';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.revoked_at IS NOT NULL THEN
      RAISE EXCEPTION 'platform privileges must be granted unrevoked';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM platform_super_admin_designation d WHERE d.auth_user_id = NEW.auth_user_id) THEN
      RAISE EXCEPTION 'platform_super_admin can be granted only to the designated identity';
    END IF;
    IF NOT hourvia_is_verified_platform_candidate(NEW.auth_user_id) THEN
      RAISE EXCEPTION 'the designated identity no longer has an active verified membership';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id OR NEW.auth_user_id IS DISTINCT FROM OLD.auth_user_id OR NEW.privilege IS DISTINCT FROM OLD.privilege
     OR NEW.granted_at IS DISTINCT FROM OLD.granted_at OR NEW.grant_approval_ref IS DISTINCT FROM OLD.grant_approval_ref
     OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL THEN
    RAISE EXCEPTION 'platform_privileges rows can only be revoked, once';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER platform_privileges_guard BEFORE INSERT OR UPDATE OR DELETE ON platform_privileges
  FOR EACH ROW EXECUTE FUNCTION hourvia_guard_platform_privilege();
CREATE TRIGGER platform_privileges_no_truncate BEFORE TRUNCATE ON platform_privileges
  FOR EACH STATEMENT EXECUTE FUNCTION hourvia_reject_audit_mutation();

CREATE FUNCTION hourvia_audit_platform_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF TG_TABLE_NAME = 'platform_super_admin_designation' THEN
    INSERT INTO platform_audit_events (event_type, outcome, subject_auth_user_id, details)
    VALUES ('platform_designation_set', 'success', NEW.auth_user_id,
            jsonb_build_object('approval_ref', NEW.approval_ref, 'source', 'operator_sql'));
  ELSIF TG_OP = 'INSERT' THEN
    INSERT INTO platform_audit_events (event_type, outcome, subject_auth_user_id, details)
    VALUES ('platform_privilege_granted', 'success', NEW.auth_user_id,
            jsonb_build_object('privilege', NEW.privilege, 'grant_id', NEW.id, 'approval_ref', NEW.grant_approval_ref, 'source', 'operator_sql'));
  ELSE
    INSERT INTO platform_audit_events (event_type, outcome, subject_auth_user_id, details)
    VALUES ('platform_privilege_revoked', 'success', NEW.auth_user_id,
            jsonb_build_object('privilege', NEW.privilege, 'grant_id', NEW.id, 'approval_ref', NEW.revoke_approval_ref, 'reason', NEW.revoked_reason, 'source', 'operator_sql'));
  END IF;
  RETURN NULL;
END
$$;
CREATE TRIGGER platform_super_admin_designation_audit AFTER INSERT ON platform_super_admin_designation
  FOR EACH ROW EXECUTE FUNCTION hourvia_audit_platform_change();
CREATE TRIGGER platform_privileges_audit AFTER INSERT OR UPDATE ON platform_privileges
  FOR EACH ROW EXECUTE FUNCTION hourvia_audit_platform_change();

-- 4. Authority of an acting member inside one organization ----------------------------------------------------------
-- NULL: no membership authority. 'workspace_admin': manages Managers and Contractors. 'platform_super_admin': an
-- active Administrator of THIS organization who also holds the active platform privilege; may manage Administrators.
CREATE FUNCTION hourvia_member_authority(actor uuid, organization text) RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT CASE
    WHEN EXISTS (SELECT 1 FROM platform_privileges p WHERE p.auth_user_id = m.auth_user_id AND p.privilege = 'platform_super_admin' AND p.revoked_at IS NULL)
      THEN 'platform_super_admin' ELSE 'workspace_admin' END
  FROM workspace_members m
  WHERE m.id = actor AND m.workspace_id = organization AND m.status = 'active' AND m.role = 'workspace_admin' AND m.auth_user_id IS NOT NULL;
$$;

-- 5. Membership guards (replace the 20261104120000 bodies; same triggers) ----------------------------------------------
CREATE OR REPLACE FUNCTION hourvia_guard_member_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  runtime constant boolean := current_user = 'hourvia_auth_runtime';
  authority text;
BEGIN
  IF NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR NEW.email IS DISTINCT FROM OLD.email
     OR (OLD.auth_user_id IS NOT NULL AND NEW.auth_user_id IS DISTINCT FROM OLD.auth_user_id) THEN
    RAISE EXCEPTION 'workspace_members identity columns are immutable';
  END IF;

  -- Disabled is terminal for the application. Operators may reinstate only through the approved procedure.
  IF OLD.status = 'disabled' AND NEW.status <> 'disabled' THEN
    IF runtime OR coalesce(current_setting('hourvia.member_reinstatement', true), '') <> 'approved' THEN
      RAISE EXCEPTION 'disabled workspace members cannot be re-enabled by the runtime';
    END IF;
    IF NEW.status <> 'active' OR NEW.role IS DISTINCT FROM OLD.role OR OLD.activated_at IS NULL THEN
      RAISE EXCEPTION 'reinstatement restores a previously active member with the same role only';
    END IF;
  ELSIF OLD.status = 'disabled' AND NEW.role IS DISTINCT FROM OLD.role THEN
    RAISE EXCEPTION 'disabled workspace members cannot change role';
  END IF;

  IF NEW.role IS DISTINCT FROM OLD.role THEN
    IF runtime THEN
      IF NEW.role_changed_by IS NULL OR NEW.role_changed_at IS NULL
         OR NEW.role_changed_at IS NOT DISTINCT FROM OLD.role_changed_at THEN
        RAISE EXCEPTION 'role changes must record the authorizing member';
      END IF;
      IF NEW.role_changed_by = NEW.id THEN
        RAISE EXCEPTION 'members cannot change their own role';
      END IF;
      authority := hourvia_member_authority(NEW.role_changed_by, NEW.workspace_id);
      IF authority IS NULL OR ((OLD.role = 'workspace_admin' OR NEW.role = 'workspace_admin') AND authority <> 'platform_super_admin') THEN
        RAISE EXCEPTION 'role change is not authorized for this member';
      END IF;
    ELSIF OLD.status <> 'invited' THEN
      RAISE EXCEPTION 'workspace_members role can change only while invited, or through the application';
    END IF;
    IF NEW.role <> 'workspace_manager' THEN
      NEW.approval_authorized := false;
    END IF;
  END IF;

  IF runtime AND NEW.status IS DISTINCT FROM OLD.status THEN
    IF NEW.status = 'active' THEN
      IF OLD.status <> 'invited' OR NOT EXISTS (
           SELECT 1 FROM workspace_invitations i
           WHERE i.member_id = NEW.id AND i.workspace_id = NEW.workspace_id AND i.status = 'accepted' AND i.role = NEW.role) THEN
        RAISE EXCEPTION 'activation requires an accepted invitation for the same role';
      END IF;
    ELSIF NEW.status = 'disabled' THEN
      authority := hourvia_member_authority(NEW.disabled_by, NEW.workspace_id);
      IF NEW.disabled_by IS NULL OR NEW.disabled_by = NEW.id OR authority IS NULL
         OR (OLD.role = 'workspace_admin' AND authority <> 'platform_super_admin') THEN
        RAISE EXCEPTION 'disable is not authorized for this member';
      END IF;
    ELSE
      RAISE EXCEPTION 'workspace_members status transition is not permitted';
    END IF;
  END IF;
  RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION hourvia_guard_member_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF current_user = 'hourvia_auth_runtime' AND (NEW.status <> 'invited' OR NEW.role_changed_by IS NOT NULL OR NEW.role_changed_at IS NOT NULL) THEN
    RAISE EXCEPTION 'the application can create only invited members';
  END IF;
  RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION hourvia_guard_invitation_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  member_role text;
  member_status text;
  authority text;
BEGIN
  SELECT m.role, m.status INTO member_role, member_status
    FROM workspace_members m WHERE m.id = NEW.member_id AND m.workspace_id = NEW.workspace_id;
  IF member_role IS DISTINCT FROM NEW.role THEN
    RAISE EXCEPTION 'invitation role must match the member role';
  END IF;
  IF NEW.status = 'pending' AND member_status IS DISTINCT FROM 'invited' THEN
    RAISE EXCEPTION 'pending invitations can be issued only to invited members';
  END IF;
  IF NEW.invited_by_member_id IS NULL THEN
    -- NULL is reserved for the reviewed first-administrator bootstrap (operator SQL).
    IF current_user = 'hourvia_auth_runtime' THEN
      RAISE EXCEPTION 'application invitations must record the inviting member';
    END IF;
  ELSE
    authority := hourvia_member_authority(NEW.invited_by_member_id, NEW.workspace_id);
    IF NEW.invited_by_member_id = NEW.member_id OR authority IS NULL
       OR (NEW.role = 'workspace_admin' AND authority <> 'platform_super_admin') THEN
      RAISE EXCEPTION 'inviter is not authorized to grant this role';
    END IF;
  END IF;
  RETURN NEW;
END
$$;

-- 6. Session revocation attribution -----------------------------------------------------------------------------------
ALTER TABLE auth_sessions ADD COLUMN revoked_by_member_id uuid REFERENCES workspace_members(id);
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_revoked_by_requires_revocation
  CHECK (revoked_by_member_id IS NULL OR revoked_at IS NOT NULL);
GRANT UPDATE (revoked_by_member_id) ON auth_sessions TO hourvia_auth_runtime;

CREATE FUNCTION hourvia_guard_session_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  authority text;
  subject_role text;
  subject_workspace text;
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id OR NEW.token_hash IS DISTINCT FROM OLD.token_hash OR NEW.member_id IS DISTINCT FROM OLD.member_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.absolute_expires_at IS DISTINCT FROM OLD.absolute_expires_at THEN
    RAISE EXCEPTION 'auth_sessions identity columns are immutable';
  END IF;
  IF OLD.revoked_at IS NOT NULL AND (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at OR NEW.revoked_reason IS DISTINCT FROM OLD.revoked_reason
     OR NEW.revoked_by_member_id IS DISTINCT FROM OLD.revoked_by_member_id) THEN
    RAISE EXCEPTION 'session revocation is final';
  END IF;
  IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL AND current_user = 'hourvia_auth_runtime' THEN
    IF NEW.revoked_by_member_id IS NULL THEN
      RAISE EXCEPTION 'application session revocations must record the acting member';
    END IF;
    IF NEW.revoked_by_member_id <> NEW.member_id THEN
      SELECT m.role, m.workspace_id INTO subject_role, subject_workspace FROM workspace_members m WHERE m.id = NEW.member_id;
      authority := hourvia_member_authority(NEW.revoked_by_member_id, subject_workspace);
      IF authority IS NULL OR (subject_role = 'workspace_admin' AND authority <> 'platform_super_admin') THEN
        RAISE EXCEPTION 'session revocation is not authorized for this member';
      END IF;
    END IF;
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER auth_sessions_guard BEFORE UPDATE ON auth_sessions
  FOR EACH ROW EXECUTE FUNCTION hourvia_guard_session_update();

CREATE FUNCTION hourvia_audit_session_revocation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  subject_workspace text;
  authority text;
BEGIN
  SELECT m.workspace_id INTO subject_workspace FROM workspace_members m WHERE m.id = NEW.member_id;
  authority := CASE
    WHEN NEW.revoked_by_member_id IS NULL THEN 'operator'
    WHEN NEW.revoked_by_member_id = NEW.member_id THEN 'self'
    ELSE coalesce(hourvia_member_authority(NEW.revoked_by_member_id, subject_workspace), 'unknown') END;
  INSERT INTO auth_audit_events (workspace_id, occurred_at, event_type, outcome, actor_member_id, subject_member_id, details)
  VALUES (subject_workspace, now(), 'session_revocation', 'success', NEW.revoked_by_member_id, NEW.member_id,
          jsonb_build_object('reason', NEW.revoked_reason, 'authority', authority,
                             'source', CASE WHEN current_user = 'hourvia_auth_runtime' THEN 'application' ELSE 'operator_sql' END));
  RETURN NULL;
END
$$;
CREATE TRIGGER auth_sessions_revocation_audit AFTER UPDATE ON auth_sessions
  FOR EACH ROW WHEN (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL)
  EXECUTE FUNCTION hourvia_audit_session_revocation();

-- 7. Privileges ------------------------------------------------------------------------------------------------------
REVOKE ALL ON platform_super_admin_designation, platform_privileges, platform_audit_events FROM PUBLIC;
REVOKE ALL ON SEQUENCE platform_audit_events_id_seq FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'netlifydb_readonly') THEN
    REVOKE ALL ON platform_super_admin_designation, platform_privileges, platform_audit_events FROM netlifydb_readonly;
    REVOKE ALL ON SEQUENCE platform_audit_events_id_seq FROM netlifydb_readonly;
  END IF;
END
$$;
REVOKE ALL ON platform_super_admin_designation, platform_privileges, platform_audit_events FROM hourvia_auth_runtime;
-- The runtime may only learn whether a UID holds an active privilege. It can never grant, revoke or read history.
GRANT SELECT (auth_user_id, privilege, revoked_at) ON platform_privileges TO hourvia_auth_runtime;
REVOKE ALL ON FUNCTION hourvia_is_verified_platform_candidate(uuid), hourvia_member_authority(uuid, text),
  hourvia_guard_platform_designation(), hourvia_guard_platform_privilege(), hourvia_audit_platform_change(),
  hourvia_guard_session_update(), hourvia_audit_session_revocation() FROM PUBLIC;
-- Called from inside the membership, invitation and session guards, which run as the invoking role.
GRANT EXECUTE ON FUNCTION hourvia_member_authority(uuid, text) TO hourvia_auth_runtime;

-- 8. Self-check: any surprise aborts this migration (and the deploy). ---------------------------------------------------
DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['platform_super_admin_designation', 'platform_privileges', 'platform_audit_events'] LOOP
    IF has_table_privilege('public', 'public.' || t, 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
       OR has_any_column_privilege('public', 'public.' || t, 'SELECT, INSERT, UPDATE, REFERENCES')
       OR (EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'netlifydb_readonly')
           AND (has_table_privilege('netlifydb_readonly', 'public.' || t, 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE')
                OR has_any_column_privilege('netlifydb_readonly', 'public.' || t, 'SELECT, INSERT, UPDATE'))) THEN
      RAISE EXCEPTION 'privilege check failed: % is exposed to PUBLIC or netlifydb_readonly', t;
    END IF;
    IF has_table_privilege('hourvia_auth_runtime', 'public.' || t, 'INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
       OR has_any_column_privilege('hourvia_auth_runtime', 'public.' || t, 'INSERT, UPDATE, REFERENCES') THEN
      RAISE EXCEPTION 'privilege check failed: hourvia_auth_runtime can write %', t;
    END IF;
  END LOOP;
  IF has_any_column_privilege('hourvia_auth_runtime', 'public.platform_super_admin_designation', 'SELECT')
     OR has_any_column_privilege('hourvia_auth_runtime', 'public.platform_audit_events', 'SELECT')
     OR has_column_privilege('hourvia_auth_runtime', 'public.platform_privileges', 'grant_approval_ref', 'SELECT')
     OR NOT has_column_privilege('hourvia_auth_runtime', 'public.platform_privileges', 'auth_user_id', 'SELECT')
     OR NOT has_column_privilege('hourvia_auth_runtime', 'public.auth_sessions', 'revoked_by_member_id', 'UPDATE') THEN
    RAISE EXCEPTION 'privilege check failed: unexpected runtime access to platform or session attribution columns';
  END IF;
  IF has_column_privilege('hourvia_auth_runtime', 'public.workspace_members', 'approval_authorized', 'UPDATE')
     OR has_table_privilege('hourvia_auth_runtime', 'public.workspace_members', 'DELETE, TRUNCATE')
     OR has_table_privilege('hourvia_auth_runtime', 'public.auth_audit_events', 'SELECT, UPDATE, DELETE, TRUNCATE') THEN
    RAISE EXCEPTION 'privilege check failed: hourvia_auth_runtime has a forbidden privilege';
  END IF;
  IF (SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled = 'O' AND tgname IN
       ('workspace_members_guard', 'workspace_members_guard_insert', 'workspace_members_audit', 'workspace_invitations_guard',
        'auth_sessions_guard', 'auth_sessions_revocation_audit', 'platform_privileges_guard', 'platform_privileges_audit',
        'platform_super_admin_designation_guard', 'platform_super_admin_designation_audit')) <> 10 THEN
    RAISE EXCEPTION 'self-check failed: guard or audit triggers are missing or disabled';
  END IF;
  IF EXISTS (SELECT 1 FROM platform_privileges) OR EXISTS (SELECT 1 FROM platform_super_admin_designation) THEN
    RAISE EXCEPTION 'self-check failed: this migration must not designate or grant anyone';
  END IF;
END
$$;
