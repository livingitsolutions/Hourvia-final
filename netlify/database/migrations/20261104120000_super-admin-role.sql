-- Hourvia — exclusive Super Admin role (forward-only; does not edit 20261103170000 or 20261103170100)
--
-- What this migration does:
--   * Adds the 'super_admin' role above 'workspace_admin' for workspace_members only. Invitations can never
--     carry it, so it can never be granted by email.
--   * Binds super_admin to the designated Living IT Solutions mailbox and allows at most one holder.
--   * Records who authorized every application role change (role_changed_by / role_changed_at).
--   * Replaces the member update guard so the DATABASE (not only the API) enforces the authorization matrix
--     for the restricted runtime role: Administrators may manage only Managers and Contractors; only the
--     Super Admin may grant, change or revoke Administrator access; nobody may change their own role; the
--     Super Admin row cannot be demoted, reassigned, disabled or deleted by the application.
--   * Writes an append-only audit row for every membership insert, role change and status change, whether it
--     came from the application or from operator SQL.
--
-- What it does NOT do: it changes no existing row. No member is promoted here. The one-time promotion of the
-- existing Living IT Solutions membership is a separate, guarded, idempotent operator script
-- (db/operations/super-admin/promote-designated-super-admin.sql) that needs its own approval.

-- 1. Role vocabulary and Super Admin exclusivity -------------------------------------------------------------
ALTER TABLE workspace_members DROP CONSTRAINT workspace_members_role_check;
ALTER TABLE workspace_members ADD CONSTRAINT workspace_members_role_check
  CHECK (role IN ('super_admin', 'workspace_admin', 'workspace_manager', 'contractor'));
-- Only the designated mailbox, only with a bound identity, never in the invited state.
ALTER TABLE workspace_members ADD CONSTRAINT workspace_members_super_admin_designated
  CHECK (role <> 'super_admin' OR (email = 'livingitsolutions@gmail.com' AND auth_user_id IS NOT NULL AND status <> 'invited'));
-- At most one Super Admin per workspace (defence in depth on top of the unique email).
CREATE UNIQUE INDEX workspace_members_one_super_admin ON workspace_members (workspace_id) WHERE role = 'super_admin';
-- Invitations already exclude super_admin through their role CHECK; this keeps it excluded if that CHECK widens.
ALTER TABLE workspace_invitations ADD CONSTRAINT workspace_invitations_no_super_admin CHECK (role <> 'super_admin');

-- 2. Role-change attribution ----------------------------------------------------------------------------------
ALTER TABLE workspace_members
  ADD COLUMN role_changed_by uuid REFERENCES workspace_members(id),
  ADD COLUMN role_changed_at timestamptz;
ALTER TABLE workspace_members ADD CONSTRAINT workspace_members_role_changed_by_not_self
  CHECK (role_changed_by IS NULL OR role_changed_by <> id);
GRANT UPDATE (role_changed_by, role_changed_at) ON workspace_members TO hourvia_auth_runtime;

-- 3. Member update guard (replaces the 20261103170100 body; same trigger) -------------------------------------
CREATE OR REPLACE FUNCTION hourvia_guard_member_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  runtime constant boolean := current_user = 'hourvia_auth_runtime';
  actor_role text;
  actor_status text;
BEGIN
  -- Unchanged invariants from 20261103170100.
  IF NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR NEW.email IS DISTINCT FROM OLD.email
     OR (OLD.auth_user_id IS NOT NULL AND NEW.auth_user_id IS DISTINCT FROM OLD.auth_user_id) THEN
    RAISE EXCEPTION 'workspace_members identity columns are immutable';
  END IF;
  IF OLD.status = 'disabled' AND NEW.status <> 'disabled' THEN
    RAISE EXCEPTION 'disabled workspace members cannot be re-enabled by the runtime';
  END IF;
  IF OLD.status = 'disabled' AND NEW.role IS DISTINCT FROM OLD.role THEN
    RAISE EXCEPTION 'disabled workspace members cannot change role';
  END IF;

  -- Super Admin: granted only by the approved operator promotion, never by the application.
  IF NEW.role = 'super_admin' AND OLD.role IS DISTINCT FROM 'super_admin' THEN
    IF runtime OR coalesce(current_setting('hourvia.super_admin_promotion', true), '') <> 'approved' THEN
      RAISE EXCEPTION 'super_admin can be assigned only by the approved operator promotion';
    END IF;
    IF OLD.role <> 'workspace_admin' OR OLD.status <> 'active' OR NEW.status <> 'active' THEN
      RAISE EXCEPTION 'super_admin promotion requires an active workspace_admin';
    END IF;
  END IF;
  IF OLD.role = 'super_admin' THEN
    IF NEW.role IS DISTINCT FROM 'super_admin' THEN
      RAISE EXCEPTION 'super_admin cannot be demoted or reassigned';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status AND (runtime OR NEW.status <> 'disabled'
        OR coalesce(current_setting('hourvia.super_admin_break_glass', true), '') <> 'approved') THEN
      RAISE EXCEPTION 'super_admin status can change only through the approved break-glass procedure';
    END IF;
  END IF;

  -- Ordinary role changes.
  IF NEW.role IS DISTINCT FROM OLD.role AND NEW.role <> 'super_admin' THEN
    IF runtime THEN
      IF NEW.role_changed_by IS NULL OR NEW.role_changed_at IS NULL
         OR NEW.role_changed_at IS NOT DISTINCT FROM OLD.role_changed_at THEN
        RAISE EXCEPTION 'role changes must record the authorizing member';
      END IF;
      IF NEW.role_changed_by = NEW.id THEN
        RAISE EXCEPTION 'members cannot change their own role';
      END IF;
      SELECT m.role, m.status INTO actor_role, actor_status
        FROM workspace_members m WHERE m.id = NEW.role_changed_by AND m.workspace_id = NEW.workspace_id;
      IF actor_status IS DISTINCT FROM 'active' OR actor_role IS NULL
         OR actor_role NOT IN ('super_admin', 'workspace_admin')
         OR ((OLD.role = 'workspace_admin' OR NEW.role = 'workspace_admin') AND actor_role <> 'super_admin') THEN
        RAISE EXCEPTION 'role change is not authorized for this member';
      END IF;
    ELSIF OLD.status <> 'invited' THEN
      RAISE EXCEPTION 'workspace_members role can change only while invited, or through the application';
    END IF;
    -- Approval authority belongs to Managers only; clear it when a Manager changes role.
    IF NEW.role <> 'workspace_manager' THEN
      NEW.approval_authorized := false;
    END IF;
  END IF;

  -- Status transitions performed by the application.
  IF runtime AND NEW.status IS DISTINCT FROM OLD.status THEN
    IF NEW.status = 'active' THEN
      IF OLD.status <> 'invited' OR NOT EXISTS (
           SELECT 1 FROM workspace_invitations i
           WHERE i.member_id = NEW.id AND i.workspace_id = NEW.workspace_id AND i.status = 'accepted' AND i.role = NEW.role) THEN
        RAISE EXCEPTION 'activation requires an accepted invitation for the same role';
      END IF;
    ELSIF NEW.status = 'disabled' THEN
      SELECT m.role, m.status INTO actor_role, actor_status
        FROM workspace_members m WHERE m.id = NEW.disabled_by AND m.workspace_id = NEW.workspace_id;
      IF actor_status IS DISTINCT FROM 'active' OR actor_role IS NULL
         OR actor_role NOT IN ('super_admin', 'workspace_admin')
         OR (OLD.role = 'workspace_admin' AND actor_role <> 'super_admin') THEN
        RAISE EXCEPTION 'disable is not authorized for this member';
      END IF;
    ELSE
      RAISE EXCEPTION 'workspace_members status transition is not permitted';
    END IF;
  END IF;
  RETURN NEW;
END
$$;

-- 4. Member insert guard ---------------------------------------------------------------------------------------
CREATE FUNCTION hourvia_guard_member_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF NEW.role = 'super_admin' THEN
    RAISE EXCEPTION 'super_admin cannot be inserted; promote the active designated workspace_admin with the approved operator procedure';
  END IF;
  IF current_user = 'hourvia_auth_runtime' AND (NEW.status <> 'invited' OR NEW.role_changed_by IS NOT NULL OR NEW.role_changed_at IS NOT NULL) THEN
    RAISE EXCEPTION 'the application can create only invited members';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER workspace_members_guard_insert BEFORE INSERT ON workspace_members
  FOR EACH ROW EXECUTE FUNCTION hourvia_guard_member_insert();

-- 5. Invitation insert guard: who may invite whom ----------------------------------------------------------------
CREATE FUNCTION hourvia_guard_invitation_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  member_role text;
  member_status text;
  inviter_role text;
  inviter_status text;
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
    SELECT m.role, m.status INTO inviter_role, inviter_status
      FROM workspace_members m WHERE m.id = NEW.invited_by_member_id AND m.workspace_id = NEW.workspace_id;
    IF NEW.invited_by_member_id = NEW.member_id OR inviter_status IS DISTINCT FROM 'active' OR inviter_role IS NULL
       OR inviter_role NOT IN ('super_admin', 'workspace_admin')
       OR (NEW.role = 'workspace_admin' AND inviter_role <> 'super_admin') THEN
      RAISE EXCEPTION 'inviter is not authorized to grant this role';
    END IF;
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER workspace_invitations_guard BEFORE INSERT ON workspace_invitations
  FOR EACH ROW EXECUTE FUNCTION hourvia_guard_invitation_insert();

-- 6. Database-level audit of every membership change ---------------------------------------------------------------
CREATE FUNCTION hourvia_audit_member_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  role_changed boolean := TG_OP = 'UPDATE' AND NEW.role IS DISTINCT FROM OLD.role;
BEGIN
  IF TG_OP = 'UPDATE' AND NOT role_changed AND NEW.status IS NOT DISTINCT FROM OLD.status THEN
    RETURN NULL;
  END IF;
  INSERT INTO auth_audit_events (workspace_id, occurred_at, event_type, outcome, actor_member_id, subject_member_id, details)
  VALUES (
    NEW.workspace_id, now(),
    CASE WHEN TG_OP = 'INSERT' THEN 'membership_created' WHEN role_changed THEN 'membership_role_changed' ELSE 'membership_status_changed' END,
    'success',
    CASE WHEN TG_OP = 'INSERT' THEN NULL
         WHEN role_changed THEN NEW.role_changed_by
         WHEN NEW.status = 'disabled' THEN NEW.disabled_by
         WHEN NEW.status = 'active' THEN NEW.id END,
    NEW.id,
    jsonb_build_object(
      'from_role', CASE WHEN TG_OP = 'UPDATE' THEN OLD.role END, 'to_role', NEW.role,
      'from_status', CASE WHEN TG_OP = 'UPDATE' THEN OLD.status END, 'to_status', NEW.status,
      'source', CASE WHEN current_user = 'hourvia_auth_runtime' THEN 'application' ELSE 'operator_sql' END));
  RETURN NULL;
END
$$;
CREATE TRIGGER workspace_members_audit AFTER INSERT OR UPDATE ON workspace_members
  FOR EACH ROW EXECUTE FUNCTION hourvia_audit_member_change();

REVOKE ALL ON FUNCTION hourvia_guard_member_update() FROM PUBLIC;
REVOKE ALL ON FUNCTION hourvia_guard_member_insert() FROM PUBLIC;
REVOKE ALL ON FUNCTION hourvia_guard_invitation_insert() FROM PUBLIC;
REVOKE ALL ON FUNCTION hourvia_audit_member_change() FROM PUBLIC;

-- 7. Self-check: any surprise aborts this migration (and the deploy) instead of weakening access control. -------------
DO $$
BEGIN
  IF has_column_privilege('hourvia_auth_runtime', 'public.workspace_members', 'approval_authorized', 'UPDATE')
     OR has_column_privilege('hourvia_auth_runtime', 'public.workspace_members', 'auth_user_id', 'UPDATE')
     OR has_column_privilege('hourvia_auth_runtime', 'public.workspace_members', 'email', 'UPDATE')
     OR has_column_privilege('hourvia_auth_runtime', 'public.workspace_members', 'workspace_id', 'UPDATE')
     OR has_column_privilege('hourvia_auth_runtime', 'public.workspace_members', 'role_changed_by', 'INSERT')
     OR has_column_privilege('hourvia_auth_runtime', 'public.workspace_invitations', 'role', 'UPDATE')
     OR has_table_privilege('hourvia_auth_runtime', 'public.workspace_members', 'DELETE, TRUNCATE')
     OR has_table_privilege('hourvia_auth_runtime', 'public.auth_audit_events', 'SELECT, UPDATE, DELETE, TRUNCATE') THEN
    RAISE EXCEPTION 'privilege check failed: hourvia_auth_runtime has a forbidden privilege';
  END IF;
  IF NOT has_column_privilege('hourvia_auth_runtime', 'public.workspace_members', 'role_changed_by', 'UPDATE')
     OR NOT has_column_privilege('hourvia_auth_runtime', 'public.workspace_members', 'role_changed_at', 'UPDATE') THEN
    RAISE EXCEPTION 'privilege check failed: hourvia_auth_runtime cannot record role-change attribution';
  END IF;
  IF has_any_column_privilege('public', 'public.workspace_members', 'SELECT, INSERT, UPDATE, REFERENCES')
     OR (EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'netlifydb_readonly')
         AND has_any_column_privilege('netlifydb_readonly', 'public.workspace_members', 'SELECT, INSERT, UPDATE, REFERENCES')) THEN
    RAISE EXCEPTION 'privilege check failed: workspace_members is exposed to PUBLIC or netlifydb_readonly';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_attribute at JOIN pg_class c ON c.oid = at.attrelid CROSS JOIN LATERAL aclexplode(at.attacl) a
    WHERE c.oid = 'public.workspace_members'::regclass AND a.grantee NOT IN (c.relowner, 'hourvia_auth_runtime'::regrole)) THEN
    RAISE EXCEPTION 'privilege check failed: an unexpected role is granted a workspace_members column';
  END IF;
  IF (SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled = 'O' AND tgname IN
       ('workspace_members_guard', 'workspace_members_guard_insert', 'workspace_members_audit', 'workspace_invitations_guard')) <> 4 THEN
    RAISE EXCEPTION 'self-check failed: membership guard triggers are missing or disabled';
  END IF;
  IF (SELECT count(*) FROM workspace_members WHERE role = 'super_admin') <> 0 THEN
    RAISE EXCEPTION 'self-check failed: this migration must not create or find a super_admin';
  END IF;
END
$$;
