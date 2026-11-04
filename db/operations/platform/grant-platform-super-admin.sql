-- OPERATOR PROCEDURE — NOT A MIGRATION. Never copy into netlify/database/migrations/.
-- Grants (or, after a revocation, reinstates) platform_super_admin to the verified Living IT Solutions identity.
-- Requires migration 20261104130000_platform-privileges-correction and its own written approval (AP-PSA-GRANT).
-- Owner SQL editor (netlifydb_owner) on the intended branch. Replace exactly three quoted placeholders:
--   '<SUPABASE_AUTH_UID>'   the Supabase Auth user id of livingitsolutions@gmail.com (copied from read-only query Q1)
--   '<EXPECTED_MEMBER_ID>'  the workspace_members.id of the same membership (Q1)
--   '<APPROVAL_REF>'        3-64 characters from [A-Za-z0-9._:-], no email address
-- First run also writes the immutable designation. The ThriveSource membership row is NOT changed: its role,
-- id, sessions and history stay as they are. Re-running while the grant is active writes nothing.
DO $grant$
DECLARE
  v_uid_raw    constant text := '<SUPABASE_AUTH_UID>';
  v_member_raw constant text := '<EXPECTED_MEMBER_ID>';
  v_approval   constant text := '<APPROVAL_REF>';
  v_uuid       constant text := '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$';
  v_uid        uuid;
  m            workspace_members%ROWTYPE;
  d            platform_super_admin_designation%ROWTYPE;
  v_grant_id   uuid;
BEGIN
  IF v_approval !~ '^[A-Za-z0-9._:-]{3,64}$' THEN RAISE EXCEPTION 'grant_input: approval reference must be 3-64 characters from [A-Za-z0-9._:-]'; END IF;
  IF v_uid_raw !~ v_uuid OR v_member_raw !~ v_uuid THEN RAISE EXCEPTION 'grant_input: UID and member id must be UUIDs'; END IF;
  v_uid := v_uid_raw::uuid;

  PERFORM set_config('lock_timeout', '5s', true);
  LOCK TABLE platform_super_admin_designation, platform_privileges IN SHARE ROW EXCLUSIVE MODE;

  SELECT * INTO m FROM workspace_members WHERE workspace_id = 'thrivesource' AND email = 'livingitsolutions@gmail.com';
  IF NOT FOUND OR m.id <> v_member_raw::uuid OR m.auth_user_id IS DISTINCT FROM v_uid THEN
    RAISE EXCEPTION 'grant_guard: UID and member id do not match the Living IT Solutions membership; nothing was written';
  END IF;
  IF m.status <> 'active' OR m.activated_at IS NULL THEN
    RAISE EXCEPTION 'grant_guard: the membership is %, not an activated active member; nothing was written', m.status;
  END IF;

  SELECT * INTO d FROM platform_super_admin_designation;
  IF FOUND AND d.auth_user_id <> v_uid THEN
    RAISE EXCEPTION 'grant_guard: a different identity is designated; nothing was written';
  END IF;
  IF EXISTS (SELECT 1 FROM platform_privileges WHERE privilege = 'platform_super_admin' AND revoked_at IS NULL) THEN
    IF EXISTS (SELECT 1 FROM platform_privileges WHERE privilege = 'platform_super_admin' AND revoked_at IS NULL AND auth_user_id = v_uid) THEN
      RAISE NOTICE 'platform_super_admin_already_active uid_member=% (no changes written)', m.id;
      RETURN;
    END IF;
    RAISE EXCEPTION 'grant_guard: another identity holds an active platform_super_admin; nothing was written';
  END IF;

  IF d.auth_user_id IS NULL THEN
    INSERT INTO platform_super_admin_designation (auth_user_id, approval_ref) VALUES (v_uid, v_approval);
  END IF;
  INSERT INTO platform_privileges (auth_user_id, privilege, grant_approval_ref) VALUES (v_uid, 'platform_super_admin', v_approval)
  RETURNING id INTO v_grant_id;

  IF (SELECT count(*) FROM platform_privileges WHERE revoked_at IS NULL) <> 1
     OR NOT EXISTS (SELECT 1 FROM workspace_members WHERE id = m.id AND role = m.role AND status = 'active') THEN
    RAISE EXCEPTION 'grant_selfcheck: unexpected result; rolled back';
  END IF;
  RAISE NOTICE 'platform_super_admin_granted grant_id=% member_id=% member_role=%', v_grant_id, m.id, m.role;
END
$grant$;
