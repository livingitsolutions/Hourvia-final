-- OPERATOR PROCEDURE — NOT A MIGRATION. Revokes the active platform_super_admin privilege (AP-PSA-REVOKE).
-- Use for suspected compromise, role change or offboarding. History is kept; reinstatement is a fresh, separately
-- approved run of grant-platform-super-admin.sql. The ThriveSource membership is not changed (disable it, if needed,
-- through the application or the member procedure). Replace exactly four quoted placeholders:
--   '<SUPABASE_AUTH_UID>'  the holder's Supabase Auth user id
--   '<APPROVAL_REF>'       3-64 characters from [A-Za-z0-9._:-]
--   '<REASON>'             lower_snake_case, for example suspected_compromise or offboarding
--   '<END_SESSIONS>'       'true' to end every Hourvia session of that identity now, otherwise 'false'
DO $revoke$
DECLARE
  v_uid_raw  constant text := '<SUPABASE_AUTH_UID>';
  v_approval constant text := '<APPROVAL_REF>';
  v_reason   constant text := '<REASON>';
  v_end_raw  constant text := '<END_SESSIONS>';
  v_uid      uuid;
  v_grant_id uuid;
  v_revoked  integer := 0;
BEGIN
  IF v_approval !~ '^[A-Za-z0-9._:-]{3,64}$' THEN RAISE EXCEPTION 'revoke_input: approval reference must be 3-64 characters from [A-Za-z0-9._:-]'; END IF;
  IF v_reason !~ '^[a-z_]{1,64}$' THEN RAISE EXCEPTION 'revoke_input: reason must be lower_snake_case'; END IF;
  IF v_end_raw NOT IN ('true', 'false') THEN RAISE EXCEPTION 'revoke_input: END_SESSIONS must be true or false'; END IF;
  IF v_uid_raw !~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' THEN RAISE EXCEPTION 'revoke_input: UID must be a UUID'; END IF;
  v_uid := v_uid_raw::uuid;

  PERFORM set_config('lock_timeout', '5s', true);
  LOCK TABLE platform_privileges IN SHARE ROW EXCLUSIVE MODE;
  UPDATE platform_privileges SET revoked_at = now(), revoke_approval_ref = v_approval, revoked_reason = v_reason
   WHERE auth_user_id = v_uid AND privilege = 'platform_super_admin' AND revoked_at IS NULL
  RETURNING id INTO v_grant_id;
  IF v_grant_id IS NULL THEN
    RAISE NOTICE 'platform_super_admin_not_active (no privilege changes written)';
  END IF;

  IF v_end_raw = 'true' THEN
    UPDATE auth_sessions s SET revoked_at = now(), revoked_reason = 'platform_privilege_revoked'
      FROM workspace_members m WHERE m.id = s.member_id AND m.auth_user_id = v_uid AND s.revoked_at IS NULL;
    GET DIAGNOSTICS v_revoked = ROW_COUNT;
  END IF;
  IF EXISTS (SELECT 1 FROM platform_privileges WHERE auth_user_id = v_uid AND revoked_at IS NULL) THEN
    RAISE EXCEPTION 'revoke_selfcheck: an active grant remains; rolled back';
  END IF;
  RAISE NOTICE 'platform_super_admin_revoked grant_id=% sessions_revoked=%', v_grant_id, v_revoked;
END
$revoke$;
