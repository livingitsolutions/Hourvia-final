-- OPERATOR PROCEDURE — NOT A MIGRATION. Reinstates a member who was disabled in error (AP-MEMBER-REINSTATE).
-- Restores status 'active' with the SAME role and identity. It does not restore ended sessions, does not change the
-- role and does not grant any platform privilege. Sprint 3.0.2 (G1): any session of the member that is still unrevoked
-- is revoked FIRST, in the same transaction, so reinstatement can never revive an old session; the member signs in again.
-- Sprint 3.0.3: on M7 such a session can exist even after an atomic application disable (a login that read the member
-- as active just before the disable committed inserts its session afterwards; M7 has no session insert guard), as well
-- as after a pre-3.0.2 or operator disable. This procedure is therefore MANDATORY for every reinstatement; never
-- re-enable a member with a raw UPDATE. Before running it, unban the Supabase user (Authentication ->
-- Users) under the same approval; Hourvia banned it when the member was disabled.
-- Replace exactly two quoted placeholders: '<EXPECTED_MEMBER_ID>' and '<APPROVAL_REF>'.
DO $reinstate$
DECLARE
  v_member_raw constant text := '<EXPECTED_MEMBER_ID>';
  v_approval   constant text := '<APPROVAL_REF>';
  m            workspace_members%ROWTYPE;
  v_swept      integer;
BEGIN
  IF v_approval !~ '^[A-Za-z0-9._:-]{3,64}$' THEN RAISE EXCEPTION 'reinstate_input: approval reference must be 3-64 characters from [A-Za-z0-9._:-]'; END IF;
  IF v_member_raw !~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' THEN RAISE EXCEPTION 'reinstate_input: member id must be a UUID'; END IF;
  PERFORM set_config('lock_timeout', '5s', true);
  LOCK TABLE workspace_members IN SHARE ROW EXCLUSIVE MODE;
  SELECT * INTO m FROM workspace_members WHERE id = v_member_raw::uuid AND workspace_id = 'thrivesource';
  IF NOT FOUND THEN RAISE EXCEPTION 'reinstate_guard: member not found; nothing was written'; END IF;
  IF m.status = 'active' THEN RAISE NOTICE 'member_already_active member_id=% (no changes written)', m.id; RETURN; END IF;
  IF m.status <> 'disabled' OR m.activated_at IS NULL OR m.auth_user_id IS NULL THEN
    RAISE EXCEPTION 'reinstate_guard: only a previously activated, disabled member can be reinstated; nothing was written';
  END IF;
  UPDATE auth_sessions SET revoked_at = now(), revoked_reason = 'member_reinstated'
   WHERE member_id = m.id AND revoked_at IS NULL;
  GET DIAGNOSTICS v_swept = ROW_COUNT;
  PERFORM set_config('hourvia.member_reinstatement', 'approved', true);
  UPDATE workspace_members SET status = 'active', disabled_at = NULL, disabled_by = NULL WHERE id = m.id AND status = 'disabled';
  PERFORM set_config('hourvia.member_reinstatement', '', true);
  INSERT INTO auth_audit_events (workspace_id, occurred_at, event_type, outcome, subject_member_id, details)
  VALUES ('thrivesource', now(), 'member_reinstated', 'success', m.id,
          jsonb_build_object('method', 'operator_sql', 'approval_ref', v_approval, 'role', m.role, 'previously_disabled_by', m.disabled_by, 'stale_sessions_revoked', v_swept));
  RAISE NOTICE 'member_reinstated member_id=% role=% stale_sessions_revoked=%', m.id, m.role, v_swept;
END
$reinstate$;
