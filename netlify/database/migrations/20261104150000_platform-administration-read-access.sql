-- Hourvia Sprint 1.8 — Platform Administration foundation (forward-only; the four earlier migrations stay unchanged)
--
-- Gives the application READ-ONLY access to platform data, only for the active Platform Super Admin, through two narrow
-- SECURITY DEFINER functions. No table privilege is granted or widened:
--   * hourvia_auth_runtime still cannot write platform_privileges, platform_super_admin_designation or
--     platform_audit_events, and still cannot SELECT the designation, the audit table or grant approval references.
--   * Each function authorizes inside the database from the caller's SESSION (sha-256 token hash), not from a UID or
--     role supplied by the caller. The session must be unrevoked and unexpired, its membership active in ThriveSource,
--     and its identity the designated, verified holder of an active, unrevoked platform_super_admin grant. The
--     organization role is deliberately NOT consulted: platform permissions never come from workspace permissions.
--     A holder whose membership is disabled has no valid session, so access fails closed.
--   * Anything else returns NULL; the API maps that to 403.
--   * Reading the platform audit trail is itself audited in platform_audit_events ('platform_audit_read').
--   * Organization data is limited to aggregate ThriveSource membership counts. No member identities, no other
--     tenant, no impersonation, no privilege management.
-- Grant, revoke and reinstatement remain operator-only procedures (db/operations/platform/).
-- Compatibility: creates functions only; changes no table, trigger, grant or row.

-- 0. Preconditions -----------------------------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hourvia_auth_runtime') THEN
    RAISE EXCEPTION 'hourvia_auth_runtime does not exist; apply 20261103170100 first';
  END IF;
  IF to_regclass('public.platform_privileges') IS NULL OR to_regclass('public.platform_audit_events') IS NULL
     OR to_regclass('public.platform_super_admin_designation') IS NULL
     OR to_regprocedure('public.hourvia_is_verified_platform_candidate(uuid)') IS NULL THEN
    RAISE EXCEPTION 'platform privilege tables are missing; apply 20261104130000 first';
  END IF;
END
$$;

-- 1. Session-bound holder resolution (internal; not executable by any application role) ----------------------------
CREATE FUNCTION hourvia_platform_session_holder(p_token_hash text) RETURNS uuid
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT m.auth_user_id
  FROM auth_sessions s
  JOIN workspace_members m ON m.id = s.member_id
  WHERE p_token_hash ~ '^[0-9a-f]{64}$'
    AND s.token_hash = p_token_hash
    AND s.revoked_at IS NULL AND s.idle_expires_at > now() AND s.absolute_expires_at > now()
    AND m.workspace_id = 'thrivesource' AND m.status = 'active' AND m.auth_user_id IS NOT NULL
    AND EXISTS (SELECT 1 FROM platform_super_admin_designation d WHERE d.auth_user_id = m.auth_user_id)
    AND EXISTS (SELECT 1 FROM platform_privileges p
                WHERE p.auth_user_id = m.auth_user_id AND p.privilege = 'platform_super_admin' AND p.revoked_at IS NULL)
    AND hourvia_is_verified_platform_candidate(m.auth_user_id)
  LIMIT 1;
$$;

-- 2. Overview: the holder's own grant, grant history counts, aggregate ThriveSource counts, audit summary ------------
CREATE FUNCTION hourvia_platform_overview(p_token_hash text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  holder uuid := hourvia_platform_session_holder(p_token_hash);
BEGIN
  IF holder IS NULL THEN
    RETURN NULL;
  END IF;
  RETURN jsonb_build_object(
    'grant', (SELECT jsonb_build_object('privilege', p.privilege, 'granted_at', p.granted_at, 'approval_ref', p.grant_approval_ref)
              FROM platform_privileges p
              WHERE p.auth_user_id = holder AND p.privilege = 'platform_super_admin' AND p.revoked_at IS NULL
              ORDER BY p.granted_at DESC LIMIT 1),
    'designated_at', (SELECT d.designated_at FROM platform_super_admin_designation d WHERE d.auth_user_id = holder),
    'grant_history', (SELECT jsonb_build_object('granted', count(*), 'revoked', count(p.revoked_at))
                      FROM platform_privileges p WHERE p.privilege = 'platform_super_admin'),
    'organizations', jsonb_build_array((
      SELECT jsonb_build_object(
        'id', 'thrivesource',
        'members', jsonb_build_object(
          'active', count(*) FILTER (WHERE m.status = 'active'),
          'invited', count(*) FILTER (WHERE m.status = 'invited'),
          'disabled', count(*) FILTER (WHERE m.status = 'disabled')),
        'active_roles', jsonb_build_object(
          'workspace_admin', count(*) FILTER (WHERE m.status = 'active' AND m.role = 'workspace_admin'),
          'workspace_manager', count(*) FILTER (WHERE m.status = 'active' AND m.role = 'workspace_manager'),
          'contractor', count(*) FILTER (WHERE m.status = 'active' AND m.role = 'contractor')))
      FROM workspace_members m WHERE m.workspace_id = 'thrivesource')),
    'audit', (SELECT jsonb_build_object('events', count(*), 'last_event_at', max(e.occurred_at)) FROM platform_audit_events e));
END
$$;

-- 3. Platform audit page: newest first, keyset pagination by id, 1..100 rows; the read itself is audited ------------
CREATE FUNCTION hourvia_platform_audit_page(p_token_hash text, p_before_id bigint, p_limit integer) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  holder uuid := hourvia_platform_session_holder(p_token_hash);
  page jsonb;
  more boolean;
BEGIN
  IF holder IS NULL THEN
    RETURN NULL;
  END IF;
  IF p_limit IS NULL OR p_limit < 1 OR p_limit > 100 THEN
    RAISE EXCEPTION 'platform audit page size must be between 1 and 100' USING ERRCODE = '22023';
  END IF;
  IF p_before_id IS NOT NULL AND p_before_id < 1 THEN
    RAISE EXCEPTION 'platform audit cursor must be positive' USING ERRCODE = '22023';
  END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object(
             'id', x.id, 'occurred_at', x.occurred_at, 'event_type', x.event_type, 'outcome', x.outcome,
             'subject_is_holder', coalesce(x.subject_auth_user_id = holder, false),
             'subject_suffix', right(x.subject_auth_user_id::text, 4),
             'details', x.details) ORDER BY x.id DESC) FILTER (WHERE x.rn <= p_limit), '[]'::jsonb),
         count(*) > p_limit
    INTO page, more
  FROM (SELECT e.id, e.occurred_at, e.event_type, e.outcome, e.subject_auth_user_id, e.details,
               row_number() OVER (ORDER BY e.id DESC) AS rn
        FROM platform_audit_events e
        WHERE p_before_id IS NULL OR e.id < p_before_id
        ORDER BY e.id DESC
        LIMIT p_limit + 1) x;
  INSERT INTO platform_audit_events (event_type, outcome, subject_auth_user_id, details)
  VALUES ('platform_audit_read', 'success', holder,
          jsonb_build_object('source', 'application', 'before_id', p_before_id, 'limit', p_limit, 'returned', jsonb_array_length(page)));
  RETURN jsonb_build_object('events', page, 'has_more', more);
END
$$;

-- 4. Privileges: EXECUTE on the two entry points for the runtime role only ------------------------------------------
REVOKE ALL ON FUNCTION hourvia_platform_session_holder(text), hourvia_platform_overview(text),
  hourvia_platform_audit_page(text, bigint, integer) FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'netlifydb_readonly') THEN
    REVOKE ALL ON FUNCTION hourvia_platform_session_holder(text), hourvia_platform_overview(text),
      hourvia_platform_audit_page(text, bigint, integer) FROM netlifydb_readonly;
  END IF;
END
$$;
GRANT EXECUTE ON FUNCTION hourvia_platform_overview(text), hourvia_platform_audit_page(text, bigint, integer) TO hourvia_auth_runtime;

-- 5. Self-check: any surprise aborts this migration (and the deploy). ---------------------------------------------------
DO $$
DECLARE
  t text;
  f text;
BEGIN
  FOREACH f IN ARRAY ARRAY['hourvia_platform_overview(text)', 'hourvia_platform_audit_page(text,bigint,integer)'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_proc p WHERE p.oid = to_regprocedure('public.' || f) AND p.prosecdef
                     AND p.proconfig @> ARRAY['search_path=pg_catalog, public'] AND p.proowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)) THEN
      RAISE EXCEPTION 'self-check failed: % must be SECURITY DEFINER, owned by the migration role, with a pinned search_path', f;
    END IF;
    IF has_function_privilege('public', 'public.' || f, 'EXECUTE')
       OR (EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'netlifydb_readonly') AND has_function_privilege('netlifydb_readonly', 'public.' || f, 'EXECUTE'))
       OR NOT has_function_privilege('hourvia_auth_runtime', 'public.' || f, 'EXECUTE') THEN
      RAISE EXCEPTION 'self-check failed: EXECUTE on % must be limited to hourvia_auth_runtime', f;
    END IF;
  END LOOP;
  IF (SELECT prosecdef FROM pg_proc WHERE oid = 'public.hourvia_platform_session_holder(text)'::regprocedure)
     OR has_function_privilege('hourvia_auth_runtime', 'public.hourvia_platform_session_holder(text)', 'EXECUTE')
     OR has_function_privilege('public', 'public.hourvia_platform_session_holder(text)', 'EXECUTE') THEN
    RAISE EXCEPTION 'self-check failed: hourvia_platform_session_holder must stay internal';
  END IF;
  -- Table privileges are unchanged: the runtime still cannot write platform tables or read their history directly.
  FOREACH t IN ARRAY ARRAY['platform_super_admin_designation', 'platform_privileges', 'platform_audit_events'] LOOP
    IF has_table_privilege('hourvia_auth_runtime', 'public.' || t, 'INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
       OR has_any_column_privilege('hourvia_auth_runtime', 'public.' || t, 'INSERT, UPDATE, REFERENCES') THEN
      RAISE EXCEPTION 'self-check failed: hourvia_auth_runtime can write %', t;
    END IF;
  END LOOP;
  IF has_any_column_privilege('hourvia_auth_runtime', 'public.platform_super_admin_designation', 'SELECT')
     OR has_any_column_privilege('hourvia_auth_runtime', 'public.platform_audit_events', 'SELECT')
     OR has_column_privilege('hourvia_auth_runtime', 'public.platform_privileges', 'grant_approval_ref', 'SELECT') THEN
    RAISE EXCEPTION 'self-check failed: hourvia_auth_runtime gained direct read access to platform history';
  END IF;
END
$$;
