-- Hourvia Sprint 1.8B — pin pg_temp last in every hourvia_* function search_path (forward-only; fixes audit finding H-1)
--
-- Finding H-1 (Sprint 1.8A): every hourvia_* function used SET search_path = pg_catalog, public. When pg_temp is not
-- listed, PostgreSQL searches the session's temporary schema FIRST for relation names, and PUBLIC holds TEMPORARY on the
-- database (datacl =Tc/netlifydb_owner on Netlify Database). A caller able to run SQL as hourvia_auth_runtime could
-- therefore shadow auth_sessions, workspace_members, platform_super_admin_designation or platform_privileges with temp
-- tables and (a) read the platform audit through the SECURITY DEFINER platform functions without a valid session, and
-- (b) pass the membership guard triggers (hourvia_member_authority) to promote a member to Administrator.
--
-- Fix: ALTER FUNCTION … SET search_path = pg_catalog, public, pg_temp on every hourvia_* function. Functions and
-- operators are never resolved from pg_temp, and with pg_temp last, relations resolve to public first.
--   * Signatures, bodies, volatility, SECURITY DEFINER flags, ownership and EXECUTE grants are unchanged
--     (ALTER FUNCTION … SET changes only proconfig). No privilege is granted or revoked. No row is changed.
--   * The function list is explicit. Any unexpected hourvia_* function aborts the migration, so nothing is hardened or
--     skipped silently.
-- The applied migrations 20261103170000 … 20261104150000 stay byte-identical; this migration only alters their functions.

-- 0. Preconditions: exactly the expected hourvia_* functions exist ---------------------------------------------------
DO $$
DECLARE
  expected text[] := ARRAY[
    'hourvia_audit_member_change()', 'hourvia_audit_platform_change()', 'hourvia_audit_session_revocation()',
    'hourvia_guard_invitation_insert()', 'hourvia_guard_member_insert()', 'hourvia_guard_member_update()',
    'hourvia_guard_platform_designation()', 'hourvia_guard_platform_privilege()', 'hourvia_guard_session_update()',
    'hourvia_is_verified_platform_candidate(uuid)', 'hourvia_member_authority(uuid,text)',
    'hourvia_platform_audit_page(text,bigint,integer)', 'hourvia_platform_overview(text)',
    'hourvia_platform_session_holder(text)', 'hourvia_reject_audit_mutation()'];
  actual text[];
BEGIN
  -- Argument-type signatures without spaces ("uuid, text" → "uuid,text"), sorted, for an exact comparison.
  SELECT coalesce(array_agg(sig ORDER BY sig), '{}') INTO actual
  FROM (SELECT replace(p.proname || '(' || oidvectortypes(p.proargtypes) || ')', ', ', ',') AS sig
        FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND p.proname LIKE 'hourvia\_%') f;
  IF actual IS DISTINCT FROM (SELECT array_agg(e ORDER BY e) FROM unnest(expected) e) THEN
    RAISE EXCEPTION 'unexpected hourvia_* functions: found %, expected %; apply 20261104150000 first and review any new function', actual, expected;
  END IF;
END
$$;

-- 1. Pin pg_temp last --------------------------------------------------------------------------------------------------
ALTER FUNCTION public.hourvia_audit_member_change()                       SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.hourvia_audit_platform_change()                     SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.hourvia_audit_session_revocation()                  SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.hourvia_guard_invitation_insert()                   SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.hourvia_guard_member_insert()                       SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.hourvia_guard_member_update()                       SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.hourvia_guard_platform_designation()                SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.hourvia_guard_platform_privilege()                  SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.hourvia_guard_session_update()                      SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.hourvia_is_verified_platform_candidate(uuid)        SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.hourvia_member_authority(uuid, text)                SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.hourvia_platform_audit_page(text, bigint, integer)  SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.hourvia_platform_overview(text)                     SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.hourvia_platform_session_holder(text)               SET search_path = pg_catalog, public, pg_temp;
-- Uses no relation; pinned for consistency so every hourvia_* function has the same, reviewable configuration.
ALTER FUNCTION public.hourvia_reject_audit_mutation()                     SET search_path = pg_catalog, public, pg_temp;

-- 2. Self-check: any surprise aborts this migration (and the deploy). ---------------------------------------------------
DO $$
DECLARE
  r record;
BEGIN
  FOR r IN SELECT p.oid::regprocedure AS f, p.proconfig, p.prosecdef, p.proname, pg_get_userbyid(p.proowner) AS owner, p.proacl
           FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND p.proname LIKE 'hourvia\_%' LOOP
    -- Exactly one setting: the hardened search_path with pg_temp last.
    IF r.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, public, pg_temp'] THEN
      RAISE EXCEPTION 'self-check failed: % has search_path config %', r.f, r.proconfig;
    END IF;
    -- SECURITY DEFINER stays limited to the two platform read entry points.
    IF r.prosecdef <> (r.proname IN ('hourvia_platform_overview', 'hourvia_platform_audit_page')) THEN
      RAISE EXCEPTION 'self-check failed: unexpected SECURITY DEFINER setting on %', r.f;
    END IF;
    IF r.owner <> current_user THEN
      RAISE EXCEPTION 'self-check failed: % is owned by %, not the migration role', r.f, r.owner;
    END IF;
    -- EXECUTE unchanged: never PUBLIC or netlifydb_readonly; the runtime only on its three documented entry points.
    IF has_function_privilege('public', r.f, 'EXECUTE')
       OR (EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'netlifydb_readonly') AND has_function_privilege('netlifydb_readonly', r.f, 'EXECUTE'))
       OR has_function_privilege('hourvia_auth_runtime', r.f, 'EXECUTE')
          <> (r.proname IN ('hourvia_member_authority', 'hourvia_platform_overview', 'hourvia_platform_audit_page')) THEN
      RAISE EXCEPTION 'self-check failed: EXECUTE privileges on % changed', r.f;
    END IF;
  END LOOP;
  -- The runtime cannot create objects that could shadow functions, operators or relations outside pg_temp.
  IF has_schema_privilege('hourvia_auth_runtime', 'public', 'CREATE')
     OR has_database_privilege('hourvia_auth_runtime', current_database(), 'CREATE') THEN
    RAISE EXCEPTION 'self-check failed: hourvia_auth_runtime can CREATE in public or create schemas';
  END IF;
  IF NOT has_schema_privilege('hourvia_auth_runtime', 'public', 'USAGE') THEN
    RAISE EXCEPTION 'self-check failed: hourvia_auth_runtime lost USAGE on public';
  END IF;
END
$$;
