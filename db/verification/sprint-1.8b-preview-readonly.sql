-- Hourvia Sprint 1.8C — read-only verification of 20261104160000 (pg_temp pinned last) on a database branch.
--
-- SAFE TO RUN ON A BRANCH COPIED FROM PRODUCTION: catalog reads only, inside a READ ONLY transaction that is rolled back.
-- It selects no application rows (no emails, UIDs, session hashes or audit details) and calls no hourvia_* function.
-- It performs NO shadowing attack: no temp table, no SET ROLE, no write. Run it as netlifydb_readonly or the owner.
--
--   netlify database connect --query "$(cat db/verification/sprint-1.8b-preview-readonly.sql)"
--
-- Every check returns one row: check, pass (boolean), detail. All rows must have pass = true.

BEGIN TRANSACTION READ ONLY;

WITH expected(sig, secdef, runtime_exec) AS (VALUES
  ('hourvia_audit_member_change()', false, false),
  ('hourvia_audit_platform_change()', false, false),
  ('hourvia_audit_session_revocation()', false, false),
  ('hourvia_guard_invitation_insert()', false, false),
  ('hourvia_guard_member_insert()', false, false),
  ('hourvia_guard_member_update()', false, false),
  ('hourvia_guard_platform_designation()', false, false),
  ('hourvia_guard_platform_privilege()', false, false),
  ('hourvia_guard_session_update()', false, false),
  ('hourvia_is_verified_platform_candidate(uuid)', false, false),
  ('hourvia_member_authority(uuid,text)', false, true),
  ('hourvia_platform_audit_page(text,bigint,integer)', true, true),
  ('hourvia_platform_overview(text)', true, true),
  ('hourvia_platform_session_holder(text)', false, false),
  ('hourvia_reject_audit_mutation()', false, false)
),
actual AS (
  SELECT replace(p.proname || '(' || oidvectortypes(p.proargtypes) || ')', ', ', ',') AS sig,
         p.oid::regprocedure AS f, p.proconfig, p.prosecdef, pg_get_userbyid(p.proowner) AS owner
  FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND p.proname LIKE 'hourvia\_%'
),
joined AS (
  SELECT coalesce(a.sig, e.sig) AS sig, a.f, a.proconfig, a.prosecdef, a.owner, e.secdef, e.runtime_exec,
         (a.sig IS NOT NULL) AS present, (e.sig IS NOT NULL) AS expected
  FROM actual a FULL JOIN expected e ON e.sig = a.sig
)
-- 1. Exactly the 15 reviewed functions exist.
SELECT 'V1 exactly 15 reviewed hourvia_* functions' AS "check",
       bool_and(present AND expected) AND count(*) = 15 AS pass,
       'found=' || count(*) FILTER (WHERE present) || ' missing=' || coalesce(string_agg(sig, ' ') FILTER (WHERE NOT present), '-')
         || ' unexpected=' || coalesce(string_agg(sig, ' ') FILTER (WHERE NOT expected), '-') AS detail
FROM joined
UNION ALL
-- 2. Every function has exactly the hardened search_path, pg_temp last.
SELECT 'V2 search_path=pg_catalog, public, pg_temp on all 15',
       bool_and(proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, public, pg_temp']) AND count(*) = 15,
       coalesce(string_agg(sig || '=' || coalesce(array_to_string(proconfig, ';'), 'NULL'), ' ')
         FILTER (WHERE proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, public, pg_temp']), 'all hardened')
FROM joined WHERE present
UNION ALL
-- 3. Ownership unchanged: all owned by the migration owner role (netlifydb_owner on Netlify Database).
SELECT 'V3 all owned by netlifydb_owner',
       bool_and(owner = 'netlifydb_owner'),
       string_agg(DISTINCT owner, ',')
FROM joined WHERE present
UNION ALL
-- 4. SECURITY DEFINER only on the two platform read functions.
SELECT 'V4 SECURITY DEFINER only on platform overview/audit_page',
       bool_and(prosecdef = secdef),
       coalesce(string_agg(sig, ' ') FILTER (WHERE prosecdef <> secdef), 'as reviewed')
FROM joined WHERE present AND expected
UNION ALL
-- 5. EXECUTE unchanged: never PUBLIC or netlifydb_readonly; runtime only on its three entry points.
SELECT 'V5 EXECUTE grants unchanged',
       bool_and(NOT has_function_privilege('public', f, 'EXECUTE')
                AND NOT (EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'netlifydb_readonly')
                         AND has_function_privilege('netlifydb_readonly', f, 'EXECUTE'))
                AND has_function_privilege('hourvia_auth_runtime', f, 'EXECUTE') = runtime_exec),
       coalesce(string_agg(sig, ' ') FILTER (WHERE has_function_privilege('public', f, 'EXECUTE')
                OR has_function_privilege('hourvia_auth_runtime', f, 'EXECUTE') <> runtime_exec), 'as reviewed')
FROM joined WHERE present AND expected
UNION ALL
-- 6. hourvia_auth_runtime cannot CREATE in public or create schemas; keeps USAGE.
SELECT 'V6 hourvia_auth_runtime: no CREATE on public/database, USAGE on public',
       NOT has_schema_privilege('hourvia_auth_runtime', 'public', 'CREATE')
         AND NOT has_database_privilege('hourvia_auth_runtime', current_database(), 'CREATE')
         AND has_schema_privilege('hourvia_auth_runtime', 'public', 'USAGE'),
       'schema_create=' || has_schema_privilege('hourvia_auth_runtime', 'public', 'CREATE')
         || ' db_create=' || has_database_privilege('hourvia_auth_runtime', current_database(), 'CREATE')
         || ' usage=' || has_schema_privilege('hourvia_auth_runtime', 'public', 'USAGE')
UNION ALL
-- 7. The runtime role is still NOLOGIN-free of new attributes (informational: no custom LOGIN role was created).
SELECT 'V7 no new LOGIN role named hourvia_*',
       NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname LIKE 'hourvia\_%' AND rolcanlogin),
       coalesce((SELECT string_agg(rolname || ':login=' || rolcanlogin, ',') FROM pg_roles WHERE rolname LIKE 'hourvia\_%'), 'none')
UNION ALL
-- 8. Six applied migrations, in order. Netlify's migration ledger lives in a platform schema; locate it by catalog
--    so this check does not depend on a private table name. Returns pass = NULL if no ledger is visible to this role
--    (then use `netlify database status`, which lists applied migrations).
SELECT 'V8 ledger table candidates (use netlify database status for the six versions)',
       NULL::boolean,
       coalesce((SELECT string_agg(table_schema || '.' || table_name, ',') FROM information_schema.tables
                 WHERE table_name ILIKE '%migration%'), 'no ledger visible to this role');

ROLLBACK;
