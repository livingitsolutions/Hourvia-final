-- Hourvia Sprint 2.0B: read-only M7 verification for an ISOLATED PREVIEW database branch (never production).
--
-- Run only after the platform has applied 20261104170000_organizations-expand.sql to the preview branch during a deploy
-- preview. Apply nothing by hand. Every statement below reads the catalog or returns aggregate counts. Nothing reads
-- member, invitation, session or audit content, so no personal data is returned. The transaction is READ ONLY and
-- rolls back.
--
--   netlify database status   (confirm the target is the preview branch and M7 is listed as applied)
--   psql "<preview branch URL>" -v ON_ERROR_STOP=1 -f db/verification/sprint-2.0b-preview-readonly.sql
--
-- Expected: every row has ok = true.
BEGIN TRANSACTION READ ONLY;

-- M7-1 exactly one organization, the active internal ThriveSource row with the stable UUID.
SELECT 'M7-1 organizations' AS check,
       (SELECT count(*) FROM organizations) = 1
       AND EXISTS (SELECT 1 FROM organizations WHERE id = '5adff49b-11d5-4b45-bb4f-2f76cfcca0c6' AND slug = 'thrivesource'
                   AND kind = 'internal' AND status = 'active') AS ok;

-- M7-2 organization_id is NOT NULL with the ThriveSource default on all five tenant tables.
SELECT 'M7-2 tenant columns' AS check, count(*) = 5 AS ok
FROM information_schema.columns
WHERE table_schema = 'public' AND column_name = 'organization_id' AND is_nullable = 'NO'
  AND column_default = '''5adff49b-11d5-4b45-bb4f-2f76cfcca0c6''::uuid'
  AND table_name IN ('workspace_members', 'workspace_invitations', 'manager_assignments', 'auth_sessions', 'auth_audit_events');

-- M7-3 aggregate only: no tenant row outside ThriveSource.
SELECT 'M7-3 all rows ThriveSource' AS check,
       NOT EXISTS (SELECT 1 FROM workspace_members WHERE organization_id <> '5adff49b-11d5-4b45-bb4f-2f76cfcca0c6')
       AND NOT EXISTS (SELECT 1 FROM workspace_invitations WHERE organization_id <> '5adff49b-11d5-4b45-bb4f-2f76cfcca0c6')
       AND NOT EXISTS (SELECT 1 FROM manager_assignments WHERE organization_id <> '5adff49b-11d5-4b45-bb4f-2f76cfcca0c6')
       AND NOT EXISTS (SELECT 1 FROM auth_sessions WHERE organization_id <> '5adff49b-11d5-4b45-bb4f-2f76cfcca0c6')
       AND NOT EXISTS (SELECT 1 FROM auth_audit_events WHERE organization_id <> '5adff49b-11d5-4b45-bb4f-2f76cfcca0c6') AS ok;

-- M7-4 all 22 organization constraints exist and are validated; the single-organization CHECKs are still present.
SELECT 'M7-4 constraints' AS check,
       (SELECT count(*) FROM pg_constraint WHERE convalidated AND connamespace = 'public'::regnamespace
          AND (conname LIKE '%\_org\_fk' OR conname LIKE '%\_organization\_fk' OR conname LIKE '%\_legacy\_organization'
               OR conname IN ('workspace_members_organization_member_key', 'organizations_single_tenant_m7'))) = 22
       AND (SELECT count(*) FROM pg_constraint WHERE conname IN ('workspace_members_workspace_id_check', 'workspace_invitations_workspace_id_check',
              'manager_assignments_workspace_id_check', 'auth_audit_events_workspace_id_check', 'workspace_members_auth_user_id_key')) = 5 AS ok;

-- M7-5 RLS still disabled everywhere.
SELECT 'M7-5 RLS off' AS check, NOT EXISTS (SELECT 1 FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relrowsecurity) AS ok;

-- M7-6 16 hourvia_* functions, all pinned with pg_temp last; SECURITY DEFINER only on the two platform readers.
SELECT 'M7-6 functions' AS check,
       count(*) = 16
       AND bool_and(proconfig = ARRAY['search_path=pg_catalog, public, pg_temp'])
       AND bool_and(prosecdef = (proname IN ('hourvia_platform_overview', 'hourvia_platform_audit_page'))) AS ok
FROM pg_proc WHERE pronamespace = 'public'::regnamespace AND proname LIKE 'hourvia\_%';

-- M7-7 runtime grants on organizations: SELECT on 5 columns only; no organization_id writes anywhere.
SELECT 'M7-7 runtime grants' AS check,
       NOT has_table_privilege('hourvia_auth_runtime', 'public.organizations', 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE')
       AND has_column_privilege('hourvia_auth_runtime', 'public.organizations', 'status', 'SELECT')
       AND NOT has_column_privilege('hourvia_auth_runtime', 'public.organizations', 'created_by_auth_user_id', 'SELECT')
       AND NOT has_any_column_privilege('hourvia_auth_runtime', 'public.organizations', 'INSERT, UPDATE')
       AND NOT EXISTS (SELECT 1 FROM unnest(ARRAY['workspace_members', 'workspace_invitations', 'manager_assignments', 'auth_sessions', 'auth_audit_events']) t
                       WHERE has_column_privilege('hourvia_auth_runtime', 'public.' || t, 'organization_id', 'INSERT')
                          OR has_column_privilege('hourvia_auth_runtime', 'public.' || t, 'organization_id', 'UPDATE'))
       AND NOT has_table_privilege('netlifydb_readonly', 'public.organizations', 'SELECT')
       AND NOT has_any_column_privilege('netlifydb_readonly', 'public.organizations', 'SELECT') AS ok;

-- M7-8 guard and append-only triggers enabled (18).
SELECT 'M7-8 triggers' AS check, count(*) = 18 AS ok FROM pg_trigger
WHERE NOT tgisinternal AND tgenabled = 'O' AND tgname IN (
  'workspace_members_guard', 'workspace_members_guard_insert', 'workspace_members_audit', 'workspace_invitations_guard',
  'auth_sessions_guard', 'auth_sessions_revocation_audit', 'auth_audit_events_no_update_delete', 'auth_audit_events_no_truncate',
  'platform_audit_events_no_update_delete', 'platform_audit_events_no_truncate', 'platform_privileges_guard', 'platform_privileges_audit',
  'platform_privileges_no_truncate', 'platform_super_admin_designation_guard', 'platform_super_admin_designation_audit',
  'platform_super_admin_designation_no_truncate', 'organizations_guard', 'organizations_no_truncate');

ROLLBACK;
