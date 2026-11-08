-- Hourvia Sprint 3.0.5: read-only M8 verification for an ISOLATED NETLIFY PREVIEW database branch (never production).
--
-- Use only as part of docs/m8-preview-rehearsal-runbook.md, after the platform has applied
-- 20261106120000_multi-organization-memberships.sql to the rehearsal preview branch during a branch deploy or Deploy
-- Preview. Apply nothing by hand. It is a single catalog-only SELECT inside a READ ONLY transaction that rolls back.
-- No member, invitation, session, audit or entitlement row is read, so it runs as netlifydb_readonly and returns no
-- personal data.
--
--   ro_sql "$RO_URL" "$(cat db/verification/sprint-3.0.5-m8-preview-readonly.sql)"
--     (runbook section 7 helper, with a netlifydb_readonly credential minted for the named rehearsal branch and
--     identity-checked by ro_url. Never run it through an unqualified `netlify database connect`: that command ignores
--     the Git branch and NETLIFY_DB_BRANCH, and reaches NETLIFY_DB_URL or a local, unmigrated database instead.)
--
-- Expected after M8:            'M8-0 M7 state' is false, and M8-1 ... M8-8 are all true.
-- Expected on M7, or after a rolled-back M8 (the atomic-rollback rehearsal): M8-0 is true, and M8-1 ... M8-8 are all false.
-- Any other combination is a partial or unexpected schema: stop and escalate.
BEGIN TRANSACTION READ ONLY;
SELECT c.check, c.ok FROM (
  SELECT 'M8-0 M7 state (no M8 object)' AS check,
         to_regclass('public.organization_seat_entitlements') IS NULL
         AND (SELECT count(*) FROM pg_proc WHERE pronamespace = 'public'::regnamespace AND proname LIKE 'hourvia\_%') = 16
         AND EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'organizations_single_tenant_m7') AS ok, 0 AS ord
  UNION ALL
  SELECT 'M8-1 entitlement table, RLS off everywhere',
         to_regclass('public.organization_seat_entitlements') IS NOT NULL
         AND NOT EXISTS (SELECT 1 FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relrowsecurity), 1
  UNION ALL
  SELECT 'M8-2 23 pinned hourvia_* functions',
         (SELECT count(*) = 23
                 AND bool_and(proconfig = ARRAY['search_path=pg_catalog, public, pg_temp'])
                 AND bool_and(prosecdef = (proname IN ('hourvia_platform_overview', 'hourvia_platform_audit_page')))
            FROM pg_proc WHERE pronamespace = 'public'::regnamespace AND proname LIKE 'hourvia\_%'), 2
  UNION ALL
  SELECT 'M8-3 26 guard, audit and revocation triggers enabled',
         (SELECT count(*) = 26 FROM pg_trigger WHERE NOT tgisinternal AND tgenabled = 'O' AND tgname IN (
            'workspace_members_guard', 'workspace_members_guard_insert', 'workspace_members_audit', 'workspace_invitations_guard',
            'auth_sessions_guard', 'auth_sessions_revocation_audit', 'auth_audit_events_no_update_delete', 'auth_audit_events_no_truncate',
            'platform_audit_events_no_update_delete', 'platform_audit_events_no_truncate', 'platform_privileges_guard',
            'platform_privileges_audit', 'platform_privileges_no_truncate', 'platform_super_admin_designation_guard',
            'platform_super_admin_designation_audit', 'platform_super_admin_designation_no_truncate',
            'organizations_guard', 'organizations_no_truncate', 'organization_seat_entitlements_guard',
            'organization_seat_entitlements_no_truncate', 'auth_sessions_guard_insert', 'auth_audit_events_guard_insert',
            'workspace_members_status_session_revocation', 'organizations_suspension_revocation', 'workspace_members_runtime_invitation',
            'workspace_invitations_guard_update'))
         AND EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'workspace_invitations_guard_update' AND tgtype = 19 AND tgqual IS NULL AND tgattr::text = '')
         AND EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'organizations_suspension_revocation' AND tgtype = 17)
         AND EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'auth_sessions_guard_insert' AND tgtype = 7), 3
  UNION ALL
  SELECT 'M8-4 new constraints validated, single-organization constraints removed',
         (SELECT count(*) = 17 FROM pg_constraint WHERE convalidated AND conname IN (
            'organizations_thrivesource_identity', 'organizations_internal_is_thrivesource', 'organizations_updated_after_creation',
            'organizations_id_slug_key', 'organizations_id_kind_key', 'workspace_members_organization_workspace_fk',
            'workspace_invitations_organization_workspace_fk', 'manager_assignments_organization_workspace_fk',
            'auth_audit_events_organization_workspace_fk', 'workspace_members_organization_auth_user_key', 'workspace_members_status_check',
            'workspace_members_suspended_was_active', 'organization_seat_entitlements_organization_fk',
            'organization_seat_entitlements_limit_matches_plan', 'organization_seat_entitlements_internal_unlimited',
            'organization_seat_entitlements_internal_no_billing', 'organization_seat_entitlements_updated_after_creation'))
         AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname IN ('organizations_single_tenant_m7', 'workspace_members_auth_user_id_key',
            'workspace_members_workspace_id_check', 'workspace_invitations_workspace_id_check', 'manager_assignments_workspace_id_check',
            'auth_audit_events_workspace_id_check')), 4
  UNION ALL
  SELECT 'M8-5 both new indexes in reviewed form',
         (SELECT count(*) = 2 FROM pg_index x JOIN pg_class i ON i.oid = x.indexrelid JOIN pg_am am ON am.oid = i.relam
           WHERE i.relnamespace = 'public'::regnamespace AND am.amname = 'btree' AND x.indisvalid AND x.indisready AND NOT x.indisunique
             AND ((i.relname = 'workspace_members_auth_user' AND x.indrelid = to_regclass('public.workspace_members')
                   AND pg_get_indexdef(i.oid, 1, false) = 'auth_user_id' AND x.indnatts = 1
                   AND pg_get_expr(x.indpred, x.indrelid) = '(auth_user_id IS NOT NULL)')
               OR (i.relname = 'workspace_invitations_organization_pending' AND x.indrelid = to_regclass('public.workspace_invitations')
                   AND x.indnatts = 2 AND pg_get_indexdef(i.oid, 1, false) = 'organization_id' AND pg_get_indexdef(i.oid, 2, false) = 'expires_at'
                   AND pg_get_expr(x.indpred, x.indrelid) = '(status = ''pending''::text)'))), 5
  UNION ALL
  SELECT 'M8-6 runtime grants',
         to_regclass('public.organization_seat_entitlements') IS NOT NULL
         AND (SELECT bool_and(has_column_privilege('hourvia_auth_runtime', 'public.' || t, 'organization_id', 'INSERT') = (t <> 'manager_assignments')
                              AND NOT has_column_privilege('hourvia_auth_runtime', 'public.' || t, 'organization_id', 'UPDATE'))
                FROM unnest(ARRAY['workspace_members', 'workspace_invitations', 'manager_assignments', 'auth_sessions', 'auth_audit_events']) t)
         AND (SELECT array_agg(a.attname::text ORDER BY a.attname) FROM pg_attribute a
               WHERE a.attrelid = 'public.workspace_invitations'::regclass AND a.attnum > 0 AND NOT a.attisdropped
                 AND has_column_privilege('hourvia_auth_runtime', a.attrelid, a.attnum, 'UPDATE')) = ARRAY['accepted_at', 'status']
         AND (SELECT array_agg(a.attname::text ORDER BY a.attname) FROM pg_attribute a
               WHERE a.attrelid = to_regclass('public.organization_seat_entitlements') AND a.attnum > 0 AND NOT a.attisdropped
                 AND has_column_privilege('hourvia_auth_runtime', a.attrelid, a.attnum, 'SELECT'))
             = ARRAY['billing_expires_at', 'organization_id', 'plan', 'seat_limit']
         AND NOT has_any_column_privilege('hourvia_auth_runtime', to_regclass('public.organization_seat_entitlements'), 'INSERT, UPDATE, REFERENCES')
         AND NOT has_any_column_privilege('hourvia_auth_runtime', 'public.organizations'::regclass, 'INSERT, UPDATE, REFERENCES'), 6
  UNION ALL
  SELECT 'M8-7 PUBLIC and netlifydb_readonly: no entitlement access, no hourvia_* EXECUTE',
         to_regclass('public.organization_seat_entitlements') IS NOT NULL
         AND NOT EXISTS (SELECT 1 FROM unnest(ARRAY['public', 'netlifydb_readonly']) g
                          WHERE EXISTS (SELECT 1 FROM pg_roles WHERE g = 'public' OR rolname = g)
                            AND (has_table_privilege(g, to_regclass('public.organization_seat_entitlements'), 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
                                 OR has_any_column_privilege(g, to_regclass('public.organization_seat_entitlements'), 'SELECT, INSERT, UPDATE, REFERENCES')
                                 OR EXISTS (SELECT 1 FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND p.proname LIKE 'hourvia\_%'
                                             AND has_function_privilege(g, p.oid, 'EXECUTE')))), 7
  UNION ALL
  SELECT 'M8-8 session and organization lock pins present',
         to_regprocedure('public.hourvia_guard_session_insert()') IS NOT NULL
         AND pg_get_functiondef(to_regprocedure('public.hourvia_guard_session_insert()')) LIKE '%pg\_advisory\_xact\_lock\_shared(hashtextextended(''hourvia\_sessions:'' || NEW.organization\_id::text, 0));%'
         AND to_regprocedure('public.hourvia_revoke_organization_sessions()') IS NOT NULL
         AND pg_get_functiondef(to_regprocedure('public.hourvia_revoke_organization_sessions()')) LIKE '%PERFORM pg\_advisory\_xact\_lock(hashtextextended(''hourvia\_sessions:'' || NEW.id::text, 0));%'
         AND to_regprocedure('public.hourvia_guard_invitation_update()') IS NOT NULL, 8
) c ORDER BY c.ord;
ROLLBACK;
