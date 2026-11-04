-- Hourvia Sprint 2.0B: M7 organization foundation (expand only; forward-only; 20261103170000 … 20261104160000 unchanged)
--
-- What this migration does:
--   * Creates `organizations` and seeds the existing tenant ThriveSource as an active internal organization with the
--     stable UUID 5adff49b-11d5-4b45-bb4f-2f76cfcca0c6 (slug 'thrivesource'). The UUID is permanent. It is also recorded
--     in src/domain/organization.ts and docs/architecture.md and must never change.
--   * Adds organization_id uuid NOT NULL DEFAULT '<ThriveSource>' to workspace_members, workspace_invitations,
--     manager_assignments, auth_sessions and auth_audit_events. A constant default makes this a catalog-only change
--     (PostgreSQL 11+): no table rewrite and no UPDATE, so no row trigger fires, and no audit row is touched.
--   * Adds organization foreign keys plus COMPOSITE membership foreign keys (organization_id, member) so a child row
--     can never reference a member of another organization. All are added NOT VALID and then VALIDATEd (a read-only scan).
--   * Adds a legacy bridge CHECK on every table that carries workspace_id: 'thrivesource' rows must belong to ThriveSource.
--
-- What it deliberately does NOT do (Sprint 2.0C–2.0E):
--   * No existing constraint is dropped or relaxed. CHECK (workspace_id = 'thrivesource'), the global
--     auth_user_id UNIQUE, the role CHECKs, guards and audit triggers all stay. A second organization is refused by
--     organizations_single_tenant_m7.
--   * No RLS, no new role and no change to any existing function or trigger.
--   * No runtime write access to organizations or to any organization_id column. Runtime INSERTs keep their
--     column lists, so organization_id always comes from the default. The only new runtime grant is
--     SELECT (id, slug, name, kind, status) ON organizations, which the session-resolution query uses.
--
-- Compatibility: the deployed application (799f042) never names organization_id, so all its INSERT, UPDATE and SELECT
-- statements keep working unchanged. Rolling the application back after M7 is safe while the defaults remain.

-- 0. Preconditions ---------------------------------------------------------------------------------------------------
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
  t text;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hourvia_auth_runtime') THEN
    RAISE EXCEPTION 'hourvia_auth_runtime does not exist; apply 20261103170100 first';
  END IF;
  FOREACH t IN ARRAY ARRAY['workspace_members', 'manager_assignments', 'workspace_invitations', 'auth_sessions', 'auth_audit_events',
                           'auth_rate_limits', 'platform_privileges', 'platform_super_admin_designation', 'platform_audit_events'] LOOP
    IF to_regclass('public.' || t) IS NULL THEN
      RAISE EXCEPTION 'table % is missing; apply the six earlier migrations first', t;
    END IF;
  END LOOP;
  IF to_regclass('public.organizations') IS NOT NULL THEN
    RAISE EXCEPTION 'organizations already exists; M7 must be applied exactly once to a pre-M7 database';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_attribute WHERE attname = 'organization_id' AND NOT attisdropped AND attrelid IN (
       'public.workspace_members'::regclass, 'public.workspace_invitations'::regclass, 'public.manager_assignments'::regclass,
       'public.auth_sessions'::regclass, 'public.auth_audit_events'::regclass)) THEN
    RAISE EXCEPTION 'an organization_id column already exists; refusing to continue';
  END IF;
  -- 20261104160000 pinned pg_temp in exactly these functions. M7 adds one more, so the set must be exact here.
  SELECT coalesce(array_agg(sig ORDER BY sig), '{}') INTO actual
  FROM (SELECT replace(p.proname || '(' || oidvectortypes(p.proargtypes) || ')', ', ', ',') AS sig
        FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND p.proname LIKE 'hourvia\_%') f;
  IF actual IS DISTINCT FROM (SELECT array_agg(e ORDER BY e) FROM unnest(expected) e) THEN
    RAISE EXCEPTION 'unexpected hourvia_* functions before M7: found %', actual;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND p.proname LIKE 'hourvia\_%'
             AND p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, public, pg_temp']) THEN
    RAISE EXCEPTION 'a hourvia_* function lacks the pinned search_path; apply 20261104160000 first';
  END IF;
  -- Defensive: the CHECKs already guarantee this, but M7 must never attach a foreign tenant's row to ThriveSource.
  IF EXISTS (SELECT 1 FROM workspace_members WHERE workspace_id <> 'thrivesource')
     OR EXISTS (SELECT 1 FROM workspace_invitations WHERE workspace_id <> 'thrivesource')
     OR EXISTS (SELECT 1 FROM manager_assignments WHERE workspace_id <> 'thrivesource')
     OR EXISTS (SELECT 1 FROM auth_audit_events WHERE workspace_id <> 'thrivesource') THEN
    RAISE EXCEPTION 'a row belongs to a workspace other than thrivesource; stop and review';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relrowsecurity) THEN
    RAISE EXCEPTION 'row-level security is unexpectedly enabled on a public table; stop and review';
  END IF;
END
$$;

-- Preservation baseline: row counts and a content fingerprint of every pre-existing column, taken inside this
-- migration's transaction and compared again by the self-check (section 7). Dropped explicitly at the end.
CREATE TEMPORARY TABLE hourvia_m7_baseline AS
SELECT 'workspace_members' AS t, count(*) AS n,
       md5(coalesce(string_agg(md5(row(id, workspace_id, auth_user_id, email, display_name, role, status, approval_authorized, created_at,
           activated_at, disabled_at, disabled_by, role_changed_by, role_changed_at)::text), '' ORDER BY id), '')) AS h FROM public.workspace_members
UNION ALL SELECT 'workspace_invitations', count(*),
       md5(coalesce(string_agg(md5(row(id, workspace_id, member_id, email, role, status, invited_by_member_id, created_at, expires_at, accepted_at)::text), '' ORDER BY id), ''))
       FROM public.workspace_invitations
UNION ALL SELECT 'manager_assignments', count(*),
       md5(coalesce(string_agg(md5(row(workspace_id, manager_member_id, contractor_member_id, created_at, created_by)::text), '' ORDER BY manager_member_id, contractor_member_id), ''))
       FROM public.manager_assignments
UNION ALL SELECT 'auth_sessions', count(*),
       md5(coalesce(string_agg(md5(row(id, token_hash, member_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at, revoked_reason, revoked_by_member_id)::text), '' ORDER BY id), ''))
       FROM public.auth_sessions
UNION ALL SELECT 'auth_audit_events', count(*),
       md5(coalesce(string_agg(md5(row(id, workspace_id, occurred_at, event_type, outcome, actor_member_id, subject_member_id, email_hmac, ip_hmac, details)::text), '' ORDER BY id), ''))
       FROM public.auth_audit_events
UNION ALL SELECT 'platform_audit_events', count(*),
       md5(coalesce(string_agg(md5(row(id, occurred_at, event_type, outcome, subject_auth_user_id, details)::text), '' ORDER BY id), ''))
       FROM public.platform_audit_events;

-- 1. Organizations ----------------------------------------------------------------------------------------------------
CREATE TABLE organizations (
  id                      uuid PRIMARY KEY,
  slug                    text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9](?:[a-z0-9-]{1,46}[a-z0-9])$'),
  name                    text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 120 AND name = btrim(name)),
  kind                    text NOT NULL CHECK (kind IN ('internal', 'customer')),
  status                  text NOT NULL CHECK (status IN ('provisioning', 'active', 'suspended', 'closed')),
  created_at              timestamptz NOT NULL DEFAULT now(),
  created_by_auth_user_id uuid,
  suspended_at            timestamptz,
  suspended_reason        text CHECK (suspended_reason ~ '^[a-z_]{1,64}$'),
  CONSTRAINT organizations_suspension_metadata CHECK ((status = 'suspended') = (suspended_at IS NOT NULL)),
  CONSTRAINT organizations_suspension_reason CHECK ((suspended_at IS NULL) = (suspended_reason IS NULL)),
  CONSTRAINT organizations_suspended_after_creation CHECK (suspended_at IS NULL OR suspended_at >= created_at),
  -- Sprint 2.0B is single-tenant: only ThriveSource may exist. Sprint 2.0C drops this in a reviewed migration.
  CONSTRAINT organizations_single_tenant_m7 CHECK (id = '5adff49b-11d5-4b45-bb4f-2f76cfcca0c6'::uuid AND slug = 'thrivesource')
);

-- created_by_auth_user_id is NULL: ThriveSource predates organization provisioning (seeded by migration, not by a person).
INSERT INTO organizations (id, slug, name, kind, status, created_at, created_by_auth_user_id)
VALUES ('5adff49b-11d5-4b45-bb4f-2f76cfcca0c6', 'thrivesource', 'ThriveSource', 'internal', 'active',
        coalesce((SELECT min(created_at) FROM workspace_members), now()), NULL);

-- Identity columns are immutable and organizations are never deleted or truncated, for every role including the owner.
-- Status and suspension changes stay possible for reviewed operator SQL (and later, audited platform provisioning).
CREATE FUNCTION hourvia_guard_organization() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
  IF TG_LEVEL = 'STATEMENT' OR TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'organizations cannot be deleted or truncated; suspend or close them instead';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id OR NEW.slug IS DISTINCT FROM OLD.slug OR NEW.kind IS DISTINCT FROM OLD.kind
     OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.created_by_auth_user_id IS DISTINCT FROM OLD.created_by_auth_user_id THEN
    RAISE EXCEPTION 'organizations identity columns are immutable';
  END IF;
  IF current_user = 'hourvia_auth_runtime' THEN
    RAISE EXCEPTION 'the application cannot change organizations';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER organizations_guard BEFORE UPDATE OR DELETE ON organizations
  FOR EACH ROW EXECUTE FUNCTION hourvia_guard_organization();
CREATE TRIGGER organizations_no_truncate BEFORE TRUNCATE ON organizations
  FOR EACH STATEMENT EXECUTE FUNCTION hourvia_guard_organization();

-- 2. organization_id on the tenant tables (catalog-only: constant default, no rewrite, no row trigger) -------------------
ALTER TABLE workspace_members     ADD COLUMN organization_id uuid NOT NULL DEFAULT '5adff49b-11d5-4b45-bb4f-2f76cfcca0c6'::uuid;
ALTER TABLE workspace_invitations ADD COLUMN organization_id uuid NOT NULL DEFAULT '5adff49b-11d5-4b45-bb4f-2f76cfcca0c6'::uuid;
ALTER TABLE manager_assignments   ADD COLUMN organization_id uuid NOT NULL DEFAULT '5adff49b-11d5-4b45-bb4f-2f76cfcca0c6'::uuid;
ALTER TABLE auth_sessions         ADD COLUMN organization_id uuid NOT NULL DEFAULT '5adff49b-11d5-4b45-bb4f-2f76cfcca0c6'::uuid;
ALTER TABLE auth_audit_events     ADD COLUMN organization_id uuid NOT NULL DEFAULT '5adff49b-11d5-4b45-bb4f-2f76cfcca0c6'::uuid;

-- 3. Organization foreign keys ---------------------------------------------------------------------------------------
ALTER TABLE workspace_members     ADD CONSTRAINT workspace_members_organization_fk     FOREIGN KEY (organization_id) REFERENCES organizations(id) NOT VALID;
ALTER TABLE workspace_invitations ADD CONSTRAINT workspace_invitations_organization_fk FOREIGN KEY (organization_id) REFERENCES organizations(id) NOT VALID;
ALTER TABLE manager_assignments   ADD CONSTRAINT manager_assignments_organization_fk   FOREIGN KEY (organization_id) REFERENCES organizations(id) NOT VALID;
ALTER TABLE auth_sessions         ADD CONSTRAINT auth_sessions_organization_fk         FOREIGN KEY (organization_id) REFERENCES organizations(id) NOT VALID;
ALTER TABLE auth_audit_events     ADD CONSTRAINT auth_audit_events_organization_fk     FOREIGN KEY (organization_id) REFERENCES organizations(id) NOT VALID;

-- 4. Composite membership foreign keys: a child row and the member it references are always in the same organization.
-- The existing single-column foreign keys stay. MATCH SIMPLE: a NULL member column (e.g. a NULL audit actor) is allowed.
ALTER TABLE workspace_members ADD CONSTRAINT workspace_members_organization_member_key UNIQUE (organization_id, id);

ALTER TABLE workspace_members ADD CONSTRAINT workspace_members_role_changed_by_org_fk
  FOREIGN KEY (organization_id, role_changed_by) REFERENCES workspace_members (organization_id, id) NOT VALID;
ALTER TABLE workspace_members ADD CONSTRAINT workspace_members_disabled_by_org_fk
  FOREIGN KEY (organization_id, disabled_by) REFERENCES workspace_members (organization_id, id) NOT VALID;
ALTER TABLE workspace_invitations ADD CONSTRAINT workspace_invitations_member_org_fk
  FOREIGN KEY (organization_id, member_id) REFERENCES workspace_members (organization_id, id) NOT VALID;
ALTER TABLE workspace_invitations ADD CONSTRAINT workspace_invitations_invited_by_org_fk
  FOREIGN KEY (organization_id, invited_by_member_id) REFERENCES workspace_members (organization_id, id) NOT VALID;
ALTER TABLE manager_assignments ADD CONSTRAINT manager_assignments_manager_org_fk
  FOREIGN KEY (organization_id, manager_member_id) REFERENCES workspace_members (organization_id, id) NOT VALID;
ALTER TABLE manager_assignments ADD CONSTRAINT manager_assignments_contractor_org_fk
  FOREIGN KEY (organization_id, contractor_member_id) REFERENCES workspace_members (organization_id, id) NOT VALID;
ALTER TABLE manager_assignments ADD CONSTRAINT manager_assignments_created_by_org_fk
  FOREIGN KEY (organization_id, created_by) REFERENCES workspace_members (organization_id, id) NOT VALID;
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_member_org_fk
  FOREIGN KEY (organization_id, member_id) REFERENCES workspace_members (organization_id, id) NOT VALID;
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_revoked_by_org_fk
  FOREIGN KEY (organization_id, revoked_by_member_id) REFERENCES workspace_members (organization_id, id) NOT VALID;
ALTER TABLE auth_audit_events ADD CONSTRAINT auth_audit_events_actor_org_fk
  FOREIGN KEY (organization_id, actor_member_id) REFERENCES workspace_members (organization_id, id) NOT VALID;
ALTER TABLE auth_audit_events ADD CONSTRAINT auth_audit_events_subject_org_fk
  FOREIGN KEY (organization_id, subject_member_id) REFERENCES workspace_members (organization_id, id) NOT VALID;

-- 5. Legacy bridge: the text workspace and the organization can never disagree. ----------------------------------------
ALTER TABLE workspace_members     ADD CONSTRAINT workspace_members_legacy_organization
  CHECK (workspace_id <> 'thrivesource' OR organization_id = '5adff49b-11d5-4b45-bb4f-2f76cfcca0c6'::uuid) NOT VALID;
ALTER TABLE workspace_invitations ADD CONSTRAINT workspace_invitations_legacy_organization
  CHECK (workspace_id <> 'thrivesource' OR organization_id = '5adff49b-11d5-4b45-bb4f-2f76cfcca0c6'::uuid) NOT VALID;
ALTER TABLE manager_assignments   ADD CONSTRAINT manager_assignments_legacy_organization
  CHECK (workspace_id <> 'thrivesource' OR organization_id = '5adff49b-11d5-4b45-bb4f-2f76cfcca0c6'::uuid) NOT VALID;
ALTER TABLE auth_audit_events     ADD CONSTRAINT auth_audit_events_legacy_organization
  CHECK (workspace_id <> 'thrivesource' OR organization_id = '5adff49b-11d5-4b45-bb4f-2f76cfcca0c6'::uuid) NOT VALID;

-- Validation only reads rows (no UPDATE, so the append-only audit triggers never fire).
ALTER TABLE workspace_members     VALIDATE CONSTRAINT workspace_members_organization_fk;
ALTER TABLE workspace_invitations VALIDATE CONSTRAINT workspace_invitations_organization_fk;
ALTER TABLE manager_assignments   VALIDATE CONSTRAINT manager_assignments_organization_fk;
ALTER TABLE auth_sessions         VALIDATE CONSTRAINT auth_sessions_organization_fk;
ALTER TABLE auth_audit_events     VALIDATE CONSTRAINT auth_audit_events_organization_fk;
ALTER TABLE workspace_members     VALIDATE CONSTRAINT workspace_members_role_changed_by_org_fk;
ALTER TABLE workspace_members     VALIDATE CONSTRAINT workspace_members_disabled_by_org_fk;
ALTER TABLE workspace_invitations VALIDATE CONSTRAINT workspace_invitations_member_org_fk;
ALTER TABLE workspace_invitations VALIDATE CONSTRAINT workspace_invitations_invited_by_org_fk;
ALTER TABLE manager_assignments   VALIDATE CONSTRAINT manager_assignments_manager_org_fk;
ALTER TABLE manager_assignments   VALIDATE CONSTRAINT manager_assignments_contractor_org_fk;
ALTER TABLE manager_assignments   VALIDATE CONSTRAINT manager_assignments_created_by_org_fk;
ALTER TABLE auth_sessions         VALIDATE CONSTRAINT auth_sessions_member_org_fk;
ALTER TABLE auth_sessions         VALIDATE CONSTRAINT auth_sessions_revoked_by_org_fk;
ALTER TABLE auth_audit_events     VALIDATE CONSTRAINT auth_audit_events_actor_org_fk;
ALTER TABLE auth_audit_events     VALIDATE CONSTRAINT auth_audit_events_subject_org_fk;
ALTER TABLE workspace_members     VALIDATE CONSTRAINT workspace_members_legacy_organization;
ALTER TABLE workspace_invitations VALIDATE CONSTRAINT workspace_invitations_legacy_organization;
ALTER TABLE manager_assignments   VALIDATE CONSTRAINT manager_assignments_legacy_organization;
ALTER TABLE auth_audit_events     VALIDATE CONSTRAINT auth_audit_events_legacy_organization;

CREATE INDEX workspace_invitations_organization_member ON workspace_invitations (organization_id, member_id);
CREATE INDEX auth_sessions_organization_member ON auth_sessions (organization_id, member_id);
CREATE INDEX auth_audit_events_organization_occurred ON auth_audit_events (organization_id, occurred_at);

-- 6. Privileges ------------------------------------------------------------------------------------------------------
-- The platform default ("GRANT SELECT ON TABLES TO netlifydb_readonly") applied to organizations at CREATE TABLE; revoke it.
REVOKE ALL ON organizations FROM PUBLIC;
REVOKE ALL ON FUNCTION hourvia_guard_organization() FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'netlifydb_readonly') THEN
    REVOKE ALL ON organizations FROM netlifydb_readonly;
    REVOKE ALL ON FUNCTION hourvia_guard_organization() FROM netlifydb_readonly;
  END IF;
END
$$;
REVOKE ALL ON organizations FROM hourvia_auth_runtime;
-- Read-only, non-sensitive columns only. No INSERT, UPDATE, DELETE or TRUNCATE; no creator or suspension metadata.
GRANT SELECT (id, slug, name, kind, status) ON organizations TO hourvia_auth_runtime;
-- Existing runtime grants are untouched. In particular, no INSERT or UPDATE privilege on any organization_id column is
-- granted: application rows always take the ThriveSource default and can never be moved between organizations.

-- 7. Self-check: any surprise aborts this migration (and the deploy). ---------------------------------------------------
DO $$
DECLARE
  ts constant uuid := '5adff49b-11d5-4b45-bb4f-2f76cfcca0c6';
  t text;
  r record;
  n bigint;
  grantees text[] := ARRAY['public'];
BEGIN
  -- 7a. Exactly one organization: ThriveSource, active, internal.
  IF (SELECT count(*) FROM organizations) <> 1
     OR NOT EXISTS (SELECT 1 FROM organizations WHERE id = ts AND slug = 'thrivesource' AND name = 'ThriveSource'
                    AND kind = 'internal' AND status = 'active' AND suspended_at IS NULL AND suspended_reason IS NULL) THEN
    RAISE EXCEPTION 'self-check failed: organizations must contain exactly the active internal ThriveSource row';
  END IF;

  -- 7b. Every tenant column exists, is NOT NULL with the ThriveSource default, and every row belongs to ThriveSource.
  FOREACH t IN ARRAY ARRAY['workspace_members', 'workspace_invitations', 'manager_assignments', 'auth_sessions', 'auth_audit_events'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_attribute a JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
                   WHERE a.attrelid = ('public.' || t)::regclass AND a.attname = 'organization_id' AND a.attnotnull AND NOT a.attisdropped
                     AND a.atttypid = 'uuid'::regtype AND pg_get_expr(d.adbin, d.adrelid) = '''5adff49b-11d5-4b45-bb4f-2f76cfcca0c6''::uuid') THEN
      RAISE EXCEPTION 'self-check failed: %.organization_id is missing, nullable or has the wrong default', t;
    END IF;
    EXECUTE format('SELECT count(*) FROM public.%I WHERE organization_id <> $1', t) INTO n USING ts;
    IF n <> 0 THEN
      RAISE EXCEPTION 'self-check failed: % has rows outside ThriveSource', t;
    END IF;
  END LOOP;

  -- 7c. Every pre-existing row is preserved byte-for-byte (counts and content fingerprints), including both audit tables.
  FOR r IN
    SELECT b.t, b.n = c.n AND b.h = c.h AS same FROM hourvia_m7_baseline b JOIN (
      SELECT 'workspace_members' AS t, count(*) AS n,
             md5(coalesce(string_agg(md5(row(id, workspace_id, auth_user_id, email, display_name, role, status, approval_authorized, created_at,
                 activated_at, disabled_at, disabled_by, role_changed_by, role_changed_at)::text), '' ORDER BY id), '')) AS h FROM public.workspace_members
      UNION ALL SELECT 'workspace_invitations', count(*),
             md5(coalesce(string_agg(md5(row(id, workspace_id, member_id, email, role, status, invited_by_member_id, created_at, expires_at, accepted_at)::text), '' ORDER BY id), ''))
             FROM public.workspace_invitations
      UNION ALL SELECT 'manager_assignments', count(*),
             md5(coalesce(string_agg(md5(row(workspace_id, manager_member_id, contractor_member_id, created_at, created_by)::text), '' ORDER BY manager_member_id, contractor_member_id), ''))
             FROM public.manager_assignments
      UNION ALL SELECT 'auth_sessions', count(*),
             md5(coalesce(string_agg(md5(row(id, token_hash, member_id, created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at, revoked_reason, revoked_by_member_id)::text), '' ORDER BY id), ''))
             FROM public.auth_sessions
      UNION ALL SELECT 'auth_audit_events', count(*),
             md5(coalesce(string_agg(md5(row(id, workspace_id, occurred_at, event_type, outcome, actor_member_id, subject_member_id, email_hmac, ip_hmac, details)::text), '' ORDER BY id), ''))
             FROM public.auth_audit_events
      UNION ALL SELECT 'platform_audit_events', count(*),
             md5(coalesce(string_agg(md5(row(id, occurred_at, event_type, outcome, subject_auth_user_id, details)::text), '' ORDER BY id), ''))
             FROM public.platform_audit_events) c ON c.t = b.t
  LOOP
    IF NOT r.same THEN
      RAISE EXCEPTION 'self-check failed: existing rows of % changed during M7', r.t;
    END IF;
  END LOOP;
  IF (SELECT count(*) FROM hourvia_m7_baseline) <> 6 THEN
    RAISE EXCEPTION 'self-check failed: preservation baseline is incomplete';
  END IF;

  -- 7d. All new constraints exist and are validated; the single-organization constraints are still in place.
  IF (SELECT count(*) FROM pg_constraint WHERE convalidated AND conname IN (
        'workspace_members_organization_fk', 'workspace_invitations_organization_fk', 'manager_assignments_organization_fk',
        'auth_sessions_organization_fk', 'auth_audit_events_organization_fk', 'workspace_members_organization_member_key',
        'workspace_members_role_changed_by_org_fk', 'workspace_members_disabled_by_org_fk', 'workspace_invitations_member_org_fk',
        'workspace_invitations_invited_by_org_fk', 'manager_assignments_manager_org_fk', 'manager_assignments_contractor_org_fk',
        'manager_assignments_created_by_org_fk', 'auth_sessions_member_org_fk', 'auth_sessions_revoked_by_org_fk',
        'auth_audit_events_actor_org_fk', 'auth_audit_events_subject_org_fk', 'workspace_members_legacy_organization',
        'workspace_invitations_legacy_organization', 'manager_assignments_legacy_organization', 'auth_audit_events_legacy_organization',
        'organizations_single_tenant_m7')) <> 22 THEN
    RAISE EXCEPTION 'self-check failed: an organization constraint is missing or not validated';
  END IF;
  IF (SELECT count(*) FROM pg_constraint WHERE contype = 'c' AND conname IN (
        'workspace_members_workspace_id_check', 'workspace_invitations_workspace_id_check',
        'manager_assignments_workspace_id_check', 'auth_audit_events_workspace_id_check',
        'workspace_members_role_check', 'workspace_invitations_role_check', 'workspace_invitations_no_super_admin')) <> 7
     OR NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'workspace_members_auth_user_id_key' AND contype = 'u') THEN
    RAISE EXCEPTION 'self-check failed: an existing single-organization or role constraint is missing';
  END IF;

  -- 7e. RLS stays off everywhere; every guard and audit trigger (old and new) is present and enabled.
  IF EXISTS (SELECT 1 FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relrowsecurity) THEN
    RAISE EXCEPTION 'self-check failed: row-level security must stay disabled in Sprint 2.0B';
  END IF;
  IF (SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled = 'O' AND tgname IN
       ('workspace_members_guard', 'workspace_members_guard_insert', 'workspace_members_audit', 'workspace_invitations_guard',
        'auth_sessions_guard', 'auth_sessions_revocation_audit', 'auth_audit_events_no_update_delete', 'auth_audit_events_no_truncate',
        'platform_audit_events_no_update_delete', 'platform_audit_events_no_truncate', 'platform_privileges_guard',
        'platform_privileges_audit', 'platform_privileges_no_truncate', 'platform_super_admin_designation_guard',
        'platform_super_admin_designation_audit', 'platform_super_admin_designation_no_truncate',
        'organizations_guard', 'organizations_no_truncate')) <> 18 THEN
    RAISE EXCEPTION 'self-check failed: guard or audit triggers are missing or disabled';
  END IF;

  -- 7f. Functions: exactly the 15 earlier ones plus hourvia_guard_organization, all pinned, none executable by
  -- PUBLIC or the read-only credential, and runtime EXECUTE unchanged.
  IF (SELECT count(*) FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND p.proname LIKE 'hourvia\_%') <> 16 THEN
    RAISE EXCEPTION 'self-check failed: unexpected number of hourvia_* functions';
  END IF;
  FOR r IN SELECT p.oid::regprocedure AS f, p.proconfig, p.prosecdef, p.proname, pg_get_userbyid(p.proowner) AS owner
           FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND p.proname LIKE 'hourvia\_%' LOOP
    IF r.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, public, pg_temp'] OR r.owner <> current_user
       OR r.prosecdef <> (r.proname IN ('hourvia_platform_overview', 'hourvia_platform_audit_page')) THEN
      RAISE EXCEPTION 'self-check failed: % has an unexpected search_path, owner or SECURITY DEFINER flag', r.f;
    END IF;
    IF has_function_privilege('public', r.f, 'EXECUTE')
       OR (EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'netlifydb_readonly') AND has_function_privilege('netlifydb_readonly', r.f, 'EXECUTE'))
       OR has_function_privilege('hourvia_auth_runtime', r.f, 'EXECUTE')
          <> (r.proname IN ('hourvia_member_authority', 'hourvia_platform_overview', 'hourvia_platform_audit_page')) THEN
      RAISE EXCEPTION 'self-check failed: EXECUTE privileges on % are unexpected', r.f;
    END IF;
  END LOOP;

  -- 7g. organizations: never readable by PUBLIC or netlifydb_readonly; runtime reads five columns and writes nothing.
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'netlifydb_readonly') THEN
    grantees := array_append(grantees, 'netlifydb_readonly');
  END IF;
  FOREACH t IN ARRAY grantees LOOP
    IF has_table_privilege(t, 'public.organizations', 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN')
       OR has_any_column_privilege(t, 'public.organizations', 'SELECT, INSERT, UPDATE, REFERENCES') THEN
      RAISE EXCEPTION 'self-check failed: % has access to organizations', t;
    END IF;
  END LOOP;
  IF has_table_privilege('hourvia_auth_runtime', 'public.organizations', 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN')
     OR has_any_column_privilege('hourvia_auth_runtime', 'public.organizations', 'INSERT, UPDATE, REFERENCES')
     OR has_column_privilege('hourvia_auth_runtime', 'public.organizations', 'created_by_auth_user_id', 'SELECT')
     OR has_column_privilege('hourvia_auth_runtime', 'public.organizations', 'suspended_reason', 'SELECT')
     OR has_column_privilege('hourvia_auth_runtime', 'public.organizations', 'suspended_at', 'SELECT')
     OR has_column_privilege('hourvia_auth_runtime', 'public.organizations', 'created_at', 'SELECT')
     OR NOT has_column_privilege('hourvia_auth_runtime', 'public.organizations', 'id', 'SELECT')
     OR NOT has_column_privilege('hourvia_auth_runtime', 'public.organizations', 'status', 'SELECT') THEN
    RAISE EXCEPTION 'self-check failed: unexpected hourvia_auth_runtime privileges on organizations';
  END IF;

  -- 7h. The runtime can never choose or change an organization_id, and its earlier boundaries are unchanged.
  FOREACH t IN ARRAY ARRAY['workspace_members', 'workspace_invitations', 'manager_assignments', 'auth_sessions', 'auth_audit_events'] LOOP
    IF has_column_privilege('hourvia_auth_runtime', 'public.' || t, 'organization_id', 'INSERT')
       OR has_column_privilege('hourvia_auth_runtime', 'public.' || t, 'organization_id', 'UPDATE')
       OR has_table_privilege('hourvia_auth_runtime', 'public.' || t, 'DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN') THEN
      RAISE EXCEPTION 'self-check failed: hourvia_auth_runtime can write %.organization_id or has a forbidden table privilege', t;
    END IF;
  END LOOP;
  IF has_any_column_privilege('hourvia_auth_runtime', 'public.auth_audit_events', 'SELECT, UPDATE')
     OR has_any_column_privilege('hourvia_auth_runtime', 'public.manager_assignments', 'INSERT, UPDATE')
     OR has_column_privilege('hourvia_auth_runtime', 'public.workspace_members', 'approval_authorized', 'UPDATE')
     OR has_column_privilege('hourvia_auth_runtime', 'public.workspace_members', 'workspace_id', 'UPDATE')
     OR has_schema_privilege('hourvia_auth_runtime', 'public', 'CREATE')
     OR has_database_privilege('hourvia_auth_runtime', current_database(), 'CREATE') THEN
    RAISE EXCEPTION 'self-check failed: an earlier hourvia_auth_runtime boundary changed';
  END IF;
  -- ACL entries on organizations may name only the owner and the runtime role.
  IF EXISTS (
    SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a
    WHERE c.oid = 'public.organizations'::regclass AND a.grantee NOT IN (c.relowner, 'hourvia_auth_runtime'::regrole)
    UNION ALL
    SELECT 1 FROM pg_attribute at CROSS JOIN LATERAL aclexplode(at.attacl) a
    WHERE at.attrelid = 'public.organizations'::regclass AND a.grantee NOT IN ((SELECT relowner FROM pg_class WHERE oid = 'public.organizations'::regclass), 'hourvia_auth_runtime'::regrole)
  ) THEN
    RAISE EXCEPTION 'self-check failed: an unexpected role is granted access to organizations';
  END IF;
END
$$;

DROP TABLE pg_temp.hourvia_m7_baseline;
