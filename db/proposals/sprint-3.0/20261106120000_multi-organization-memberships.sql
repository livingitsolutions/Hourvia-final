-- Hourvia Sprint 3.0: M8 multi-organization memberships (PROPOSAL; forward-only; NOT AUTO-APPLIED)
--
-- Staged under db/proposals/sprint-3.0/ on purpose. Netlify applies only netlify/database/migrations/, so this file
-- reaches no preview or production database until an owner-approved promotion copies it there byte-for-byte.
-- Promotion prerequisites are in db/proposals/sprint-3.0/README.md (M7 ledger provenance, owner ledger check,
-- catalog-evidence update). M1-M7 stay byte-identical; this migration only adds, replaces and relaxes in one transaction.
--
-- What this migration does:
--   * Organizations: drops organizations_single_tenant_m7; permanently binds the ThriveSource UUID to slug 'thrivesource'
--     and makes 'internal' a ThriveSource-only kind; adds updated_at (maintained by the guard); adds (id, slug) and
--     (id, kind) keys for composite foreign keys.
--   * Workspace binding: replaces CHECK (workspace_id = 'thrivesource') on the four tables that carry workspace_id with a
--     composite foreign key (organization_id, workspace_id) -> organizations (id, slug). The legacy text key can never
--     disagree with the organization, and slugs are immutable.
--   * Memberships: replaces the global auth_user_id UNIQUE with UNIQUE (organization_id, auth_user_id). One Supabase
--     identity may hold one membership per organization, with an independent role and status in each. Adds the
--     'suspended' status (operator-only; never granted or cleared by the runtime). organization_id becomes immutable.
--   * Seat entitlements: new organization_seat_entitlements (one row per organization). ThriveSource is seeded as
--     internal_unlimited (no limit, no billing expiry), and only an internal organization can hold that plan.
--     The database enforces seats: a new pending invitation, or a member becoming active, needs a free seat.
--     Active members consume seats; pending unexpired invitations reserve seats; invited (without a pending
--     invitation), suspended and disabled members do not. Each organization is counted independently.
--   * Audit triggers write NEW.organization_id instead of relying on the ThriveSource column default.
--   * The runtime role gains INSERT on organization_id (never UPDATE) for the four tables it inserts into, and SELECT on
--     four non-sensitive entitlement columns. Composite foreign keys keep every child row in its member's organization.
--   * The platform candidate is restricted to the ThriveSource membership of the designated mailbox.
--
-- What it deliberately does NOT do:
--   * No organization is created, no row is moved or rewritten, and no audit row is touched. ADD COLUMN uses a
--     non-volatile default (catalog-only); every validation is a read-only scan.
--   * The ThriveSource column defaults stay (expand step). The deployed application keeps working unchanged. A later,
--     separately reviewed contract migration drops them once no deployed code relies on them.
--   * No RLS (see README: one runtime role serves every organization; isolation is enforced by composite keys, guards
--     and the application's lexical tenant predicates). No new role, no SECURITY DEFINER change, no new runtime EXECUTE.
--   * The runtime still cannot create, change or delete organizations or entitlements.

-- 0. Preconditions: exactly the reviewed M7 state ---------------------------------------------------------------------
DO $$
DECLARE
  ts constant uuid := '5adff49b-11d5-4b45-bb4f-2f76cfcca0c6';
  expected text[] := ARRAY[
    'hourvia_audit_member_change()', 'hourvia_audit_platform_change()', 'hourvia_audit_session_revocation()',
    'hourvia_guard_invitation_insert()', 'hourvia_guard_member_insert()', 'hourvia_guard_member_update()',
    'hourvia_guard_organization()', 'hourvia_guard_platform_designation()', 'hourvia_guard_platform_privilege()',
    'hourvia_guard_session_update()', 'hourvia_is_verified_platform_candidate(uuid)', 'hourvia_member_authority(uuid,text)',
    'hourvia_platform_audit_page(text,bigint,integer)', 'hourvia_platform_overview(text)',
    'hourvia_platform_session_holder(text)', 'hourvia_reject_audit_mutation()'];
  actual text[];
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'hourvia_auth_runtime') THEN
    RAISE EXCEPTION 'hourvia_auth_runtime does not exist; apply M1-M7 first';
  END IF;
  IF to_regclass('public.organizations') IS NULL THEN
    RAISE EXCEPTION 'organizations does not exist; apply M7 (20261104170000) first';
  END IF;
  IF to_regclass('public.organization_seat_entitlements') IS NOT NULL THEN
    RAISE EXCEPTION 'organization_seat_entitlements already exists; M8 must be applied exactly once to an M7 database';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'organizations_single_tenant_m7' AND conrelid = 'public.organizations'::regclass)
     OR NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'workspace_members_auth_user_id_key' AND contype = 'u') THEN
    RAISE EXCEPTION 'the M7 single-organization constraints are not in their reviewed state; stop and review';
  END IF;
  SELECT coalesce(array_agg(sig ORDER BY sig), '{}') INTO actual
  FROM (SELECT replace(p.proname || '(' || oidvectortypes(p.proargtypes) || ')', ', ', ',') AS sig
        FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND p.proname LIKE 'hourvia\_%') f;
  IF actual IS DISTINCT FROM (SELECT array_agg(e ORDER BY e) FROM unnest(expected) e) THEN
    RAISE EXCEPTION 'unexpected hourvia_* functions before M8: found %', actual;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND p.proname LIKE 'hourvia\_%'
             AND p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, public, pg_temp']) THEN
    RAISE EXCEPTION 'a hourvia_* function lacks the pinned search_path; stop and review';
  END IF;
  IF (SELECT count(*) FROM organizations) <> 1
     OR NOT EXISTS (SELECT 1 FROM organizations WHERE id = ts AND slug = 'thrivesource' AND kind = 'internal' AND status = 'active') THEN
    RAISE EXCEPTION 'organizations must contain exactly the active internal ThriveSource row before M8';
  END IF;
  IF EXISTS (SELECT 1 FROM workspace_members WHERE organization_id <> ts OR workspace_id <> 'thrivesource')
     OR EXISTS (SELECT 1 FROM workspace_invitations WHERE organization_id <> ts OR workspace_id <> 'thrivesource')
     OR EXISTS (SELECT 1 FROM manager_assignments WHERE organization_id <> ts OR workspace_id <> 'thrivesource')
     OR EXISTS (SELECT 1 FROM auth_sessions WHERE organization_id <> ts)
     OR EXISTS (SELECT 1 FROM auth_audit_events WHERE organization_id <> ts OR workspace_id <> 'thrivesource') THEN
    RAISE EXCEPTION 'a row is outside ThriveSource before M8; stop and review';
  END IF;
  IF EXISTS (SELECT 1 FROM workspace_members WHERE status NOT IN ('invited', 'active', 'disabled')) THEN
    RAISE EXCEPTION 'unexpected membership status before M8; stop and review';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relrowsecurity) THEN
    RAISE EXCEPTION 'row-level security is unexpectedly enabled on a public table; stop and review';
  END IF;
END
$$;

-- Preservation baseline: counts and content fingerprints of every existing row (including organization_id), compared
-- again by the self-check. Dropped explicitly at the end.
CREATE TEMPORARY TABLE hourvia_m8_baseline AS
SELECT 'workspace_members' AS t, count(*) AS n, md5(coalesce(string_agg(md5(row(m.*)::text), '' ORDER BY id), '')) AS h FROM public.workspace_members m
UNION ALL SELECT 'workspace_invitations', count(*), md5(coalesce(string_agg(md5(row(i.*)::text), '' ORDER BY id), '')) FROM public.workspace_invitations i
UNION ALL SELECT 'manager_assignments', count(*), md5(coalesce(string_agg(md5(row(a.*)::text), '' ORDER BY manager_member_id, contractor_member_id), '')) FROM public.manager_assignments a
UNION ALL SELECT 'auth_sessions', count(*), md5(coalesce(string_agg(md5(row(s.*)::text), '' ORDER BY id), '')) FROM public.auth_sessions s
UNION ALL SELECT 'auth_audit_events', count(*), md5(coalesce(string_agg(md5(row(e.*)::text), '' ORDER BY id), '')) FROM public.auth_audit_events e
UNION ALL SELECT 'auth_rate_limits', count(*), md5(coalesce(string_agg(md5(row(rl.*)::text), '' ORDER BY bucket, window_start), '')) FROM public.auth_rate_limits rl
UNION ALL SELECT 'platform_privileges', count(*), md5(coalesce(string_agg(md5(row(p.*)::text), '' ORDER BY id), '')) FROM public.platform_privileges p
UNION ALL SELECT 'platform_super_admin_designation', count(*), md5(coalesce(string_agg(md5(row(d.*)::text), ''), '')) FROM public.platform_super_admin_designation d
UNION ALL SELECT 'platform_audit_events', count(*), md5(coalesce(string_agg(md5(row(x.*)::text), '' ORDER BY id), '')) FROM public.platform_audit_events x
UNION ALL SELECT 'organizations', count(*), md5(coalesce(string_agg(md5(row(o.id, o.slug, o.name, o.kind, o.status, o.created_at, o.created_by_auth_user_id, o.suspended_at, o.suspended_reason)::text), '' ORDER BY id), '')) FROM public.organizations o;

-- 1. Organizations ----------------------------------------------------------------------------------------------------
ALTER TABLE organizations DROP CONSTRAINT organizations_single_tenant_m7;
-- The ThriveSource UUID and slug are permanently bound to each other, and 'internal' belongs to ThriveSource only.
ALTER TABLE organizations ADD CONSTRAINT organizations_thrivesource_identity
  CHECK ((id = '5adff49b-11d5-4b45-bb4f-2f76cfcca0c6'::uuid) = (slug = 'thrivesource'));
ALTER TABLE organizations ADD CONSTRAINT organizations_internal_is_thrivesource
  CHECK ((kind = 'internal') = (id = '5adff49b-11d5-4b45-bb4f-2f76cfcca0c6'::uuid));
-- now() is evaluated once for the existing row: catalog-only, no rewrite, no row trigger.
ALTER TABLE organizations ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE organizations ADD CONSTRAINT organizations_updated_after_creation CHECK (updated_at >= created_at);
ALTER TABLE organizations ADD CONSTRAINT organizations_id_slug_key UNIQUE (id, slug);
ALTER TABLE organizations ADD CONSTRAINT organizations_id_kind_key UNIQUE (id, kind);

CREATE OR REPLACE FUNCTION hourvia_guard_organization() RETURNS trigger
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
  NEW.updated_at := greatest(now(), OLD.updated_at);
  RETURN NEW;
END
$$;

-- 2. Workspace binding: (organization_id, workspace_id) must name an existing organization and its own slug ------------
ALTER TABLE workspace_members     ADD CONSTRAINT workspace_members_organization_workspace_fk
  FOREIGN KEY (organization_id, workspace_id) REFERENCES organizations (id, slug) NOT VALID;
ALTER TABLE workspace_invitations ADD CONSTRAINT workspace_invitations_organization_workspace_fk
  FOREIGN KEY (organization_id, workspace_id) REFERENCES organizations (id, slug) NOT VALID;
ALTER TABLE manager_assignments   ADD CONSTRAINT manager_assignments_organization_workspace_fk
  FOREIGN KEY (organization_id, workspace_id) REFERENCES organizations (id, slug) NOT VALID;
ALTER TABLE auth_audit_events     ADD CONSTRAINT auth_audit_events_organization_workspace_fk
  FOREIGN KEY (organization_id, workspace_id) REFERENCES organizations (id, slug) NOT VALID;
ALTER TABLE workspace_members     VALIDATE CONSTRAINT workspace_members_organization_workspace_fk;
ALTER TABLE workspace_invitations VALIDATE CONSTRAINT workspace_invitations_organization_workspace_fk;
ALTER TABLE manager_assignments   VALIDATE CONSTRAINT manager_assignments_organization_workspace_fk;
ALTER TABLE auth_audit_events     VALIDATE CONSTRAINT auth_audit_events_organization_workspace_fk;
-- Only now, with the binding validated, is the single-workspace CHECK removed.
ALTER TABLE workspace_members     DROP CONSTRAINT workspace_members_workspace_id_check;
ALTER TABLE workspace_invitations DROP CONSTRAINT workspace_invitations_workspace_id_check;
ALTER TABLE manager_assignments   DROP CONSTRAINT manager_assignments_workspace_id_check;
ALTER TABLE auth_audit_events     DROP CONSTRAINT auth_audit_events_workspace_id_check;

-- 3. Memberships: one per (organization, identity); 'suspended' status ---------------------------------------------------
ALTER TABLE workspace_members ADD CONSTRAINT workspace_members_organization_auth_user_key UNIQUE (organization_id, auth_user_id);
ALTER TABLE workspace_members DROP CONSTRAINT workspace_members_auth_user_id_key;
CREATE INDEX workspace_members_auth_user ON workspace_members (auth_user_id) WHERE auth_user_id IS NOT NULL;
ALTER TABLE workspace_members DROP CONSTRAINT workspace_members_status_check;
ALTER TABLE workspace_members ADD CONSTRAINT workspace_members_status_check CHECK (status IN ('invited', 'active', 'suspended', 'disabled'));
ALTER TABLE workspace_members ADD CONSTRAINT workspace_members_suspended_was_active
  CHECK (status <> 'suspended' OR (auth_user_id IS NOT NULL AND activated_at IS NOT NULL));
CREATE INDEX workspace_invitations_organization_pending ON workspace_invitations (organization_id, expires_at) WHERE status = 'pending';

-- 4. Seat entitlements ---------------------------------------------------------------------------------------------------
CREATE TABLE organization_seat_entitlements (
  organization_id    uuid PRIMARY KEY,
  organization_kind  text NOT NULL,
  plan               text NOT NULL CHECK (plan IN ('internal_unlimited', 'standard')),
  seat_limit         integer CHECK (seat_limit BETWEEN 1 AND 100000),
  billing_expires_at timestamptz,
  approval_ref       text NOT NULL CHECK (approval_ref ~ '^[A-Za-z0-9._:-]{3,64}$'),
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT organization_seat_entitlements_organization_fk FOREIGN KEY (organization_id, organization_kind) REFERENCES organizations (id, kind),
  CONSTRAINT organization_seat_entitlements_limit_matches_plan CHECK ((plan = 'internal_unlimited') = (seat_limit IS NULL)),
  CONSTRAINT organization_seat_entitlements_internal_unlimited CHECK ((plan = 'internal_unlimited') = (organization_kind = 'internal')),
  CONSTRAINT organization_seat_entitlements_internal_no_billing CHECK (plan <> 'internal_unlimited' OR billing_expires_at IS NULL),
  CONSTRAINT organization_seat_entitlements_updated_after_creation CHECK (updated_at >= created_at)
);
INSERT INTO organization_seat_entitlements (organization_id, organization_kind, plan, seat_limit, billing_expires_at, approval_ref)
VALUES ('5adff49b-11d5-4b45-bb4f-2f76cfcca0c6', 'internal', 'internal_unlimited', NULL, NULL, 'M8-THRIVESOURCE-INTERNAL');

CREATE FUNCTION hourvia_guard_seat_entitlement() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
  IF TG_LEVEL = 'STATEMENT' OR TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'seat entitlements cannot be deleted or truncated';
  END IF;
  IF current_user = 'hourvia_auth_runtime' THEN
    RAISE EXCEPTION 'the application cannot change seat entitlements';
  END IF;
  IF NEW.organization_id IS DISTINCT FROM OLD.organization_id OR NEW.organization_kind IS DISTINCT FROM OLD.organization_kind
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'seat entitlement identity columns are immutable';
  END IF;
  NEW.updated_at := greatest(now(), OLD.updated_at);
  RETURN NEW;
END
$$;
CREATE TRIGGER organization_seat_entitlements_guard BEFORE UPDATE OR DELETE ON organization_seat_entitlements
  FOR EACH ROW EXECUTE FUNCTION hourvia_guard_seat_entitlement();
CREATE TRIGGER organization_seat_entitlements_no_truncate BEFORE TRUNCATE ON organization_seat_entitlements
  FOR EACH STATEMENT EXECUTE FUNCTION hourvia_guard_seat_entitlement();

-- 5. Membership guards (same triggers; bodies extend the M4 versions) ------------------------------------------------------
-- Seat rule (inlined so the runtime needs no new EXECUTE privilege). A transaction-scoped advisory lock per organization
-- serializes concurrent seat consumers. Reference time is least(now(), supplied time) so a caller cannot make
-- reservations look expired by supplying a future timestamp.
CREATE OR REPLACE FUNCTION hourvia_guard_member_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
  runtime constant boolean := current_user = 'hourvia_auth_runtime';
  authority text;
  ent record;
  used bigint;
BEGIN
  IF NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
     OR NEW.email IS DISTINCT FROM OLD.email OR (OLD.auth_user_id IS NOT NULL AND NEW.auth_user_id IS DISTINCT FROM OLD.auth_user_id) THEN
    RAISE EXCEPTION 'workspace_members identity columns are immutable';
  END IF;

  IF OLD.status = 'disabled' AND NEW.status <> 'disabled' THEN
    IF runtime OR coalesce(current_setting('hourvia.member_reinstatement', true), '') <> 'approved' THEN
      RAISE EXCEPTION 'disabled workspace members cannot be re-enabled by the runtime';
    END IF;
    IF NEW.status <> 'active' OR NEW.role IS DISTINCT FROM OLD.role OR OLD.activated_at IS NULL THEN
      RAISE EXCEPTION 'reinstatement restores a previously active member with the same role only';
    END IF;
  ELSIF OLD.status IN ('disabled', 'suspended') AND NEW.role IS DISTINCT FROM OLD.role THEN
    RAISE EXCEPTION 'disabled or suspended workspace members cannot change role';
  END IF;

  IF NEW.role IS DISTINCT FROM OLD.role THEN
    IF runtime THEN
      IF NEW.role_changed_by IS NULL OR NEW.role_changed_at IS NULL
         OR NEW.role_changed_at IS NOT DISTINCT FROM OLD.role_changed_at THEN
        RAISE EXCEPTION 'role changes must record the authorizing member';
      END IF;
      IF NEW.role_changed_by = NEW.id THEN
        RAISE EXCEPTION 'members cannot change their own role';
      END IF;
      authority := hourvia_member_authority(NEW.role_changed_by, NEW.workspace_id);
      IF authority IS NULL OR ((OLD.role = 'workspace_admin' OR NEW.role = 'workspace_admin') AND authority <> 'platform_super_admin') THEN
        RAISE EXCEPTION 'role change is not authorized for this member';
      END IF;
    ELSIF OLD.status <> 'invited' THEN
      RAISE EXCEPTION 'workspace_members role can change only while invited, or through the application';
    END IF;
    IF NEW.role <> 'workspace_manager' THEN
      NEW.approval_authorized := false;
    END IF;
  END IF;

  IF runtime AND NEW.status IS DISTINCT FROM OLD.status THEN
    IF NEW.status = 'active' THEN
      IF OLD.status <> 'invited' OR NOT EXISTS (
           SELECT 1 FROM workspace_invitations i
           WHERE i.member_id = NEW.id AND i.organization_id = NEW.organization_id AND i.workspace_id = NEW.workspace_id
             AND i.status = 'accepted' AND i.role = NEW.role) THEN
        RAISE EXCEPTION 'activation requires an accepted invitation for the same role';
      END IF;
    ELSIF NEW.status = 'disabled' THEN
      authority := hourvia_member_authority(NEW.disabled_by, NEW.workspace_id);
      IF NEW.disabled_by IS NULL OR NEW.disabled_by = NEW.id OR authority IS NULL
         OR (OLD.role = 'workspace_admin' AND authority <> 'platform_super_admin') THEN
        RAISE EXCEPTION 'disable is not authorized for this member';
      END IF;
    ELSE
      RAISE EXCEPTION 'workspace_members status transition is not permitted';
    END IF;
  END IF;

  IF NEW.status = 'active' AND OLD.status <> 'active' THEN
    PERFORM pg_advisory_xact_lock(hashtextextended('hourvia_seats:' || NEW.organization_id::text, 0));
    SELECT e.plan, e.seat_limit, e.billing_expires_at INTO ent FROM organization_seat_entitlements e WHERE e.organization_id = NEW.organization_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'organization has no seat entitlement';
    END IF;
    IF ent.plan <> 'internal_unlimited' THEN
      IF ent.billing_expires_at IS NOT NULL AND ent.billing_expires_at <= now() THEN
        RAISE EXCEPTION 'organization seat entitlement has expired';
      END IF;
      SELECT (SELECT count(*) FROM workspace_members m WHERE m.organization_id = NEW.organization_id AND m.status = 'active' AND m.id <> NEW.id)
           + (SELECT count(*) FROM workspace_invitations i JOIN workspace_members m ON m.id = i.member_id AND m.organization_id = i.organization_id
              WHERE i.organization_id = NEW.organization_id AND i.status = 'pending' AND i.expires_at > now() AND m.status = 'invited' AND i.member_id <> NEW.id)
        INTO used;
      IF used >= ent.seat_limit THEN
        RAISE EXCEPTION 'no seat is available in this organization';
      END IF;
    END IF;
  END IF;
  RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION hourvia_guard_member_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
  ent record;
  used bigint;
BEGIN
  IF current_user = 'hourvia_auth_runtime' THEN
    IF NEW.status <> 'invited' OR NEW.role_changed_by IS NOT NULL OR NEW.role_changed_at IS NOT NULL THEN
      RAISE EXCEPTION 'the application can create only invited members';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM organizations o WHERE o.id = NEW.organization_id AND o.status = 'active') THEN
      RAISE EXCEPTION 'members can be added only to an active organization';
    END IF;
  END IF;
  IF NEW.status = 'active' THEN
    PERFORM pg_advisory_xact_lock(hashtextextended('hourvia_seats:' || NEW.organization_id::text, 0));
    SELECT e.plan, e.seat_limit, e.billing_expires_at INTO ent FROM organization_seat_entitlements e WHERE e.organization_id = NEW.organization_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'organization has no seat entitlement';
    END IF;
    IF ent.plan <> 'internal_unlimited' THEN
      IF ent.billing_expires_at IS NOT NULL AND ent.billing_expires_at <= now() THEN
        RAISE EXCEPTION 'organization seat entitlement has expired';
      END IF;
      SELECT (SELECT count(*) FROM workspace_members m WHERE m.organization_id = NEW.organization_id AND m.status = 'active')
           + (SELECT count(*) FROM workspace_invitations i JOIN workspace_members m ON m.id = i.member_id AND m.organization_id = i.organization_id
              WHERE i.organization_id = NEW.organization_id AND i.status = 'pending' AND i.expires_at > now() AND m.status = 'invited')
        INTO used;
      IF used >= ent.seat_limit THEN
        RAISE EXCEPTION 'no seat is available in this organization';
      END IF;
    END IF;
  END IF;
  RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION hourvia_guard_invitation_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
  member_role text;
  member_status text;
  authority text;
  ent record;
  used bigint;
  ref timestamptz;
BEGIN
  SELECT m.role, m.status INTO member_role, member_status
    FROM workspace_members m WHERE m.id = NEW.member_id AND m.workspace_id = NEW.workspace_id AND m.organization_id = NEW.organization_id;
  IF member_role IS DISTINCT FROM NEW.role THEN
    RAISE EXCEPTION 'invitation role must match the member role';
  END IF;
  IF NEW.status = 'pending' AND member_status IS DISTINCT FROM 'invited' THEN
    RAISE EXCEPTION 'pending invitations can be issued only to invited members';
  END IF;
  IF NEW.invited_by_member_id IS NULL THEN
    IF current_user = 'hourvia_auth_runtime' THEN
      RAISE EXCEPTION 'application invitations must record the inviting member';
    END IF;
  ELSE
    authority := hourvia_member_authority(NEW.invited_by_member_id, NEW.workspace_id);
    IF NEW.invited_by_member_id = NEW.member_id OR authority IS NULL
       OR (NEW.role = 'workspace_admin' AND authority <> 'platform_super_admin') THEN
      RAISE EXCEPTION 'inviter is not authorized to grant this role';
    END IF;
  END IF;
  IF NEW.status = 'pending' THEN
    IF NOT EXISTS (SELECT 1 FROM organizations o WHERE o.id = NEW.organization_id AND o.status = 'active') THEN
      RAISE EXCEPTION 'invitations can be issued only in an active organization';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('hourvia_seats:' || NEW.organization_id::text, 0));
    SELECT e.plan, e.seat_limit, e.billing_expires_at INTO ent FROM organization_seat_entitlements e WHERE e.organization_id = NEW.organization_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'organization has no seat entitlement';
    END IF;
    IF ent.plan <> 'internal_unlimited' THEN
      IF ent.billing_expires_at IS NOT NULL AND ent.billing_expires_at <= now() THEN
        RAISE EXCEPTION 'organization seat entitlement has expired';
      END IF;
      ref := least(now(), NEW.created_at);
      SELECT (SELECT count(*) FROM workspace_members m WHERE m.organization_id = NEW.organization_id AND m.status = 'active')
           + (SELECT count(*) FROM workspace_invitations i JOIN workspace_members m ON m.id = i.member_id AND m.organization_id = i.organization_id
              WHERE i.organization_id = NEW.organization_id AND i.status = 'pending' AND i.expires_at > ref AND m.status = 'invited' AND i.member_id <> NEW.member_id)
        INTO used;
      IF used >= ent.seat_limit THEN
        RAISE EXCEPTION 'no seat is available in this organization';
      END IF;
    END IF;
  END IF;
  RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION hourvia_guard_session_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
  authority text;
  subject_role text;
  subject_workspace text;
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id OR NEW.token_hash IS DISTINCT FROM OLD.token_hash OR NEW.member_id IS DISTINCT FROM OLD.member_id
     OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.absolute_expires_at IS DISTINCT FROM OLD.absolute_expires_at THEN
    RAISE EXCEPTION 'auth_sessions identity columns are immutable';
  END IF;
  IF OLD.revoked_at IS NOT NULL AND (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at OR NEW.revoked_reason IS DISTINCT FROM OLD.revoked_reason
     OR NEW.revoked_by_member_id IS DISTINCT FROM OLD.revoked_by_member_id) THEN
    RAISE EXCEPTION 'session revocation is final';
  END IF;
  IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL AND current_user = 'hourvia_auth_runtime' THEN
    IF NEW.revoked_by_member_id IS NULL THEN
      RAISE EXCEPTION 'application session revocations must record the acting member';
    END IF;
    IF NEW.revoked_by_member_id <> NEW.member_id THEN
      SELECT m.role, m.workspace_id INTO subject_role, subject_workspace FROM workspace_members m WHERE m.id = NEW.member_id;
      authority := hourvia_member_authority(NEW.revoked_by_member_id, subject_workspace);
      IF authority IS NULL OR (subject_role = 'workspace_admin' AND authority <> 'platform_super_admin') THEN
        RAISE EXCEPTION 'session revocation is not authorized for this member';
      END IF;
    END IF;
  END IF;
  RETURN NEW;
END
$$;

-- 6. Audit triggers write the member's organization explicitly ------------------------------------------------------------
CREATE OR REPLACE FUNCTION hourvia_audit_member_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
  role_changed boolean := TG_OP = 'UPDATE' AND NEW.role IS DISTINCT FROM OLD.role;
BEGIN
  IF TG_OP = 'UPDATE' AND NOT role_changed AND NEW.status IS NOT DISTINCT FROM OLD.status THEN
    RETURN NULL;
  END IF;
  INSERT INTO auth_audit_events (organization_id, workspace_id, occurred_at, event_type, outcome, actor_member_id, subject_member_id, details)
  VALUES (
    NEW.organization_id, NEW.workspace_id, now(),
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

CREATE OR REPLACE FUNCTION hourvia_audit_session_revocation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
DECLARE
  subject_workspace text;
  subject_organization uuid;
  authority text;
BEGIN
  SELECT m.workspace_id, m.organization_id INTO subject_workspace, subject_organization FROM workspace_members m WHERE m.id = NEW.member_id;
  authority := CASE
    WHEN NEW.revoked_by_member_id IS NULL THEN 'operator'
    WHEN NEW.revoked_by_member_id = NEW.member_id THEN 'self'
    ELSE coalesce(hourvia_member_authority(NEW.revoked_by_member_id, subject_workspace), 'unknown') END;
  INSERT INTO auth_audit_events (organization_id, workspace_id, occurred_at, event_type, outcome, actor_member_id, subject_member_id, details)
  VALUES (subject_organization, subject_workspace, now(), 'session_revocation', 'success', NEW.revoked_by_member_id, NEW.member_id,
          jsonb_build_object('reason', NEW.revoked_reason, 'authority', authority,
                             'source', CASE WHEN current_user = 'hourvia_auth_runtime' THEN 'application' ELSE 'operator_sql' END));
  RETURN NULL;
END
$$;

-- 7. Platform candidate: the designated mailbox's active ThriveSource membership only ------------------------------------
CREATE OR REPLACE FUNCTION hourvia_is_verified_platform_candidate(candidate uuid) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, public, pg_temp AS $$
  SELECT EXISTS (
    SELECT 1 FROM workspace_members m
    WHERE m.auth_user_id = candidate AND m.email = 'livingitsolutions@gmail.com'
      AND m.organization_id = '5adff49b-11d5-4b45-bb4f-2f76cfcca0c6'::uuid AND m.workspace_id = 'thrivesource'
      AND m.status = 'active' AND m.activated_at IS NOT NULL);
$$;

-- 8. Privileges ------------------------------------------------------------------------------------------------------------
REVOKE ALL ON organization_seat_entitlements FROM PUBLIC;
REVOKE ALL ON FUNCTION hourvia_guard_seat_entitlement() FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'netlifydb_readonly') THEN
    REVOKE ALL ON organization_seat_entitlements FROM netlifydb_readonly;
    REVOKE ALL ON FUNCTION hourvia_guard_seat_entitlement() FROM netlifydb_readonly;
  END IF;
END
$$;
REVOKE ALL ON organization_seat_entitlements FROM hourvia_auth_runtime;
GRANT SELECT (organization_id, plan, seat_limit, billing_expires_at) ON organization_seat_entitlements TO hourvia_auth_runtime;
-- Explicit organization on INSERT only. UPDATE of organization_id is never granted, and the guards make it immutable.
GRANT INSERT (organization_id) ON workspace_members, workspace_invitations, auth_sessions, auth_audit_events TO hourvia_auth_runtime;

-- 9. Self-check: any surprise aborts this migration (and the deploy) --------------------------------------------------------
DO $$
DECLARE
  ts constant uuid := '5adff49b-11d5-4b45-bb4f-2f76cfcca0c6';
  r record;
  t text;
  grantees text[] := ARRAY['public'];
BEGIN
  -- 9a. Exactly ThriveSource, unchanged, with its unlimited internal entitlement.
  IF (SELECT count(*) FROM organizations) <> 1
     OR NOT EXISTS (SELECT 1 FROM organizations WHERE id = ts AND slug = 'thrivesource' AND kind = 'internal' AND status = 'active')
     OR (SELECT count(*) FROM organization_seat_entitlements) <> 1
     OR NOT EXISTS (SELECT 1 FROM organization_seat_entitlements WHERE organization_id = ts AND plan = 'internal_unlimited'
                    AND seat_limit IS NULL AND billing_expires_at IS NULL) THEN
    RAISE EXCEPTION 'self-check failed: ThriveSource or its internal unlimited entitlement is not in the expected state';
  END IF;

  -- 9b. Every pre-existing row is preserved byte-for-byte.
  FOR r IN
    SELECT b.t, b.n = c.n AND b.h = c.h AS same FROM hourvia_m8_baseline b JOIN (
      SELECT 'workspace_members' AS t, count(*) AS n, md5(coalesce(string_agg(md5(row(m.*)::text), '' ORDER BY id), '')) AS h FROM public.workspace_members m
      UNION ALL SELECT 'workspace_invitations', count(*), md5(coalesce(string_agg(md5(row(i.*)::text), '' ORDER BY id), '')) FROM public.workspace_invitations i
      UNION ALL SELECT 'manager_assignments', count(*), md5(coalesce(string_agg(md5(row(a.*)::text), '' ORDER BY manager_member_id, contractor_member_id), '')) FROM public.manager_assignments a
      UNION ALL SELECT 'auth_sessions', count(*), md5(coalesce(string_agg(md5(row(s.*)::text), '' ORDER BY id), '')) FROM public.auth_sessions s
      UNION ALL SELECT 'auth_audit_events', count(*), md5(coalesce(string_agg(md5(row(e.*)::text), '' ORDER BY id), '')) FROM public.auth_audit_events e
      UNION ALL SELECT 'auth_rate_limits', count(*), md5(coalesce(string_agg(md5(row(rl.*)::text), '' ORDER BY bucket, window_start), '')) FROM public.auth_rate_limits rl
      UNION ALL SELECT 'platform_privileges', count(*), md5(coalesce(string_agg(md5(row(p.*)::text), '' ORDER BY id), '')) FROM public.platform_privileges p
      UNION ALL SELECT 'platform_super_admin_designation', count(*), md5(coalesce(string_agg(md5(row(d.*)::text), ''), '')) FROM public.platform_super_admin_designation d
      UNION ALL SELECT 'platform_audit_events', count(*), md5(coalesce(string_agg(md5(row(x.*)::text), '' ORDER BY id), '')) FROM public.platform_audit_events x
      UNION ALL SELECT 'organizations', count(*), md5(coalesce(string_agg(md5(row(o.id, o.slug, o.name, o.kind, o.status, o.created_at, o.created_by_auth_user_id, o.suspended_at, o.suspended_reason)::text), '' ORDER BY id), '')) FROM public.organizations o
    ) c ON c.t = b.t
  LOOP
    IF NOT r.same THEN
      RAISE EXCEPTION 'self-check failed: existing rows of % changed during M8', r.t;
    END IF;
  END LOOP;
  IF (SELECT count(*) FROM hourvia_m8_baseline) <> 10 THEN
    RAISE EXCEPTION 'self-check failed: preservation baseline is incomplete';
  END IF;

  -- 9c. New constraints exist and are validated; the relaxed ones are gone; M7 tenant constraints are still present.
  IF (SELECT count(*) FROM pg_constraint WHERE convalidated AND conname IN (
        'organizations_thrivesource_identity', 'organizations_internal_is_thrivesource', 'organizations_updated_after_creation',
        'organizations_id_slug_key', 'organizations_id_kind_key', 'workspace_members_organization_workspace_fk',
        'workspace_invitations_organization_workspace_fk', 'manager_assignments_organization_workspace_fk',
        'auth_audit_events_organization_workspace_fk', 'workspace_members_organization_auth_user_key', 'workspace_members_status_check',
        'workspace_members_suspended_was_active', 'organization_seat_entitlements_organization_fk',
        'organization_seat_entitlements_limit_matches_plan', 'organization_seat_entitlements_internal_unlimited',
        'organization_seat_entitlements_internal_no_billing', 'organization_seat_entitlements_updated_after_creation')) <> 17 THEN
    RAISE EXCEPTION 'self-check failed: an M8 constraint is missing or not validated';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname IN ('organizations_single_tenant_m7', 'workspace_members_auth_user_id_key',
        'workspace_members_workspace_id_check', 'workspace_invitations_workspace_id_check', 'manager_assignments_workspace_id_check',
        'auth_audit_events_workspace_id_check')) THEN
    RAISE EXCEPTION 'self-check failed: a single-organization constraint was not removed';
  END IF;
  IF (SELECT count(*) FROM pg_constraint WHERE convalidated AND conname IN (
        'workspace_members_organization_member_key', 'workspace_invitations_member_org_fk', 'workspace_invitations_invited_by_org_fk',
        'manager_assignments_manager_org_fk', 'manager_assignments_contractor_org_fk', 'manager_assignments_created_by_org_fk',
        'auth_sessions_member_org_fk', 'auth_sessions_revoked_by_org_fk', 'auth_audit_events_actor_org_fk', 'auth_audit_events_subject_org_fk',
        'workspace_members_role_changed_by_org_fk', 'workspace_members_disabled_by_org_fk', 'workspace_members_role_check',
        'workspace_invitations_role_check', 'workspace_invitations_no_super_admin', 'workspace_members_workspace_id_email_key')) <> 16 THEN
    RAISE EXCEPTION 'self-check failed: an M7 tenant, role or uniqueness constraint is missing';
  END IF;

  -- 9d. RLS stays off; every guard and audit trigger is present and enabled.
  IF EXISTS (SELECT 1 FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relrowsecurity) THEN
    RAISE EXCEPTION 'self-check failed: row-level security must stay disabled in M8';
  END IF;
  IF (SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled = 'O' AND tgname IN
       ('workspace_members_guard', 'workspace_members_guard_insert', 'workspace_members_audit', 'workspace_invitations_guard',
        'auth_sessions_guard', 'auth_sessions_revocation_audit', 'auth_audit_events_no_update_delete', 'auth_audit_events_no_truncate',
        'platform_audit_events_no_update_delete', 'platform_audit_events_no_truncate', 'platform_privileges_guard',
        'platform_privileges_audit', 'platform_privileges_no_truncate', 'platform_super_admin_designation_guard',
        'platform_super_admin_designation_audit', 'platform_super_admin_designation_no_truncate',
        'organizations_guard', 'organizations_no_truncate', 'organization_seat_entitlements_guard',
        'organization_seat_entitlements_no_truncate')) <> 20 THEN
    RAISE EXCEPTION 'self-check failed: guard or audit triggers are missing or disabled';
  END IF;

  -- 9e. Functions: the 16 M7 functions plus hourvia_guard_seat_entitlement; pinned; SECURITY DEFINER and EXECUTE unchanged.
  IF (SELECT count(*) FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace AND p.proname LIKE 'hourvia\_%') <> 17 THEN
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

  -- 9f. Entitlements: never readable by PUBLIC or netlifydb_readonly; the runtime reads four columns and writes nothing.
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'netlifydb_readonly') THEN
    grantees := array_append(grantees, 'netlifydb_readonly');
  END IF;
  FOREACH t IN ARRAY grantees LOOP
    IF has_table_privilege(t, 'public.organization_seat_entitlements', 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN')
       OR has_any_column_privilege(t, 'public.organization_seat_entitlements', 'SELECT, INSERT, UPDATE, REFERENCES') THEN
      RAISE EXCEPTION 'self-check failed: % has access to organization_seat_entitlements', t;
    END IF;
  END LOOP;
  IF has_table_privilege('hourvia_auth_runtime', 'public.organization_seat_entitlements', 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN')
     OR has_any_column_privilege('hourvia_auth_runtime', 'public.organization_seat_entitlements', 'INSERT, UPDATE, REFERENCES')
     OR has_column_privilege('hourvia_auth_runtime', 'public.organization_seat_entitlements', 'approval_ref', 'SELECT')
     OR NOT has_column_privilege('hourvia_auth_runtime', 'public.organization_seat_entitlements', 'seat_limit', 'SELECT') THEN
    RAISE EXCEPTION 'self-check failed: unexpected hourvia_auth_runtime privileges on organization_seat_entitlements';
  END IF;

  -- 9g. organization_id: INSERT on exactly four tables, UPDATE nowhere; organizations stay read-only for the runtime.
  FOREACH t IN ARRAY ARRAY['workspace_members', 'workspace_invitations', 'manager_assignments', 'auth_sessions', 'auth_audit_events'] LOOP
    IF has_column_privilege('hourvia_auth_runtime', 'public.' || t, 'organization_id', 'UPDATE')
       OR has_column_privilege('hourvia_auth_runtime', 'public.' || t, 'organization_id', 'INSERT') <> (t <> 'manager_assignments')
       OR has_table_privilege('hourvia_auth_runtime', 'public.' || t, 'DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN') THEN
      RAISE EXCEPTION 'self-check failed: unexpected hourvia_auth_runtime organization_id privilege on %', t;
    END IF;
  END LOOP;
  IF has_table_privilege('hourvia_auth_runtime', 'public.organizations', 'INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN')
     OR has_any_column_privilege('hourvia_auth_runtime', 'public.organizations', 'INSERT, UPDATE, REFERENCES')
     OR has_any_column_privilege('hourvia_auth_runtime', 'public.auth_audit_events', 'SELECT, UPDATE')
     OR has_any_column_privilege('hourvia_auth_runtime', 'public.manager_assignments', 'INSERT, UPDATE')
     OR has_column_privilege('hourvia_auth_runtime', 'public.workspace_members', 'approval_authorized', 'UPDATE')
     OR has_column_privilege('hourvia_auth_runtime', 'public.workspace_members', 'workspace_id', 'UPDATE')
     OR has_schema_privilege('hourvia_auth_runtime', 'public', 'CREATE')
     OR has_database_privilege('hourvia_auth_runtime', current_database(), 'CREATE') THEN
    RAISE EXCEPTION 'self-check failed: an earlier hourvia_auth_runtime boundary changed';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a
    WHERE c.oid = 'public.organization_seat_entitlements'::regclass AND a.grantee NOT IN (c.relowner, 'hourvia_auth_runtime'::regrole)
    UNION ALL
    SELECT 1 FROM pg_attribute at CROSS JOIN LATERAL aclexplode(at.attacl) a
    WHERE at.attrelid = 'public.organization_seat_entitlements'::regclass
      AND a.grantee NOT IN ((SELECT relowner FROM pg_class WHERE oid = 'public.organization_seat_entitlements'::regclass), 'hourvia_auth_runtime'::regrole)
  ) THEN
    RAISE EXCEPTION 'self-check failed: an unexpected role is granted access to organization_seat_entitlements';
  END IF;
END
$$;

DROP TABLE pg_temp.hourvia_m8_baseline;
