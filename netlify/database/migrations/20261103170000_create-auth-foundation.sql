-- Hourvia Sprint 1.7 — authentication foundation (PROPOSAL, NOT AUTO-APPLIED)
--
-- Staged deliberately outside netlify/database/migrations so Netlify does not apply it to any
-- preview or production database. An operator promotes it only after review, together with
-- 002_restricted_auth_runtime_role.sql as the next-numbered migration in the same pull request. Until then
-- the auth functions fail closed (HTTP 503) because these tables do not exist.
--
-- Identity mapping: Supabase Auth owns credentials (auth_user_id). Hourvia owns workspace
-- membership, role, status, assignments, sessions and audit. Roles are NEVER read from Supabase
-- user_metadata or browser input.
--
-- Sprint 1.7 readiness revision: tighter row constraints, and the platform's default
-- "GRANT SELECT ON TABLES TO netlifydb_readonly" is revoked from every table in this file before it
-- commits, so the read-only (CLI/dashboard) credential never sees session hashes, invitations, members,
-- rate-limit buckets or audit records — even if 002 later fails.

CREATE TABLE workspace_members (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id        text NOT NULL CHECK (workspace_id = 'thrivesource'),
  auth_user_id        uuid UNIQUE,
  email               text NOT NULL CHECK (email = lower(email) AND length(email) BETWEEN 3 AND 320),
  display_name        text NOT NULL DEFAULT '' CHECK (length(display_name) <= 120),
  role                text NOT NULL CHECK (role IN ('workspace_admin', 'workspace_manager', 'contractor')),
  status              text NOT NULL CHECK (status IN ('invited', 'active', 'disabled')),
  approval_authorized boolean NOT NULL DEFAULT false,
  created_at          timestamptz NOT NULL DEFAULT now(),
  activated_at        timestamptz,
  disabled_at         timestamptz,
  disabled_by         uuid REFERENCES workspace_members(id),
  UNIQUE (workspace_id, email),
  CHECK (approval_authorized = false OR role = 'workspace_manager'),
  CHECK (status <> 'active' OR (auth_user_id IS NOT NULL AND activated_at IS NOT NULL)),
  CHECK (status <> 'disabled' OR disabled_at IS NOT NULL),
  CHECK (disabled_by IS NULL OR disabled_by <> id)
);

CREATE TABLE manager_assignments (
  workspace_id         text NOT NULL CHECK (workspace_id = 'thrivesource'),
  manager_member_id    uuid NOT NULL REFERENCES workspace_members(id),
  contractor_member_id uuid NOT NULL REFERENCES workspace_members(id),
  created_at           timestamptz NOT NULL DEFAULT now(),
  created_by           uuid REFERENCES workspace_members(id),
  PRIMARY KEY (manager_member_id, contractor_member_id),
  CHECK (manager_member_id <> contractor_member_id)
);

CREATE TABLE workspace_invitations (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id         text NOT NULL CHECK (workspace_id = 'thrivesource'),
  member_id            uuid NOT NULL REFERENCES workspace_members(id),
  email                text NOT NULL CHECK (email = lower(email) AND length(email) BETWEEN 3 AND 320),
  role                 text NOT NULL CHECK (role IN ('workspace_admin', 'workspace_manager', 'contractor')),
  status               text NOT NULL CHECK (status IN ('pending', 'accepted', 'revoked')),
  invited_by_member_id uuid REFERENCES workspace_members(id), -- NULL only for the reviewed first-admin bootstrap
  created_at           timestamptz NOT NULL DEFAULT now(),
  expires_at           timestamptz NOT NULL,
  accepted_at          timestamptz,
  CHECK (expires_at > created_at),
  CHECK ((status = 'accepted') = (accepted_at IS NOT NULL))
);
CREATE UNIQUE INDEX workspace_invitations_one_pending ON workspace_invitations (member_id) WHERE status = 'pending';

-- Opaque server sessions. Only a SHA-256 hash of the cookie token is stored.
CREATE TABLE auth_sessions (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash          text NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  member_id           uuid NOT NULL REFERENCES workspace_members(id),
  created_at          timestamptz NOT NULL,
  last_seen_at        timestamptz NOT NULL,
  idle_expires_at     timestamptz NOT NULL,
  absolute_expires_at timestamptz NOT NULL,
  revoked_at          timestamptz,
  revoked_reason      text CHECK (length(revoked_reason) BETWEEN 1 AND 64),
  CHECK (idle_expires_at <= absolute_expires_at),
  CHECK (absolute_expires_at > created_at),
  CHECK (last_seen_at >= created_at),
  CHECK (revoked_reason IS NULL OR revoked_at IS NOT NULL)
);
CREATE INDEX auth_sessions_member_active ON auth_sessions (member_id) WHERE revoked_at IS NULL;

-- Append-only audit trail. Email and IP values are stored only as keyed HMACs.
CREATE TABLE auth_audit_events (
  id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  workspace_id      text NOT NULL CHECK (workspace_id = 'thrivesource'),
  occurred_at       timestamptz NOT NULL,
  event_type        text NOT NULL CHECK (event_type ~ '^[a-z_]{1,64}$'),
  outcome           text NOT NULL CHECK (outcome IN ('success', 'denied', 'error')),
  actor_member_id   uuid REFERENCES workspace_members(id),
  subject_member_id uuid REFERENCES workspace_members(id),
  email_hmac        text CHECK (email_hmac ~ '^[0-9a-f]{64}$'),
  ip_hmac           text CHECK (ip_hmac ~ '^[0-9a-f]{64}$'),
  details           jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details) = 'object' AND pg_column_size(details) <= 4096)
);
CREATE INDEX auth_audit_events_occurred ON auth_audit_events (occurred_at);

CREATE FUNCTION hourvia_reject_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'auth_audit_events is append-only';
END
$$;
CREATE TRIGGER auth_audit_events_no_update_delete BEFORE UPDATE OR DELETE ON auth_audit_events
  FOR EACH ROW EXECUTE FUNCTION hourvia_reject_audit_mutation();
CREATE TRIGGER auth_audit_events_no_truncate BEFORE TRUNCATE ON auth_audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION hourvia_reject_audit_mutation();

-- Fixed-window counters keyed by HMAC(bucket input). No raw email or IP is stored.
CREATE TABLE auth_rate_limits (
  bucket       text NOT NULL CHECK (bucket ~ '^[a-z_]{1,64}:[0-9a-f]{64}$'),
  window_start timestamptz NOT NULL,
  hits         integer NOT NULL CHECK (hits > 0),
  PRIMARY KEY (bucket, window_start)
);
CREATE INDEX auth_rate_limits_window ON auth_rate_limits (window_start);

-- Privilege hardening. Netlify Database ships "ALTER DEFAULT PRIVILEGES FOR ROLE netlifydb_owner IN SCHEMA
-- public GRANT SELECT ON TABLES TO netlifydb_readonly", so every table above was readable by the read-only
-- credential the moment it was created. Revoke it here, in the same transaction, and from PUBLIC too.
REVOKE ALL ON workspace_members, manager_assignments, workspace_invitations, auth_sessions, auth_audit_events, auth_rate_limits FROM PUBLIC;
REVOKE ALL ON SEQUENCE auth_audit_events_id_seq FROM PUBLIC;
REVOKE ALL ON FUNCTION hourvia_reject_audit_mutation() FROM PUBLIC;
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'netlifydb_readonly') THEN
    REVOKE ALL ON workspace_members, manager_assignments, workspace_invitations, auth_sessions, auth_audit_events, auth_rate_limits FROM netlifydb_readonly;
    REVOKE ALL ON SEQUENCE auth_audit_events_id_seq FROM netlifydb_readonly;
  END IF;
END
$$;
