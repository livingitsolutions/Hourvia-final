-- Hourvia Sprint 1.7 — authentication foundation (PROPOSAL, NOT AUTO-APPLIED)
--
-- Staged deliberately outside netlify/database/migrations so Netlify does not apply it to any
-- preview or production database. An operator promotes it only after review together with the
-- Sprint 1.6 restricted-role proposal (validated separately). Until then the auth functions fail
-- closed (HTTP 503) because these tables do not exist.
--
-- Identity mapping: Supabase Auth owns credentials (auth_user_id). Hourvia owns workspace
-- membership, role, status, assignments, sessions and audit. Roles are NEVER read from Supabase
-- user_metadata or browser input.

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
  CHECK (status <> 'active' OR auth_user_id IS NOT NULL)
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
  email                text NOT NULL CHECK (email = lower(email)),
  role                 text NOT NULL CHECK (role IN ('workspace_admin', 'workspace_manager', 'contractor')),
  status               text NOT NULL CHECK (status IN ('pending', 'accepted', 'revoked')),
  invited_by_member_id uuid REFERENCES workspace_members(id), -- NULL only for the reviewed first-admin bootstrap
  created_at           timestamptz NOT NULL DEFAULT now(),
  expires_at           timestamptz NOT NULL,
  accepted_at          timestamptz,
  CHECK (expires_at > created_at)
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
  revoked_reason      text,
  CHECK (idle_expires_at <= absolute_expires_at)
);
CREATE INDEX auth_sessions_member_active ON auth_sessions (member_id) WHERE revoked_at IS NULL;

-- Append-only audit trail. Email and IP values are stored only as keyed HMACs.
CREATE TABLE auth_audit_events (
  id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  workspace_id      text NOT NULL CHECK (workspace_id = 'thrivesource'),
  occurred_at       timestamptz NOT NULL,
  event_type        text NOT NULL,
  outcome           text NOT NULL CHECK (outcome IN ('success', 'denied', 'error')),
  actor_member_id   uuid REFERENCES workspace_members(id),
  subject_member_id uuid REFERENCES workspace_members(id),
  email_hmac        text,
  ip_hmac           text,
  details           jsonb NOT NULL DEFAULT '{}'::jsonb
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
  bucket       text NOT NULL,
  window_start timestamptz NOT NULL,
  hits         integer NOT NULL CHECK (hits > 0),
  PRIMARY KEY (bucket, window_start)
);
CREATE INDEX auth_rate_limits_window ON auth_rate_limits (window_start);
