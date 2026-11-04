# Hourvia SaaS and PWA architecture (design only — not implemented)

Status: approved direction from Sprint 1.8A. Nothing here exists in code or schema yet. Each part needs its own reviewed migration and sprint.

## 1. Multi-tenant organizations and deny-by-default isolation

- **Organizations table.** `organizations (id text PRIMARY KEY, name text, kind text CHECK (kind IN ('internal','customer')), status text CHECK (status IN ('active','suspended')), created_at)`. The first row is `('thrivesource', 'ThriveSource / Exordiom', 'internal', 'active')`. Keeping the ID `thrivesource` means no existing row changes; the display name needs confirming.
- **Schema.** Every `CHECK (workspace_id = 'thrivesource')` becomes a foreign key to `organizations(id)`. The column keeps its name, so existing rows and indexes stay valid.
- **Organization ID comes from the session, never from input.** It is taken from the authenticated membership. API paths that carry an organization ID must match it, or the request gets a 404. That avoids confirming that another tenant exists.
- **Every query is organization-scoped.** Every store query takes `organizationId` as a required parameter and filters on it. A static test fails on any SQL touching tenant tables without a `workspace_id = $n` predicate.
- **Cross-tenant access** is never implicit, including for platform privileges. Support access would be a future explicit grant: time-boxed, scoped to one organization, read-only by default, separately approved and audited in `platform_audit_events`.
- **Future organization roles:**
  - **Owner:** manages Administrators and billing. There must always be at least one active Owner, enforced by a trigger that refuses to remove the last one.
  - **Administrator:** manages Managers and Contractors.
  - **Manager:** reviews assigned Contractors.
  - **Contractor:** works with own records.

  Until Owner exists, Administrator management in ThriveSource uses Administrator plus Platform Super Admin.

## 2. Seat entitlements

- **Entitlements table.** `organization_entitlements (organization_id PRIMARY KEY REFERENCES organizations, plan_code text, seat_limit integer NULL CHECK (seat_limit > 0), subscription_expires_at timestamptz NULL)`. NULL means unlimited seats or no expiry.
- **ThriveSource / Exordiom:** `plan_code 'internal'`, `seat_limit NULL`, `subscription_expires_at NULL`. Unlimited seats, never expires.
- **Future SaaS plans:** a finite `seat_limit` and an expiry, configured only through the platform API by a platform privilege holder, and audited.
- **What counts as a seat:** every membership that is `invited` or `active`. Disabled members and revoked invitations free their seat.
- **Concurrency-safe reservation:**
  - A counter row, `organization_seat_usage (organization_id PRIMARY KEY, used integer NOT NULL CHECK (used >= 0))`, is maintained only by a trigger on membership insert and status change.
  - An invitation reserves its seat inside the invitation transaction with one conditional statement:

    ```sql
    UPDATE organization_seat_usage u SET used = u.used + 1
    FROM organization_entitlements e
    WHERE u.organization_id = $1 AND e.organization_id = $1
      AND (e.seat_limit IS NULL OR u.used < e.seat_limit)
      AND (e.subscription_expires_at IS NULL OR e.subscription_expires_at > now())
    RETURNING u.used;
    ```

  - Zero rows means `402 seat_limit_reached` (or `subscription_expired`), and the whole transaction rolls back.
  - Because this is one row update, concurrent invitations serialize on the row lock and can't exceed the limit. Tests for this need a multi-connection Postgres, because PGlite is single-connection.
  - A reconciliation check compares `used` with the live count and alerts on any mismatch.
  - Lowering a limit below current usage only blocks new reservations; nobody loses access automatically.

## 3. Installable, online-only PWA

- **Install.** A web app manifest (name, icons, `display: standalone`, `start_url: /dashboard`). The service worker caches only the versioned static app shell and fonts.
- **Network rules.** `/api/*` and HTML navigations to authenticated data are always network-only and never cached. There is no Background Sync, no IndexedDB or localStorage mutation queue, and no optimistic writes.
- **Offline.** Every action that changes data is disabled, with an "Offline — reconnect to continue" banner. A request that fails is shown as failed, never queued or retried later.
- **Sessions.** The HttpOnly `__Host-` session cookie, SameSite=Strict and the CSP work unchanged in standalone mode. A service worker update never serves a stale shell against a newer API without a version check.

## 4. Server-authoritative timers

- **Server is the clock.** The server owns all time: `shift_events (shift_id, type, server_time, actor, reason)` is append-only, and elapsed time is always derived from server events. The client only shows a projection of server state.
- **Heartbeat.** While a timer runs, the client sends an authenticated heartbeat about every 30 seconds. The server keeps a lease.
- **Connectivity pause.** If the lease expires, the server records `paused_connectivity` at the last confirmed server time. The gap is never counted as work.
- **Auto-resume, only after authenticated reconnection.** When the client reconnects, the server records `resumed_connectivity` only if the request carries a valid, unexpired session for the same member and the shift is still open. If the 30-minute idle timeout passed, the member signs in first, and the timer stays paused until then. Auto-resume never happens on the client.
- **Manual pauses never auto-resume.** Break, Lunch and other manual pauses (`paused_manual`) resume only when the member acts explicitly. A connectivity loss during a manual pause doesn't change it.
- **Audit and integrity.**
  - Every transition is audited with server time.
  - Clients can't submit timestamps.
  - Corrections go through the existing Manual Time Request approval flow.
  - Long connectivity gaps are flagged for review.
