# Hourvia foundation

Hourvia by Living IT Solutions serves the single ThriveSource workspace. The intended domain is hourvia.livingitsolutions.com; no domain or DNS configuration was changed.

## Boundaries

- `src/presentation`: React views, responsive styles, login validation feedback, routing guards, and permission-filtered navigation.
- `src/application`: authentication orchestration, safe return destinations, and the central screen registry. Authentication is dependency-injected so the infrastructure adapter can be replaced without rewriting views.
- `src/domain`: authentication, authorization, shifts, timesheets, approvals, and cutoff interfaces; Zod input schemas; centralized permission policy. No framework or database dependency.
- `src/infrastructure`: deliberately unconfigured authentication adapter. Session resolution returns null; sign-in always fails. There are no hardcoded credentials, browser storage sessions, network credential submissions, or role switches.

`AuthProvider` accepts an Authentication implementation. Since Sprint 1.7 the entry point supplies `serverSessionAuth`, a cookie-only adapter for the `/api/auth/*` Netlify Function. That function uses Supabase Auth (with Resend SMTP) as the credential verifier and keeps sessions, membership, roles, and audit in Netlify Database. The plan to use Netlify Identity is superseded. See [authentication.md](authentication.md). `unconfiguredAuth` remains for tests.

The UI guard is a presentation boundary, not operational authorization. Future Netlify Functions must verify identity, load trusted workspace membership and assignments, and enforce `authorization.can` for every requested resource. Do not accept roles, assignments, or approval authority from browser input or user-editable metadata. Missing, invalid, expired, or unrecognized membership must fail closed. Database query predicates must enforce the same scope before pagination, aggregates, exports, or writes.

## Permission matrix

| Capability | Workspace Admin | Workspace Manager | Contractor |
| --- | --- | --- | --- |
| Dashboard | Workspace | Assigned scope | Own scope |
| Tracker, My DTR, My Timesheets, Manual Time Requests | Workspace management / own screen access | No | Own resources only |
| Contractor directory and records | All workspace contractors | Assigned contractors only | No |
| Approval Queue | Workspace | Assigned contractors plus explicit approval authority | No |
| Cutoff Review and Reports | Workspace | Assigned contractors only | No |
| Workspace Settings | Workspace | No | No |

Admins have all defined permissions inside ThriveSource. Managers need an assigned contractor resource on every records, reports, review, and directory check; unscoped manager checks deny. Manager approval additionally requires `approvalAuthorized`. Contractors require their own ID. Navigation uses the same policy to determine whether at least one allowed resource exists; this does not grant unscoped API access. A manager with no assignments sees Dashboard only. Dashboard data must be scoped server-side when implemented.

## Routes

`/` resolves to `/login` or `/dashboard`. `/login` is public and authenticated visitors go to the safe intended destination (or `/dashboard`). Protected route redirects preserve pathname, query, and hash in `next`. Only local absolute paths are allowed; external URLs, backslashes, control characters, and login loops are rejected.

| Path | Screen |
| --- | --- |
| /dashboard | Dashboard |
| /tracker | Time Tracker |
| /my-dtr | My DTR |
| /my-timesheets | My Timesheets |
| /manual-requests | Manual Time Requests |
| /contractors | Contractor Directory |
| /contractor-records | Contractor DTR and Timesheets |
| /approvals | Approval Queue |
| /cutoff-review | Cutoff Review |
| /reports | Reports |
| /settings | Workspace Settings |

All workspace screens are explicit future-sprint placeholders with role guards. Unauthorized direct links display an access-restricted state; unknown paths display a public 404. Netlify's SPA rewrite serves deep links; the React 404 is rendered with the SPA response's HTTP 200 status.

## Future deployment and storage

Vite emits static assets to `dist`. Netlify uses the checked-in build command and SPA fallback. Future server endpoints belong in `netlify/functions`. Sprint 1.7 added the auth function. Its schema was promoted from `db/proposals/sprint-1.7-auth` into `netlify/database/migrations`, which now holds the seven immutable migrations M1–M7 (see [operations status](operations-status.md) for digests and production evidence). Use Netlify Database managed PostgreSQL with @netlify/database and Drizzle in Sprint 1; define the eventual schema in `db/schema.ts` only after the domain model and identity mapping are approved. Do not introduce browser persistence or an external database for application records.

## Security and release limits

Identity and role security are not operational until tested against a real provider and backend. Production is deployed at https://hourvia.livingitsolutions.com with authentication fail-closed (503 `auth_unavailable`); see [production pre-launch safeguards](production-prelaunch.md). The login form validates locally and returns an unavailable message without sending credentials. Password recovery likewise reports that it is not connected. No signup, preview login, seeded accounts, or permissive fallback exists.

Google Fonts supplies DM Sans and Manrope; the UI falls back to sans-serif offline. Self-host fonts if external font requests are unsuitable for the internal workspace. Responsive breakpoints and reduced-motion support are implemented; real-browser visual and assistive-technology checks remain recommended before release.

## Organization foundation (Sprint 2.0B, migration M7)

Migration `20261104170000_organizations-expand.sql` (M7) is the additive "expand" step of the Sprint 2.0A multi-tenant design. It was originally planned for a separate `feature/hourvia-2.0-tenancy` track. It reached `main` through PR #15 (2026-11-04 15:24 UTC) and is part of the reviewed M1–M7 baseline. Merging to `main` applies migrations to production. The production ledger recorded M7 before that merge, by a source that no deploy records; see [operations status](operations-status.md). Its catalog in production is not yet independently verified.

**Stable organization identity.** These values are permanent. Never change or reuse them.

| Organization | UUID | Slug | Kind | Status |
|---|---|---|---|---|
| ThriveSource | `5adff49b-11d5-4b45-bb4f-2f76cfcca0c6` | `thrivesource` | internal | active |

The same UUID appears in three places: the migration (seed row and column default), the shared constant `THRIVESOURCE_ORGANIZATION_ID` in `src/domain/organization.ts`, and this document. A test asserts all three agree.

**What M7 adds**
- An `organizations` table with a UUID key, a unique slug, name, kind (`internal`/`customer`), status (`provisioning`/`active`/`suspended`/`closed`), creation time, creator identity, and suspension time and reason. The suspension columns are consistency-checked.
- On ThriveSource's seed row the creator is NULL, because the row was created by migration rather than by a person.
- `organization_id uuid NOT NULL DEFAULT '<ThriveSource>'` on `workspace_members`, `workspace_invitations`, `manager_assignments`, `auth_sessions` and `auth_audit_events`. A constant default is catalog-only: no rewrite, no UPDATE and no trigger, so audit rows are never touched.
- Foreign keys from every tenant table to `organizations`.
- Composite membership foreign keys on `(organization_id, <member column>)` → `workspace_members (organization_id, id)`. These cover invitations (member and inviter), sessions (member and revoker), assignments (manager, contractor and creator), audit (actor and subject), and members (role changer and disabler). A row therefore can't reference a member of another organization.
- Legacy bridge CHECKs: a `workspace_id = 'thrivesource'` row must belong to ThriveSource.
- `hourvia_guard_organization()`, with `search_path` pinned to `pg_catalog, public, pg_temp`. Organization id, slug, kind and creator are immutable. Organizations can't be deleted or truncated. The runtime role can't modify them.
- Precondition and self-check blocks. Before and after the migration they compare row counts and content fingerprints for every pre-existing tenant and audit table, and they check grants, triggers, functions and RLS.

**What M7 keeps, on purpose**
- Every single-organization constraint: `CHECK (workspace_id = 'thrivesource')`, the global `auth_user_id` uniqueness, the role vocabulary, all guards and both append-only audit triggers.
- A new `organizations_single_tenant_m7` CHECK that allows only ThriveSource.
- RLS stays disabled.
- The runtime role (`hourvia_auth_runtime`) gains exactly one grant: `SELECT (id, slug, name, kind, status) ON organizations`. It has no INSERT or UPDATE on any `organization_id` column, so application rows always take the ThriveSource default. Every other grant, function EXECUTE privilege and SECURITY DEFINER function is unchanged.
- The pre-M7 application (`799f042`) never names `organization_id`, so it stays code-compatible with M7. Republishing a pre-M7 deploy is still prohibited: its deploy no longer carries M7, and the platform reports a migration-history error (observed on deploy `6aeabf28` at 15:20–15:23 UTC). Roll back only to a deploy built from a commit that contains M1–M7.

**Application foundation** (ThriveSource-only behavior)
- `src/domain/organization.ts`: the branded `OrganizationId` (canonical lower-case UUID only), the `Organization` model, and the frozen, branded `OrganizationContext`. A context is built server-side from a membership row or the single supported organization, and never from request input. Unsupported, malformed or mismatched organizations are rejected.
- `server/auth/tenant-sql.ts`: the organization-scoped SQL wrapper. Every store statement must pass a static tenant-predicate check:
  - each tenant-table reference needs `<alias>.organization_id = $n`, and `organizations` needs `<alias>.id = $n`;
  - OR, schema-qualified references and any write of `organization_id` are refused;
  - INSERT, UPDATE and DELETE on `organizations` are refused;
  - at run time every `$n` must equal the context's organization;
  - default-derived INSERTs are accepted only in the ThriveSource context.

  The wrapper runs in addition to the existing statement policy, which is unchanged.
- `PostgresAuthStore` is bound to one `OrganizationContext`, which defaults to ThriveSource, and scopes every tenant query to it. Session resolution also requires session, member and organization to agree and the organization to be `active`. `AuthService` rejects a membership outside the store's context.

**Sprint 2.0C prerequisites found by M7 tests**
- `hourvia_audit_member_change` and `hourvia_audit_session_revocation` still write the default organization. A member of another organization would fail closed on the composite audit foreign key, so 2.0C must make them write `NEW.organization_id`.
- 2.0C must also grant the runtime explicit, checked `organization_id` INSERTs before dropping the defaults.

## Organization-first multi-tenancy (Sprint 3.0, M8 proposal — not applied)

Hourvia is organization-first. Every workspace belongs to an organization, and there are no personal workspaces. A solo consultant gets a single-member organization. Sprint 3.0 adds the backend contracts and the forward-only M8 proposal. **Production behaviour is unchanged:** the HTTP API, `AuthService` and runtime wiring stay ThriveSource-only, and every multi-organization path returns 503 `multi_organization_unavailable` until M8 is promoted.

- **M8 proposal:** `db/proposals/sprint-3.0/20261106120000_multi-organization-memberships.sql`. Its README covers dependencies, backfill, constraints, RLS and authorization implications, rollback limits and the promotion strategy. It is outside `netlify/database/migrations/`, so no environment applies it, and M1–M7 are byte-identical.
- **Global identity, per-organization memberships:** `UNIQUE (organization_id, auth_user_id)` replaces the global uniqueness. Each membership has its own role and its own status (`invited`, `active`, `suspended` (operator-only), or `disabled`, the removed state).
- **Server-authoritative context:** the context is derived from the session cookie: `auth_sessions` → membership → organization. `organizationContextForVerifiedMembership` (`src/domain/organization.ts`) builds it only from server-read rows, only for an active organization, and only with a `MultiOrganizationCapability`. Production never holds a capability in Sprint 3.0, and only offline tests mint one (a source scan enforces this).
- **Switching contract:** `OrganizationAccessService` (`server/auth/organization-service.ts`) lists, selects, revalidates, reports seats and authorizes. Selection matches the requested id against the identity's own memberships. Non-member, suspended, removed, malformed and inactive targets all give the same 403. A successful switch revokes the old session and issues a new one bound to the target membership. No HTTP route is registered.
- **Identity directory:** `server/auth/organization-directory.ts` holds the only cross-organization reads. There are two fixed, allowlisted statements, and the identity is taken from the session row, never from input.
- **Tenant isolation:**
  - `tenant-sql.ts` now also covers `organization_seat_entitlements` and the reserved future tables `projects`, `time_entries`, `timesheets`, `clients`, `invoices` and `billing_rates`.
  - Explicit `organization_id` INSERTs are accepted only outside ThriveSource, as one VALUES row with a bare parameter equal to the context. The ThriveSource context keeps the Sprint 2.0B rule.
  - `src/domain/tenancy.ts` provides `assertTenantResource`, `scopeTenantResources` and `organizationCan`. The last applies the unchanged role rules after a strict same-organization check.
- **Seats:** `organization_seat_entitlements` (M8). Active members consume seats, pending unexpired invitations reserve them, and suspended or disabled members don't count. Organizations are counted independently. M8 guards enforce the limit in the database. ThriveSource is `internal_unlimited`, and only the internal kind (ThriveSource) can hold that plan.
- **Platform Super Admin:** unchanged and still single. M8 restricts the platform candidate to the designated mailbox's ThriveSource membership. Organization roles never yield a platform privilege, and the platform console still needs the holder's ThriveSource session.

**Sprint 3.0.1 hardening (independent review findings)**
- **Switching (H2, H3):** `selectOrganization` runs one transaction. `PostgresAuthStore.consumeSession` revokes the source session only if it is still valid and still the caller's member's; only that single winner creates the replacement, which keeps the source session's absolute expiry. Concurrent switches, replays, logout and administrator revocation leave no replacement; a failure rolls back both steps.
- **Platform authority (M1):** platform privileges count only in the ThriveSource context, in `OrganizationAccessService.principal`, in `organizationCan` and in M8's `hourvia_member_authority`.
- **Suspension (M2):** M8 revokes sessions when a member or organization is suspended (or closed), and refuses new sessions for inactive members or organizations.
- **Tenant SQL (M3):** outside ThriveSource the analyzer itself requires an explicit, single-row, bare-parameter `organization_id` bound to the context.
- **Isolation (M4):** M8's seat, session and suspension guards fail closed unless the transaction is `READ COMMITTED`.
- **Directory (L2):** memberships of closed or provisioning organizations are not listed.

**Sprint 3.0.2 M8 security closure (independent audit findings)**
- **Disabled-member sessions (G1):** `PostgresAuthStore.disableMemberAndRevokeSessions` locks the member row, disables the member, revokes every unrevoked session (attributed to the Administrator) and revokes pending invitations in **one** transaction (statement order corrected in Sprint 3.0.3, below); `AuthService.disableMember` uses it. Previously the disable and the session revocation were separate transactions, so a failure between them left live session rows that an operator reinstatement would revive. This works on today's M7 schema. In M8, the member status trigger also revokes on every transition into `disabled` (attributed to `disabled_by`), exactly like `suspended`, and sweeps anything still unrevoked when a member leaves `disabled` or `suspended`. The reinstatement procedure sweeps stale sessions before reactivating.
- **Session lifetime (G2):** M8's session insert guard bounds `created_at` by the database clock (`clock_timestamp()` + 2 minutes of skew), so a supplied future timestamp can no longer stretch the 24-hour cap. The absolute expiry is never later than database time + 24 h + 2 min.
- **Evidence:** `server/auth/m8-security-closure.test.ts` (offline). On disposable PostgreSQL 18, `scripts/rehearsal/platform-grant-rehearsal.sh [m7|m8]` (16 scenarios, now on M1–M7 and optionally M8) and `scripts/rehearsal/multi-organization-rehearsal.sh` (S1–S12, including deterministic switch/logout, switch/administrator revocation, organization suspension and disable/reinstatement interleavings, and, since Sprint 3.0.5, concurrent invitation acceptance and revocation).

**Sprint 3.0.3 post-merge hotfix (independent audit of Sprint 3.0.2)**
- **Disable/suspension deadlock (fixed):** Sprint 3.0.2 swept the member's session rows *before* updating the member. On M8 the member UPDATE fires the status trigger, which takes the exclusive `hourvia_sessions:<org>` lock. Organization suspension takes that lock first and then updates every session of the organization. Each transaction held what the other needed, and PostgreSQL aborted one with `deadlock detected`. The order is now: member row lock, member UPDATE (M8: the trigger takes the session lock and revokes), explicit session sweep, invitation revocation. That is the same order as suspension (session lock, then session rows), so the two serialize instead. `sessionsRevoked` counts the sessions revoked by the trigger as well as by the sweep, so it now also includes a session committed concurrently with the disable. Atomicity, attribution (`revoked_by_member_id` = the disabling Administrator) and rollback are unchanged.
- **Residual M7 stale-session race (open, mitigated):** on M7 (production today) the login reads the member and inserts its session as separate statements, and nothing in the database re-checks the member at insert. A login that read the member as `active` just before a disable committed can still insert a session afterwards. The disable's sweep can't see an uncommitted or not-yet-inserted row, so this happens even with the atomic Sprint 3.0.2/3.0.3 disable. It is not limited to disables from before Sprint 3.0.2, as previously documented. The row is unusable while the member is disabled, because session resolution requires `status = 'active'`, but it would become valid again if the member were re-enabled without a sweep. Mitigations: a repeated disable sweeps leftovers, and the mandatory reviewed procedure `db/operations/platform/reinstate-disabled-member.sql` revokes every unrevoked session in the same transaction before reactivating. **Never reinstate a member with a raw `UPDATE`.** Organization suspension on M7 also doesn't revoke sessions; they are refused only while the organization is not `active`.
- **M8 closes the race:** the `BEFORE INSERT` session guard takes the shared per-organization session lock and re-reads the member and organization, so a login racing a disable is either refused (disable first) or revoked by the disable's trigger (login first). Leaving `disabled` or `suspended` sweeps anything still unrevoked, so on M8 a raw reinstatement can't revive a session either. The procedure remains the reviewed path.
- **M8 self-checks (G1/G2):** M8 now aborts unless the member revocation trigger matches exactly (AFTER UPDATE OF status, row-level, enabled, the full WHEN clause covering every transition into and out of `suspended`/`disabled`). Its function must map each transition to its reason and attribution under the *exclusive* session lock, and the session insert guard must enforce the relative 24-hour cap and both database-clock bounds (`created_at` ≤ now + 2 min, absolute expiry ≤ now + 24 h 2 min). The insert/update triggers must be present, and `created_at`/`absolute_expires_at` must be immutable.
- **Evidence:** `scripts/rehearsal/disable-lock-order-rehearsal.sh` (disposable PostgreSQL 18, M7 and M8 templates). D0 reproduces the old deadlock. D1a/D1b/D1c cover disable racing suspension in both orders and inside the old window, on M7 and M8. L1/L2 cover login racing disable plus reviewed reinstatement on M7 and M8. Offline, `server/auth/m8-security-closure.test.ts` pins the statement order and applies ten weakened M8 variants, each of which the self-check rejects.
