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

Vite emits static assets to `dist`. Netlify uses the checked-in build command and SPA fallback. Future server endpoints belong in `netlify/functions`. Sprint 1.7 adds the auth function. Its tables are staged as an unapplied proposal in `db/proposals/sprint-1.7-auth`, and no migrations exist in `netlify/database/migrations`. Use Netlify Database managed PostgreSQL with @netlify/database and Drizzle in Sprint 1; define the eventual schema in `db/schema.ts` only after the domain model and identity mapping are approved. Do not introduce browser persistence or an external database for application records.

## Security and release limits

Identity and role security are not operational until tested against a real provider and backend. No production deployment or DNS change was performed. The login form validates locally and returns an unavailable message without sending credentials. Password recovery likewise reports that it is not connected. No signup, preview login, seeded accounts, or permissive fallback exists.

Google Fonts supplies DM Sans and Manrope; the UI falls back to sans-serif offline. Self-host fonts if external font requests are unsuitable for the internal workspace. Responsive breakpoints and reduced-motion support are implemented; real-browser visual and assistive-technology checks remain recommended before release.

## Organization foundation (Sprint 2.0B, migration M7)

Migration `20261104170000_organizations-expand.sql` (M7) is the additive "expand" step of the Sprint 2.0A multi-tenant design. It runs on the `feature/hourvia-2.0-tenancy` integration track and must not reach `main` until the Sprint 1.9G promotion gates pass. Merging to `main` applies migrations to production.

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
- The deployed application (799f042) never names `organization_id`, so it stays compatible with M7. Rolling the application back is safe while the defaults remain.

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
