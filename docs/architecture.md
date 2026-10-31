# Hourvia foundation

Hourvia by Living IT Solutions serves the single ThriveSource workspace. The intended domain is hourvia.livingitsolutions.com; no domain or DNS configuration was changed.

## Boundaries

- `src/presentation`: React views, responsive styles, login validation feedback, routing guards, and permission-filtered navigation.
- `src/application`: authentication orchestration, safe return destinations, and the central screen registry. Authentication is dependency-injected so the infrastructure adapter can be replaced without rewriting views.
- `src/domain`: authentication, authorization, shifts, timesheets, approvals, and cutoff interfaces; Zod input schemas; centralized permission policy. No framework or database dependency.
- `src/infrastructure`: deliberately unconfigured authentication adapter. Session resolution returns null; sign-in always fails. There are no hardcoded credentials, browser storage sessions, network credential submissions, or role switches.

`AuthProvider` accepts an Authentication implementation. The production entry point only supplies `unconfiguredAuth`. Test-only service implementations exercise authenticated behavior and never ship through the entry point. No identity provider was enabled in Sprint 0. Use @netlify/identity when integrating Netlify Identity in Sprint 1; require invitation-only registration and server-controlled workspace membership and roles before enabling access.

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

Vite emits static assets to `dist`. Netlify uses the checked-in build command and SPA fallback. Future server endpoints belong in `netlify/functions`. No endpoints, tables, migrations, credentials, or persisted records exist in this sprint. Use Netlify Database managed PostgreSQL with @netlify/database and Drizzle in Sprint 1; define the eventual schema in `db/schema.ts` only after the domain model and identity mapping are approved. Do not introduce browser persistence or an external database for application records.

## Security and release limits

Identity and role security are not operational until tested against a real provider and backend. No production deployment or DNS change was performed. The login form validates locally and returns an unavailable message without sending credentials. Password recovery likewise reports that it is not connected. No signup, preview login, seeded accounts, or permissive fallback exists.

Google Fonts supplies DM Sans and Manrope; the UI falls back to sans-serif offline. Self-host fonts if external font requests are unsuitable for the internal workspace. Responsive breakpoints and reduced-motion support are implemented; real-browser visual and assistive-technology checks remain recommended before release.
