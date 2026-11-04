# Hourvia Platform Super Admin privilege

**Status: implemented in development and preview only. Not applied to production, and not granted to anyone.**

This privilege replaces the withdrawn workspace role `super_admin`, which came from migration `20261104120000`. That migration is applied on the Agent Runner preview database branch and stays unchanged. Migration `20261104130000_platform-privileges-correction` corrects it, forward-only.

## 1. Model: two independent planes

| Plane | Where it is stored | Values | Who changes it |
| --- | --- | --- | --- |
| **Organization role** | `workspace_members.role`, one row per organization membership | `workspace_admin` (Administrator), `workspace_manager` (Manager), `contractor` (Contractor). Owner is designed for a later sprint. | The application, within the caller's authority (section 2) |
| **Platform privilege** | `platform_privileges`, keyed by Supabase Auth UID, not by membership | `platform_super_admin` | **Only** the approved operator procedures (section 4). The application can read it, never write it. |

The rules that connect the two planes:
- **No implication.** An organization role never implies a platform privilege, and a platform privilege never implies an organization role. Living IT Solutions keeps its ThriveSource `workspace_admin` membership, its member ID, sessions, login and history. The grant doesn't touch that row.
- **Eligibility.** A database trigger enforces who can hold the privilege. It must be:
  - the **designated** UID, which is written once and immutable afterwards;
  - and that UID must be bound to the **active, invitation-verified** membership of `livingitsolutions@gmail.com`.

  There can be at most one active holder.
- **No cross-organization data access.** Organization data permissions come only from the organization role. The platform privilege adds exactly one capability, `administrators.manage`, and only inside an organization where the holder is an **active Administrator**. A holder who is a Manager, or who isn't a member, manages nobody.
- **Principal.** The principal is `{ …, role, platformPrivileges: ['platform_super_admin'] | [] }`. It is rebuilt from the database on every request, so revoking the privilege takes effect on the next request.

## 2. Authorization matrix

The API is authoritative. The database triggers enforce the same rules again for the restricted runtime role.

| Action | Administrator + Platform Super Admin | Administrator | Manager | Contractor | Anonymous |
| --- | --- | --- | --- | --- | --- |
| List members, open Workspace Settings | ✅ | ✅ | 403 | 403 | 401 |
| Invite, change, disable or end the sessions of a Manager or Contractor | ✅ | ✅ | 403 | 403 | 401 |
| Invite an Administrator, promote to it, demote from it, disable one or end one's sessions | ✅ | 403 (database: `not authorized`) | 403 | 403 | 401 |
| Request `platform_super_admin` or `super_admin` through an invitation or role change | 400, audited | 400, audited | 403 | 403 | 401 |
| Grant or revoke a platform privilege | ✖ (operator procedure only) | ✖ | ✖ | ✖ | ✖ |
| Change own role or disable self | 403 / 409 | 403 / 409 | 403 | 403 | — |
| End own sessions | ✅ | ✅ | via logout | via logout | — |
| Organization time data | Per organization role | All in the organization | Assigned Contractors | Own | — |
| Another organization's data | ✖ | ✖ | ✖ | ✖ | ✖ |

## 3. Database enforcement (`20261104130000`)

- **Withdraws `super_admin`.** The migration drops the designated-email CHECK and the one-holder index, and restores the role CHECK to the three organization roles. It aborts if any `super_admin` row exists.
- **New tables:**
  - `platform_super_admin_designation`: a single row, immutable.
  - `platform_privileges`: grant history. A row can be revoked once. Rows are never deleted or edited, and reinstatement inserts a new row.
  - `platform_audit_events`: append-only.

  Each has a guard trigger and an audit trigger, and none can be truncated.
- **Membership guards.** These replace the earlier function bodies; the triggers are unchanged. For the runtime role:
  - Every role change and disable must name an actor who is an active Administrator of the **same** organization and isn't the member being changed.
  - Anything involving `workspace_admin` also needs that actor to hold the active platform privilege, checked through `hourvia_member_authority(actor, organization)`.
  - Invitations follow the same rules.

  Disabling remains terminal for the application. Operators may reinstate a member only through the approved procedure.
- **Session attribution.**
  - The new column `auth_sessions.revoked_by_member_id` is required for every revocation made by the application.
  - Revoking someone else's sessions needs the same authority as managing them.
  - Revocation is final: none of its fields can change once it is set. Identity columns are immutable.
  - Every revocation writes an audit row, `session_revocation`, recording the actor, the reason, the authority (`self`, `workspace_admin`, `platform_super_admin` or `operator`) and the source.
- **Runtime privileges.** The runtime gets SELECT on `platform_privileges (auth_user_id, privilege, revoked_at)` only. It gets nothing on the designation or the platform audit, and no write access at all. `netlifydb_readonly` and PUBLIC get nothing. A self-check at the end of the migration aborts the deploy if any of this differs.

## 4. Operator procedures (`db/operations/platform/`)

Each procedure is owner SQL that needs its own written approval. Each one locks, checks its guards, is idempotent, records an approval reference, writes an audit row and deletes nothing.

| Procedure | Approval | Effect |
| --- | --- | --- |
| `grant-platform-super-admin.sql` | AP-PSA-GRANT | Verifies that the UID **and** the member ID match the active, activated Living IT Solutions membership. Writes the designation on the first run. Inserts the grant. A re-run while the grant is active writes nothing. After a revocation, a new run with a new approval reinstates it. |
| `revoke-platform-super-admin.sql` | AP-PSA-REVOKE | Revokes the active grant, with a reason. Optionally ends every session of that identity, audited as `operator`. Doesn't change the membership. Re-running it is a no-op. |
| `reinstate-disabled-member.sql` | AP-MEMBER-REINSTATE | Restores a member who was disabled in error to `active`, with the **same** role. Unban the Supabase user first, under the same approval. Doesn't restore ended sessions and doesn't grant any privilege. |

Changing the designated UID, for example if the Supabase identity is permanently lost, deliberately needs a reviewed forward migration. Membership identity is also immutable, so a new identity for the same mailbox needs a reviewed procedure in any case.

**Grant run sheet** (production only, after the release prerequisites in the change record):
1. **Q1, read-only:** `SELECT id, auth_user_id, role, status, activated_at IS NOT NULL AS activated FROM workspace_members WHERE email = 'livingitsolutions@gmail.com';` Expect one row that is `active` and activated. Copy `id` and `auth_user_id`; don't type them.
2. **Q2, read-only:** `SELECT count(*) FROM platform_privileges WHERE revoked_at IS NULL;` Expect `0`.
3. Run the grant procedure with the three placeholders replaced. Expect the notice `platform_super_admin_granted`.
4. **Verify:**
   - `SELECT event_type FROM platform_audit_events ORDER BY id;` should return `platform_designation_set` and `platform_privilege_granted`.
   - The membership role is still `workspace_admin`.
   - After a reload, the sidebar shows the **Platform Super Admin** badge.

## 5. Runtime database role: limits that remain

- **Session user.** The function connects as `netlifydb_owner` and runs every statement under `SET LOCAL ROLE hourvia_auth_runtime`. Any code able to run arbitrary SQL could `RESET ROLE` and act as owner, bypassing the runtime-only rules. Everything else here is defence in depth. A hard boundary needs a dedicated LOGIN role with its own credential, and it isn't confirmed that Netlify Database supports that. **Unresolved.**
- **What still holds for the owner:**
  - identity immutability
  - append-only audit tables
  - immutable designation and grant history
  - eligibility of the designated UID
  - the one-active-holder index
  - the role CHECK
  - the ban on re-enabling a disabled member without the reinstatement flag
- **What doesn't hold for the owner:** the approval flags (`hourvia.member_reinstatement`) only guard against mistakes; anyone with owner access can set them. Only change control and the audit trail detect misuse.
- **Existing mitigations:** the SQL is fixed-text and parameterized, and a static test forbids any database access outside the role-scoped client. Audit triggers fire for every role.

## 6. Residual risks

- While `HOURVIA_EMAIL_DELIVERY_AUTHORIZED=false`, every application invitation returns 503. Role changes don't need email.
- In smoke mode, only allowlisted emails can be invited or administered.
- The new isolation and seat-race guarantees for SaaS are design only. See [saas-pwa-architecture.md](saas-pwa-architecture.md).
