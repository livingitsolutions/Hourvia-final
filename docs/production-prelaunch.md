# Sprint 2.0B.2 production pre-launch safeguards

This is the current production-only application policy. Main is the only development/deployment branch; staging is retired. Earlier preflight, activation, preview-verification and migration-promotion instructions are historical and must not authorize operations. This implementation changed code and ran offline tests only. It did not verify current production state, deploy, activate authentication, change configuration, run platform migrations, or contact the live provider.

## Runtime admission

The default Supabase network transport and the auth dependency factory reject dev, Agent Runner processes, deploy previews, branch deployments and unknown contexts. Only a published production Function on the exact existing Hourvia site can proceed. A metadata-only build step stamps site, branch, context, deploy ID and commit into the server artifact; runtime site/deploy identity must match, the branch must be main, and the commit must be present. Empty local defaults refuse access. Request headers cannot supply identity. The stamp is an artifact consistency check, not a signature or a sandbox against malicious code with deployment privileges.

Production still requires the explicit production authorization switch and the exact canonical HTTPS origin. Only smoke stage is accepted; general/public stage is refused. The existing exact email allowlist must match a complete synthetic identity manifest. Email authorization remains a separate gate, absent/off by default. No signup route is added. Cookies, CSRF, canonical-origin rejection, tenant scoping, SQL role/statement controls, audit and rate limits remain in place.

`HOURVIA_SYNTHETIC_IDENTITY_POLICY` is a server-only JSON policy with exactly these fields:

- `identities`: 1–20 entries, each with normalized `email`, immutable `memberId`, immutable `authUserId`.
- `protectedEmails`, `protectedMemberIds`, `protectedAuthUserIds`: nonempty exact protected sets collected from the independent production inventory. UUIDs are canonical lower-case values. No duplicate mapping, missing email, or intersection is allowed.

There is no default account manifest. Do not classify existing administrators as synthetic. Platform privilege holders are refused even if accidentally mapped as synthetic. This protects the platform holder but means pre-launch app tests cannot log in as that holder. Inventory completeness is an operator responsibility; code cannot infer whether an account belongs to a real person. Policy entries are authorization configuration, not application persistence or an account creation mechanism.

Login resolves an active membership and checks the full email/member/provider binding before calling Supabase. It checks the returned provider UUID before revocation or application session creation. Sessions and administrative targets recheck the manifest, protected sets and platform privileges. Code recovery preauthorizes the active mapped membership, then checks the returned UUID before changing a password or revoking sessions. A mismatched result is discarded without further calls on that unknown provider identity.

## Token limitations

Invitation creation and invitation acceptance are unavailable under the production pre-launch policy. Token-hash recovery is also unavailable. These paths deny before provider verification, even for allowlisted accounts. A token hash cannot safely be associated with an approved immutable identity using caller-supplied email. Sending an invitation while acceptance is disabled would strand the recipient, so creation is blocked too. There is no hidden opt-in to bypass this restriction.

Login and six-digit email-code recovery for independently provisioned approved synthetic accounts remain supported. Recovery email requires separate delivery authorization. No accounts are provisioned by this change. Provider signup/anonymous/OAuth/magic-link settings must be independently reviewed: the application does not prevent direct requests to Supabase or Resend APIs. Provider email-to-UUID ownership must match the approved inventory. If Supabase returns a mismatched identity, the initial credential/OTP operation has already occurred; the app prevents subsequent mutation and session issuance, but cannot undo that provider operation. Do not claim an absolute provider-side noninterference guarantee under provider misconfiguration or compromised credentials.

Offline tests can inject mocked transports. Production wiring never injects a transport. The default transport checks runtime context on each request. Arbitrary malicious code holding production credentials is outside this application boundary; production-only secret scoping, trusted deployment access and runner permissions remain necessary.

## Database readiness and independent evidence

Corrected in Sprint 2.0B.2A after the production evidence feasibility audit. A trusted operator must independently identify the production database target before any later deployment or migration. A successful session probe, a copied preview schema or deployment metadata alone is insufficient.

### Two separate identity bindings

- **Artifact identity (automatic, unchanged).** The build stamps site, branch, context, deploy ID and commit. At runtime the Function must be published, on the exact Hourvia site, built from main in the production context, and its runtime deploy ID must equal the stamped deploy ID. Request headers can't supply identity.
- **Operator evidence (manual).** This is bound to the exact site, **commit**, production database branch, live database target digest and approved catalog digest. It carries **no deploy ID**. Netlify fixes Function environment values per deploy, and a change takes effect only through a new deploy with a new ID, so no operator can know the ID of the deploy that will carry the evidence. A legacy evidence value that still contains `deployId` or `expiresAt` is rejected as malformed.

### `HOURVIA_PRODUCTION_DATABASE_EVIDENCE`

Server-only, secret, production context and Functions scope. It's a JSON object with exactly these fields; any missing, extra or malformed field refuses access:

- `siteId`: the Hourvia site ID. `commit`: the full 40-character main commit SHA that will be deployed. `branch`: `"production"`.
- `targetDigest`: SHA-256 hex of `JSON.stringify([hostname lower-cased, port or "5432", decoded database path])` for the production database connection, the same calculation as `targetDigest` in `server/auth/production-database.ts`. The username, password and query parameters are excluded, so the redacted connection string from `netlify db status --branch production --json` is enough. Don't print, paste or log a credential-bearing string.
- `catalogDigest`: SHA-256 over the JSON result of `CATALOG_FINGERPRINT`, calculated with `catalogDigest`, for the independently reviewed M1–M7 baseline. Never approve a fingerprint only because the current database returned it.
- `migrationHistory`: an object with exactly `source: "netlify db status --branch production --json"`, `target: "production"`, `applied` (the exact ordered M1–M7 names from `MIGRATIONS`) and empty `pending`, `missingOnDisk` and `outOfOrder` arrays, copied from that command's output.
- `reviewer`, `approvalRef`: non-empty text, at most 200 characters.
- `verifiedAt`, `smokeWindowStart`, `smokeWindowEnd`: UTC ISO-8601 timestamps such as `2026-11-05T09:00:00Z`. They must satisfy `verifiedAt <= smokeWindowStart <= now < smokeWindowEnd`. The window can't exceed 7 days, and evidence age at the end of the window (`smokeWindowEnd - verifiedAt`) can't exceed 7 days. Future, expired, inverted or excessive windows fail closed.

### Migration history

The runtime no longer queries `netlify.migrations`. The platform table has no migration-name column, and the read-only role can't read the `netlify` schema, so that query could never pass. Migration history is verified by the operator through supported tooling: `netlify db status --branch production --json` reports applied, pending, missing-on-disk and out-of-order migrations for the production branch. It compares names and versions, not file contents. File immutability is covered by an offline test that checks each M1–M7 file against its original SHA-256 in `MIGRATION_DIGESTS`. Netlify also refuses to publish a production deploy if a migration fails.

### Runtime checks

On each request, the evidence and artifact identity are parsed and checked before any database work. The injected `NETLIFY_DB_URL` must produce the evidence `targetDigest`. Readiness then runs one read-only transaction with a 5-second statement timeout. It checks the M7 seed, tenant columns, tenant rows, constraints, RLS, functions, grants and triggers, plus the M1–M6 authority boundaries, and compares the full catalog fingerprint with `catalogDigest`. Errors, false or missing results, or a failed rollback refuse access, and uncertain connections are destroyed. No catalog result is exposed publicly.

**Success cache.** Each Function instance keeps one success entry for at most 60 seconds, and never beyond `smokeWindowEnd`. The cache key covers the runtime site, deploy ID and published flag, the build stamp, the target digest and the exact evidence text, and the entry also requires the identical pool object. Failures are never cached. Invalid evidence or identity clears the cache. Evidence, identity and the live binding are re-validated on every request, including cache hits, so the only thing skipped is the catalog query, and schema drift is detected within 60 seconds.

**Warm-instance pool handling.** If the injected binding moves to a different target (endpoint, port or database), the instance fails closed with `database_target_changed` and never rebuilds a pool for it. A binding that doesn't match the evidence target fails with `database_binding_mismatch`. If only credentials or connection parameters change for the same target, the pool is rebuilt and the old pool is drained. Because the new pool is a different object, full readiness checks run again. Requests still in flight on the retired pool may fail with 503. Pool credentials remain privileged; role scoping is defense in depth.

If production routing turns out to use a shared endpoint that doesn't uniquely identify the production branch, this target format is insufficient. Activation stays NO-GO until a trustworthy branch discriminator is available.

### Operator procedure (main-only)

1. A team member with production database access runs `netlify db status --branch production --json`. Confirm M1–M7 are applied in order and that `pending`, `missingOnDisk` and `outOfOrder` are empty. Calculate `targetDigest` privately from the redacted connection string. Compare the host with a preview branch host to confirm it identifies production uniquely.
2. Calculate the expected `catalogDigest` from a reviewed baseline: a database branch at exactly M1–M7, and the production catalog where supported read-only catalog access exists. The fingerprint reads only `pg_catalog`. Don't use the M7 row-count postconditions as read-only operator evidence, because the read-only role can't read those tables.
3. Merge the reviewed change to main. The resulting production deploy runs with auth fail-closed, because no evidence matches its commit yet. Record the exact commit SHA.
4. Set `HOURVIA_PRODUCTION_DATABASE_EVIDENCE` for that commit (production context, Functions scope, secret) with a smoke window of at most 7 days. Setting it is a separately authorized configuration change.
5. Trigger a reviewed redeploy of **the same commit**. The deploy ID changes, and the artifact identity check binds the new deploy to its own stamp; the evidence binds by commit. Confirm the published deploy's commit and ID, then run the negative smoke cases.

**Renewal.** Before `smokeWindowEnd`, re-run steps 1–2. Then update the evidence with a new `verifiedAt`, a new window and a new `approvalRef`, and trigger a reviewed redeploy of the same commit. Because the old evidence is still valid during the redeploy, there's no outage. If the window lapses first, auth returns 503 until renewal, which is the intended fail-closed result. A new commit always needs new evidence. No automatic renewal exists, and there's no mutable runtime evidence store.

## Configuration prerequisites — separate authorization

All provider credentials, hash material, manifests, enable/email flags and attestation must be production/functions only. Mark sensitive identity manifests and evidence private. Remove all-context inheritance from previews, branches and dev only with authorization; review old deploy environments, shared definitions, logs and runner permissions. Rotate credentials where exposure cannot be bounded. Do not write secrets or configured values into source, TOML, logs or this document. Existing VITE-prefixed provider aliases and staging flags are not used.

Before activation, independently verify Supabase invitation-only settings, protected account inventory, no anonymous/alternate provider access, correct canonical Site URL and exact recovery/invitation redirects; review the unused legacy Netlify Identity surface. Keep existing Resend SMTP configuration unchanged until authorized review; do not create another service or project.

The attestation is commit-bound and published through a reviewed redeploy of the same commit (see the operator procedure above). The deploy-ID circularity identified in the feasibility audit is resolved without relaxing the artifact identity check. No build, deployment, provider action or environment change is authorized by this document.

## Later release and rollback

Deployment and activation are separate decisions. Reconfirm production target and M1–M7 ledger/catalog before deployment, compare immutable migration digests, run offline checks and review the exact diff. An implementation artifact with no matching evidence/policy remains unavailable. Main changes can publish production code through the platform; committing or publishing is a separately controlled operation.

Activation additionally requires valid independent evidence for the exact commit and an open smoke window, complete synthetic/protected identity inventory, verified production-only secrets and provider settings, agreed evidence-renewal process, known compatible rollback artifact and a bounded smoke window. Test all negative deployment/target/policy/CSRF/cookie/role/tenant cases. Positive login and email tests require separate approval; invitation tests remain blocked pending the challenge design.

On failure, an authorized operator disables authentication and email, publishes a reviewed disabled artifact if required, and verifies actual canonical/alternate-host behavior and deployment identity. Environment edits alone do not prove a running deployment is disabled. Check retained deployment paths separately. Revoke affected app/provider sessions before reactivation; changing the HMAC key does not invalidate SHA-256 opaque session hashes. Preserve evidence and audit records. Application rollback does not undo emails, password changes, provider token consumption or database writes. Keep M1–M7 immutable and repair schema only forward in a separately approved migration.

## Controlled synthetic-data retirement/reset design

No reset is implemented or authorized. Production is not disposable. Default to preserving every unclassified row and identity.

1. Freeze an independently reviewed manifest of exact synthetic provider/member UUIDs, affected organization/run, invitations, sessions, assignments, rate buckets and test business records. Prefix or domain matching is insufficient. Abort on unknown ownership, new dependencies or protected-set overlap.
2. Preserve schemas, migration ledger/artifacts, role/ACL/function/trigger definitions, audit trails, platform grants/designation and their identities, protected admins and required seed/configuration records. Preserve ThriveSource's permanent organization and legacy bridge. Any identity referenced by retained audit/platform records remains protected from deletion.
3. Verify existing recovery/backup capability for both systems before destructive work; no new paid service. Provider UUID/password restoration may be unavailable. If recovery cannot be proven, use logical retirement only.
4. With separate authorization, quiesce auth/email and competing writes, verify the actual disabled runtime, revoke only approved synthetic app/provider sessions and record expected counts.
5. Prefer membership disabling, invitation expiry and provider bans. Retain audit-linked tombstones. Never disable guards, truncate/reset tables or sequences, cascade through protected data, drop schema or replay migrations. Prune only classified expired synthetic rate buckets.
6. Use an approved restartable operation journal in an existing controlled system, since Netlify Database and Supabase do not share a transaction. Track intended/completed steps, exact IDs and reconciliation; never automatically recreate identities or resend email on retry.
7. Hard deletion requires separate per-identity authorization, dependency/recovery proof, bounded leaf-first transactions and count assertions. Any reference to retained audit/platform/protected rows prevents deletion. No destructive SQL is included here.
8. Verify protected-set/seed fingerprints and counts, unchanged schema/history/ACLs/triggers, no orphans, no live retired sessions/invitations and cross-system reconciliation. Keep activation off pending a new decision.

Deployment readiness is conditional on the independent target evidence and operator workflow. Activation remains NO-GO until all prerequisites close. Invitation onboarding requires a later challenge-preauthorization implementation; public launch requires a separate reviewed policy change.
