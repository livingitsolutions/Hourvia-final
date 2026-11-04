# Challenge preauthorization proposal — not a migration

No SQL is staged in the auto-applied migration directory. Existing M1–M7 are unchanged. Production pre-launch currently denies invitation creation/acceptance and token-hash recovery before provider contact. Email-code recovery uses approved active identity mappings.

A future design may use Netlify Database challenge rows containing purpose, digest of an application challenge, immutable synthetic provider/member UUIDs, organization, approval/run reference, expiry, attempt budget and atomic consumed state. Never store raw passwords, OTPs, provider bearer tokens or raw emailed token hashes. Challenges must be issued server-side only after independently approved identity binding. Caller-supplied email plus an arbitrary Supabase token hash is not proof of that binding.

The token delivered to the user must be cryptographically bound to the issued record and the exact authorized provider challenge. A generic application challenge attached to an unrelated provider token does not prevent consuming someone else's provider token. Establish a supported provider flow that creates that binding before verification, with email delivery independently gated. If no supported flow can guarantee it, keep opaque-token routes disabled. Review provider token generation APIs carefully: even token generation/account creation is a stateful separately authorized operation.

Before implementing, specify transaction/locking behavior for concurrent consume/replay, fixed retry budgets, expiry, revocation, audit retention, failure reconciliation across provider/database operations and least-privilege runtime grants. Test zero provider calls for unknown, forged, expired, replayed, wrong-purpose, wrong-tenant and protected identity challenges, plus provider-returned UUID mismatches.

A new forward-only migration would add these records and restricted statement-policy access only after independent production target/ledger verification, security review and migration authorization. Do not edit M1–M7, apply proposal SQL, or put a draft destructive/reset operation in a migration. No new infrastructure is needed.
