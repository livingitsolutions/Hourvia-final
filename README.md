# Hourvia by Living IT Solutions

Internal time-tracking workspace foundation for ThriveSource. React, Vite, strict TypeScript, Tailwind CSS v4, React Router, and Zod.

```sh
npm ci
npm run dev
npm run typecheck
npm test
```

`npm run build` stamps non-secret deployment metadata and then runs strict TypeScript validation and the Vite production bundle. Netlify's automatic build performs that step. `main` is the production branch: merging to `main` builds, auto-publishes to https://hourvia.livingitsolutions.com and applies any new file in `netlify/database/migrations/` to the production database. Treat every merge to `main` as a production release.

Start at `/login`. Authentication uses Supabase Auth behind Netlify Functions with server-managed HttpOnly sessions. The current controls are in [production pre-launch safeguards](docs/production-prelaunch.md); older activation documents are historical. Until those gates pass (independent production database evidence, synthetic identity policy, smoke-stage configuration), every `/api/auth/*`, `/api/admin/*` and `/api/platform/*` request fails closed with a 503. There is no preview bypass, signup, or role selector.

The current verified state of the deployment, database and configuration, including what is owner-confirmed and what remains unverified, is in [operations status](docs/operations-status.md).

See [architecture and permission contracts](docs/architecture.md) and [future time-tracking requirements](docs/time-tracking-contract.md). The auth, platform-administration and organization schema (migrations M1–M7) exists in Netlify Database. Timers, shifts, payments, payroll, monitoring and SaaS subscriptions are not implemented.
