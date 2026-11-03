# Hourvia by Living IT Solutions

Internal time-tracking workspace foundation for ThriveSource. React, Vite, strict TypeScript, Tailwind CSS v4, React Router, and Zod.

```sh
npm ci
npm run dev
npm run typecheck
npm test
```

`npm run build` runs strict TypeScript validation and produces the Vite production bundle. Netlify's automatic build performs that step; no production deployment is requested for Sprint 0.

Start at `/login`. Authentication uses Supabase Auth behind Netlify Functions with server-managed HttpOnly sessions; see [authentication](docs/authentication.md). Until an operator configures the nonproduction Supabase project and promotes the staged auth schema, sign-in fails closed with a 503. There is no preview bypass, signup, or role selector.

See [architecture and permission contracts](docs/architecture.md) and [future time-tracking requirements](docs/time-tracking-contract.md). No database, timers, shifts, payments, payroll, monitoring, or SaaS subscriptions were implemented.
