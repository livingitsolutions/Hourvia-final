# Hourvia by Living IT Solutions

Internal time-tracking workspace foundation for ThriveSource. React, Vite, strict TypeScript, Tailwind CSS v4, React Router, and Zod.

```sh
npm ci
npm run dev
npm run typecheck
npm test
```

`npm run build` runs strict TypeScript validation and produces the Vite production bundle. Netlify's automatic build performs that step; no production deployment is requested for Sprint 0.

Start at `/login`. Sign-in intentionally remains unavailable: no identity service is connected, and no credentials create a session. Authenticated screens can only be exercised through injected test services until a real authentication adapter and backend are implemented. There is no preview bypass or role selector.

See [architecture and permission contracts](docs/architecture.md) and [future time-tracking requirements](docs/time-tracking-contract.md). No database, timers, shifts, payments, payroll, monitoring, or SaaS subscriptions were implemented.
