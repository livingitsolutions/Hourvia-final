// Build metadata only. Never read or serialize credentials or the rest of process.env.
import { writeFileSync } from 'node:fs';
const identity = {
  branch: process.env.BRANCH ?? '',
  siteId: process.env.SITE_ID ?? '',
  deployId: process.env.DEPLOY_ID ?? '',
};
writeFileSync(new URL('../server/auth/deployment-identity.ts', import.meta.url),
  '// Generated from Netlify build metadata; contains no credentials. Empty defaults fail closed locally.\n'
  + `export const deploymentIdentity = ${JSON.stringify(identity)} as const;\n`);
