// Serialize only non-secret platform artifact metadata. Never serialize the environment.
import { writeFileSync } from 'node:fs';
const identity = {
  siteId: process.env.SITE_ID ?? '', branch: process.env.BRANCH ?? '',
  context: process.env.CONTEXT ?? '', deployId: process.env.DEPLOY_ID ?? '',
  commit: process.env.COMMIT_REF ?? '',
};
writeFileSync(new URL('../server/auth/deployment-identity.ts', import.meta.url),
  '// Generated artifact metadata; no credentials.\nexport const deploymentIdentity = ' + JSON.stringify(identity) + ';\n');
