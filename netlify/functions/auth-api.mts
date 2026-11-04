import type { Config, Context } from '@netlify/functions';
import { handleAuthRequest } from '../../server/auth/http';
import { deploymentIdentity } from '../../server/auth/deployment-identity';
import { runtimeDeps } from '../../server/auth/runtime';

// Hourvia authentication, admin membership and read-only Platform Administration API. Supabase Auth verifies credentials server-side; the browser
// only ever receives an opaque HttpOnly session cookie.
export default async (req: Request, context: Context) =>
  handleAuthRequest(req, context.ip, runtimeDeps(name => Netlify.env.get(name), context.deploy?.context, {
    siteId: context.site?.id,
    branch: deploymentIdentity.deployId && deploymentIdentity.deployId === context.deploy?.id
      && deploymentIdentity.siteId === context.site?.id ? deploymentIdentity.branch : undefined,
  }));

export const config: Config = { path: ['/api/auth/*', '/api/admin/*', '/api/platform/*'] };
