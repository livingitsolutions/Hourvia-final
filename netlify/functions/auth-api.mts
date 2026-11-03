import type { Config, Context } from '@netlify/functions';
import { handleAuthRequest } from '../../server/auth/http';
import { runtimeDeps } from '../../server/auth/runtime';

// Hourvia authentication + admin membership API. Supabase Auth verifies credentials server-side; the browser
// only ever receives an opaque HttpOnly session cookie.
export default async (req: Request, context: Context) =>
  handleAuthRequest(req, context.ip, runtimeDeps(name => Netlify.env.get(name), context.deploy?.context));

export const config: Config = { path: ['/api/auth/*', '/api/admin/*'] };
