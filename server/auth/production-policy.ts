import { deploymentIdentity } from './deployment-identity';

export const PRODUCTION_SITE = '48d7a24b-6072-40bc-866f-0d6e43a921ea';
export const PRODUCTION_ORIGIN = 'https://hourvia.livingitsolutions.com';
export interface RuntimeIdentity { siteId?: string; deployId?: string; published?: boolean }
export function deploymentAllowed(runtime: RuntimeIdentity | undefined, build = deploymentIdentity): boolean {
  return !!runtime && runtime.published === true && runtime.siteId === PRODUCTION_SITE
    && build.siteId === PRODUCTION_SITE && build.branch === 'main' && build.context === 'production'
    && /^[a-f0-9]{24}$/.test(build.deployId) && runtime.deployId === build.deployId
    && /^[a-f0-9]{40}$/.test(build.commit);
}
