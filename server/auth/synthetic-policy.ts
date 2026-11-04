import type { MemberRecord } from './types';

export interface SyntheticIdentity { email: string; memberId: string; authUserId: string }
export interface IdentityPolicy {
  identities: SyntheticIdentity[];
  protectedEmails: string[];
  protectedMemberIds: string[];
  protectedAuthUserIds: string[];
}
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const email = /^[^\s@,]+@[^\s@,]+\.[^\s@,]+$/;
export function parseIdentityPolicy(raw: string | undefined, allowed: ReadonlySet<string> | null): IdentityPolicy | null {
  try {
    const p = JSON.parse(raw ?? '') as IdentityPolicy;
    if (!allowed || !p || Object.keys(p).sort().join(',') !== 'identities,protectedAuthUserIds,protectedEmails,protectedMemberIds'
      || !Array.isArray(p.identities) || p.identities.length !== allowed.size) return null;
    for (const [values, pattern] of [[p.protectedEmails, email], [p.protectedMemberIds, uuid], [p.protectedAuthUserIds, uuid]] as const) {
      if (!Array.isArray(values) || !values.length || values.length > 1000
        || !values.every(v => typeof v === 'string' && pattern.test(v) && v === v.trim().toLowerCase())
        || new Set(values).size !== values.length) return null;
    }
    for (const i of p.identities) {
      if (!i || Object.keys(i).sort().join(',') !== 'authUserId,email,memberId'
        || typeof i.email !== 'string' || !allowed.has(i.email) || !uuid.test(i.memberId) || !uuid.test(i.authUserId)
        || p.protectedEmails.includes(i.email) || p.protectedMemberIds.includes(i.memberId)
        || p.protectedAuthUserIds.includes(i.authUserId)) return null;
    }
    if (['email', 'memberId', 'authUserId'].some(k => new Set(p.identities.map(i => i[k as keyof SyntheticIdentity])).size !== p.identities.length)) return null;
    return p;
  } catch { return null; }
}
export function identityAllowed(policy: IdentityPolicy, member: MemberRecord): boolean {
  return !policy.protectedEmails.includes(member.email) && !policy.protectedMemberIds.includes(member.id)
    && !policy.protectedAuthUserIds.includes(member.authUserId ?? '')
    && policy.identities.some(i => i.email === member.email && i.memberId === member.id && i.authUserId === member.authUserId);
}
