import type { Organization, OrganizationContext, OrganizationId } from '../../src/domain/organization';
import type { PlatformPrivilege, Role } from '../../src/domain/permissions';
import type { PlatformAuditPage, PlatformOverview } from '../../src/domain/platform';

/** Minimal SQL surface shared by Netlify Database (pg Pool) and the embedded test Postgres. */
export interface SqlClient {
  query<T = Record<string, unknown>>(text: string, params?: unknown[]): Promise<{ rows: T[] }>;
  transaction<T>(fn: (tx: SqlClient) => Promise<T>): Promise<T>;
}

export type MemberStatus = 'invited' | 'active' | 'disabled';
export interface MemberRecord {
  id: string;
  workspaceId: string;
  /** M7 organization_id. Always ThriveSource in Sprint 2.0B; never taken from request input. */
  organizationId: OrganizationId;
  authUserId: string | null;
  email: string;
  displayName: string;
  role: Role;
  status: MemberStatus;
  approvalAuthorized: boolean;
  createdAt: Date;
}

export interface SessionRecord { sessionId: string; member: MemberRecord; lastSeenAt: Date; absoluteExpiresAt: Date }

export interface AuditEvent {
  eventType: string;
  outcome: 'success' | 'denied' | 'error';
  actorMemberId?: string | null;
  subjectMemberId?: string | null;
  emailHmac?: string | null;
  ipHmac?: string | null;
  details?: Record<string, string | number | boolean | null>;
}

/**
 * Tenant-aware store (Sprint 2.0B). A store instance is bound to exactly one server-derived OrganizationContext, and
 * every tenant query it issues is scoped to that organization (see tenant-sql.ts). No method accepts an organization
 * identifier as an argument, so a caller cannot redirect a query to another tenant.
 */
export interface TenantScopedStore {
  readonly context: OrganizationContext;
  /** The context's organization (runtime-readable columns only), or null if it does not exist. */
  organization(): Promise<Organization | null>;
}

export interface AuthStore extends TenantScopedStore {
  findMemberById(id: string): Promise<MemberRecord | null>;
  findMemberByEmail(email: string): Promise<MemberRecord | null>;
  findMemberByAuthUserId(authUserId: string): Promise<MemberRecord | null>;
  listMembers(): Promise<MemberRecord[]>;
  assignedContractorIds(managerMemberId: string): Promise<string[]>;
  /** Active platform privileges of a Supabase identity (read-only for the application). */
  platformPrivileges(authUserId: string): Promise<PlatformPrivilege[]>;
  /**
   * Platform console reads (Sprint 1.8). Authorized inside the database from the caller's session token hash;
   * null means the database refused (not the active, designated holder, or the session is no longer valid).
   */
  platformOverview(sessionTokenHash: string): Promise<PlatformOverview | null>;
  platformAuditPage(sessionTokenHash: string, page: { beforeId: number | null; limit: number }): Promise<PlatformAuditPage | null>;
  upsertInvitation(input: { email: string; role: Role; displayName: string; authUserId: string; invitedBy: string | null; now: Date; expiresAt: Date }): Promise<MemberRecord>;
  hasPendingInvitation(memberId: string, now: Date): Promise<boolean>;
  acceptInvitation(memberId: string, now: Date): Promise<boolean>;
  disableMember(memberId: string, disabledBy: string, now: Date): Promise<boolean>;
  /** Changes an active member's role from expectedRole to role, recording the authorizing member. */
  changeMemberRole(input: { memberId: string; expectedRole: Role; role: Role; changedBy: string; now: Date }): Promise<boolean>;
  createSession(input: { tokenHash: string; memberId: string; now: Date; idleExpiresAt: Date; absoluteExpiresAt: Date }): Promise<void>;
  resolveSession(tokenHash: string, now: Date): Promise<SessionRecord | null>;
  touchSession(sessionId: string, now: Date, idleExpiresAt: Date): Promise<void>;
  /** Revokes one session; the acting member is the session's own member (logout). */
  revokeSession(tokenHash: string, reason: string, now: Date): Promise<string | null>;
  /** Revokes every session of memberId, recording revokedBy as the acting member. */
  revokeMemberSessions(memberId: string, reason: string, now: Date, revokedBy: string): Promise<number>;
  hitRateLimit(bucket: string, windowStart: Date): Promise<number>;
  audit(event: AuditEvent, now: Date): Promise<void>;
}

export interface ProviderSession { userId: string; accessToken: string }
export type OtpVerification =
  | { type: 'invite'; tokenHash: string }
  | { type: 'recovery'; tokenHash: string }
  | { type: 'recovery'; email: string; code: string };

/** Credential verifier. Only ever runs inside Netlify Functions; no token leaves the server. */
export interface IdentityProvider {
  /** Resolves null for any credential rejection; throws only for provider outages. */
  signInWithPassword(email: string, password: string): Promise<ProviderSession | null>;
  verifyEmailOtp(params: OtpVerification): Promise<ProviderSession | null>;
  revokeSession(accessToken: string, scope: 'local' | 'global'): Promise<void>;
  inviteUser(email: string, redirectTo: string): Promise<{ userId: string }>;
  sendRecovery(email: string, redirectTo: string): Promise<void>;
  setPassword(userId: string, password: string): Promise<void>;
  banUser(userId: string): Promise<void>;
}

export class ProviderConflictError extends Error {}

export interface AuthConfig {
  /** Only runtime production wiring supplies this mandatory pre-launch identity binding. */
  prelaunch?: import('./synthetic-policy').IdentityPolicy;
  hashKey: string;
  appOrigin: string | null;
  emailDeliveryAuthorized: boolean;
  /**
   * Production smoke-test stage: when set, only these (lower-cased) designated test emails can sign in, be
   * invited, recover a password, hold a session, or be administered. Everyone else is denied before any
   * provider call for identity-bearing flows. Runtime pre-launch wiring also blocks opaque tokens.
   * null is reserved for offline legacy fixtures; production wiring never accepts general availability.
   */
  smokeTestEmails: ReadonlySet<string> | null;
  idleTimeoutSeconds: number;
  absoluteTimeoutSeconds: number;
  invitationTtlSeconds: number;
  /** Minimum duration of recovery requests, to blunt timing-based account enumeration. */
  recoveryMinimumMs: number;
}

export interface AuthDeps {
  store: AuthStore;
  provider: IdentityProvider;
  config: AuthConfig;
  now(): Date;
  sleep(ms: number): Promise<void>;
}
