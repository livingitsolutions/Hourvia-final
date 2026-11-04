import { z } from 'zod';
import type { Principal, ResourceScope } from './permissions';
export const loginSchema = z.object({ email: z.email('Enter a valid work email address.'), password: z.string().min(1, 'Enter your password.') });
export type LoginInput = z.infer<typeof loginSchema>;
export interface Authentication { getSession(): Promise<Principal | null>; signIn(input: LoginInput): Promise<Principal>; signOut(): Promise<void> }
// Sprint 1.7 additive contracts: invitation acceptance and recovery. Shared by browser forms and server validation.
export const passwordSchema = z.string().min(12, 'Use at least 12 characters.').max(72, 'Use 72 characters or fewer.').refine(value => value.trim().length >= 12, 'Use at least 12 non-space characters.');
const tokenHashSchema = z.string().regex(/^[A-Za-z0-9_-]{16,256}$/, 'This link is incomplete. Open it again from your email.');
export const recoveryCodeSchema = z.string().regex(/^\d{6}$/, 'Enter the 6-digit code from your email.');
export const recoveryRequestSchema = z.object({ email: z.email('Enter a valid work email address.') });
export const recoveryCompleteSchema = z.union([
  z.strictObject({ email: z.email('Enter a valid work email address.'), code: recoveryCodeSchema, password: passwordSchema }),
  z.strictObject({ tokenHash: tokenHashSchema, password: passwordSchema }),
]);
export type RecoveryCompleteInput = z.infer<typeof recoveryCompleteSchema>;
export const acceptInvitationSchema = z.object({ tokenHash: tokenHashSchema, password: passwordSchema });
export type AcceptInvitationInput = z.infer<typeof acceptInvitationSchema>;
/**
 * Organization roles the application can grant. Platform privileges (platform_super_admin) and the withdrawn
 * workspace super_admin are never accepted. Which of these the caller may grant is decided server-side by
 * assignableRoles(). Workspace is fixed server-side and never accepted here.
 */
export const assignableRoleSchema = z.enum(['workspace_admin', 'workspace_manager', 'contractor'], 'Choose a valid role.');
export const adminInviteSchema = z.object({ email: z.email('Enter a valid work email address.').max(320), role: assignableRoleSchema, displayName: z.string().trim().max(120).optional() });
export type AdminInviteInput = z.infer<typeof adminInviteSchema>;
export const memberRoleChangeSchema = z.object({ role: assignableRoleSchema });
export type MemberRoleChangeInput = z.infer<typeof memberRoleChangeSchema>;
export interface AccountAccess { requestRecovery(email: string): Promise<string>; completeRecovery(input: RecoveryCompleteInput): Promise<string>; acceptInvitation(input: AcceptInvitationInput): Promise<string> }
export const taskSchema = z.enum(['Working', 'Break', 'Lunch']);
export const shiftStartSchema = z.object({ projectId: z.string().trim().min(1), description: z.string().trim().min(1) });
export type UtcTimestamp = string; // ISO 8601 UTC (Z); validate at the future API boundary.
export interface Shift { id: string; contractorId: string; projectId: string; description: string; startedAt: UtcTimestamp; endedAt: UtcTimestamp | null; netWorkedSeconds: number }
export interface ShiftSummary { shift: Shift; breakSeconds: number; lunchSeconds: number }
export interface Shifts { start(input: z.infer<typeof shiftStartSchema>): Promise<Shift>; changeTask(shiftId: string, task: z.infer<typeof taskSchema>): Promise<void>; clockOut(shiftId: string): Promise<ShiftSummary>; list(scope: ResourceScope): Promise<readonly Shift[]> }
export interface Timesheet { id: string; contractorId: string; cutoffId: string; netWorkedSeconds: number }
export interface Timesheets { list(scope: ResourceScope, cutoffId: string): Promise<readonly Timesheet[]> }
export interface CorrectionRequest { id: string; contractorId: string; shiftId: string; reason: string; status: 'pending' | 'approved' | 'rejected' }
export interface Approvals { request(input: { shiftId: string; reason: string; proposedStart: UtcTimestamp; proposedEnd: UtcTimestamp }): Promise<CorrectionRequest>; list(scope: ResourceScope): Promise<readonly CorrectionRequest[]>; decide(requestId: string, decision: 'approved' | 'rejected', reason: string): Promise<void> }
export interface Cutoff { id: string; startsOn: string; endsOn: string; calendarTimeZone: string }
export interface Cutoffs { forDate(calendarDate: string, calendarTimeZone: string): Promise<Cutoff>; review(cutoffId: string, scope: ResourceScope): Promise<void> }
