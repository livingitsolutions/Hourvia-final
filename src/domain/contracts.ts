import { z } from 'zod';
import type { Principal, ResourceScope } from './permissions';
export const loginSchema = z.object({ email: z.email('Enter a valid work email address.'), password: z.string().min(1, 'Enter your password.') });
export type LoginInput = z.infer<typeof loginSchema>;
export interface Authentication { getSession(): Promise<Principal | null>; signIn(input: LoginInput): Promise<Principal>; signOut(): Promise<void> }
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
