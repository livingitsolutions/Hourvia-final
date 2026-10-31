# Future time-tracking requirements

This is a Sprint 1+ contract, not an implemented tracker. No live timers or persistent shifts exist in Sprint 0.

1. Require a valid authorized project and a nonblank work description before Clock In. Validate in both UI and server; Zod's shiftStartSchema expresses the initial input shape.
2. Use a task dropdown with exactly Working, Break, and Lunch. Clock In starts Working; Clock Out ends the shift.
3. Break and Lunch keep the shift open but pause net worked time. Returning to Working requires explicit Resume; never infer resumption from elapsed time, navigation, or reconnection.
4. Allow multiple shifts per day. Prevent overlapping open shifts for the same contractor using server-side transactions and a database constraint. Concurrent tabs and retries must not create duplicate open shifts; use idempotent commands.
5. Store event timestamps in UTC with a consistent ISO 8601/API representation and PostgreSQL timestamptz. Compute net time from persisted event intervals, not a browser counter. Validate timestamp formats and interval ordering at the future API boundary.
6. Configure and validate one workspace IANA calendar time zone before tracking starts. Do not infer it from the visitor's browser. Handle DST, overnight shifts, and interval allocation across local calendar dates explicitly.
7. Clock Out immediately returns a server-calculated shift summary: project, description, start/end, net worked seconds, break seconds, and lunch seconds. Do not show success before persistence succeeds.
8. Generate DTR and timesheets automatically from approved persisted events. Preserve the relationship between source events, corrections, daily records, and cutoff totals. Derive summaries consistently rather than independently editing totals.
9. Manual corrections require a reason and authorized approval. Keep the original values and an immutable decision audit trail. Pending or rejected corrections do not alter approved totals. Server rechecks assignment, authority, status, and concurrency at decision time. Define self-approval and separation-of-duties policy before enabling approvals.
10. Use semi-monthly calendar cutoffs: days 1–15 inclusive, then 16 through the last day of the month inclusive in the configured time zone. Convert boundaries to UTC using half-open intervals. Test February, leap years, month/year transitions, and DST. Define cutoff locking, reopening, and post-cutoff corrections before enabling review.

Outstanding product decisions: calendar time zone; who can assign managers and approval authority; self-approval policy; cutoff locking and reopening rules; project membership rules; and how overnight shift intervals are presented in DTR. Resolve these before production tracking.
