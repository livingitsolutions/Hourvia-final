import type { Authentication } from '../domain/contracts';
// Deliberately has no identity provider, browser session storage, or credential transport.
export const unconfiguredAuth: Authentication = {
  async getSession() { return null; },
  async signIn() { throw new Error('Workspace sign-in is not connected yet. Contact your workspace administrator for access.'); },
  async signOut() {},
};
