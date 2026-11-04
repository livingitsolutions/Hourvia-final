import { describe, expect, it, vi } from 'vitest';
import { SupabaseIdentityProvider } from './provider-supabase';

describe('provider transport context boundary', () => {
  it('never sends network requests from an ordinary dev or Agent Runner process', async () => {
    const network = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('network must not run'));
    try {
      const provider = new SupabaseIdentityProvider('https://offline.example.test', 'public-fixture', 'private-fixture');
      // Supabase may wrap transport rejections; no request can reach fetch.
      await provider.signInWithPassword('synthetic@example.test', 'offline password').catch(() => null);
      expect(network).not.toHaveBeenCalled();
    } finally { network.mockRestore(); }
  });
});
