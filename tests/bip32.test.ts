import { describe, expect, it } from 'vitest';
import { deriveAccountXpub, importAccountXpub, deriveChildKey } from '../src/index.js';

describe('BIP32 wallet derivation', () => {
  it('derives the BIP32 vector 1 child at m/0 prime', () => {
    const seed = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
    const account = deriveAccountXpub(seed, "m/0'", 'mainnet');
    expect(account.xpub).toBe('xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw');
  });

  it('rejects malformed extended public keys and origins', () => {
    expect(() => importAccountXpub('invalid', 'deadbeef', 'mainnet')).toThrow();
  });

  it('derives the requested non-hardened branch/index from an imported account', () => {
    const seed = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
    const account = deriveAccountXpub(seed, 'm', 'mainnet');
    const child = deriveChildKey(account, 0, 0);
    expect(child.branchIndex).toBe(0);
    expect(child.addressIndex).toBe(0);
    expect(child.compressedPublicKey).toHaveLength(33);
    expect(child.xOnlyPublicKey).toHaveLength(32);
  });
});
