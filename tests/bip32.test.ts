import { describe, expect, it } from 'vitest';
import { deriveAccountXpub, importAccountXpub, deriveChildKey, mnemonicToSeed, WalletDerivationError } from '../src/index.js';

describe('BIP32 wallet derivation', () => {
  it('derives the BIP32 vector 1 child at m/0 prime', () => {
    const seed = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
    const account = deriveAccountXpub(seed, "m/0'", 'mainnet');
    expect(account.xpub).toBe('xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw');
  });

  it('derives the published BIP39 English vector with passphrase TREZOR', () => {
    const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    expect(Buffer.from(mnemonicToSeed(mnemonic, 'TREZOR')).toString('hex')).toBe('c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04');
  });
  it('serializes a Signet account key with tpub and imports it watch-only', () => {
    const seed = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
    const account = deriveAccountXpub(seed, "m/48'/1'/0'/2'", 'signet');
    expect(account.xpub.startsWith('tpub')).toBe(true);
    expect(importAccountXpub(account.xpub, `${account.masterFingerprint}/48'/1'/0'/2'`, 'signet')).toEqual(account);
  });
  it('uses typed errors for invalid derivation indexes', () => {
    try { deriveChildKey({ network: 'mainnet', xpub: 'x', masterFingerprint: '00000000', originPath: 'm' }, 0x80000000, 0); throw new Error('expected error'); }
    catch (error) {
      expect(error).toBeInstanceOf(WalletDerivationError);
      expect((error as WalletDerivationError).code).toBe('INVALID_INDEX');
    }
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
