import { describe, expect, it } from 'vitest';
import { wordlist as japaneseWordlist } from '@scure/bip39/wordlists/japanese.js';
import { deriveAccountXpub, importAccountXpub, deriveChildKey, mnemonicToSeed, WalletDerivationError } from '../src/index.js';

describe('BIP32 wallet derivation', () => {
  it('derives the BIP32 vector 1 child at m/0 prime', () => {
    const seed = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
    const account = deriveAccountXpub(seed, "m/0'", 'mainnet');
    expect(account.xpub).toBe('xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw');
    expect(account.masterFingerprint).toBe('3442193e');
  });

  it('matches pinned Rust CKDpub branch/index keys for the BIP32 test-vector-1 account', () => {
    const seed = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
    const account = deriveAccountXpub(seed, "m/0'", 'mainnet');
    // Cross-checks BIP32 test vector 1's m/0' account against the pinned Rust CKDpub harness.
    const expected = [
      '027b6a7dd645507d775215a9035be06700e1ed8c541da9351b4bd14bd50ab61428',
      '03e10f4f003b36e87c070fcda5201bb5f3f8a4a9537f853e3aaca53a44f166b630',
    ];
    for (const branch of [0, 1]) {
      const child = deriveChildKey(account, branch, 0);
      expect(Buffer.from(child.compressedPublicKey).toString('hex')).toBe(expected[branch]);
    }
  });
  it('derives the published BIP39 English vector with passphrase TREZOR', () => {
    const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    expect(Buffer.from(mnemonicToSeed(mnemonic, 'TREZOR')).toString('hex')).toBe('c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04');
  });
  it('derives the published BIP39 Japanese NFKD vector with its wordlist', () => {
    const mnemonic = 'あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あおぞら';
    const passphrase = '㍍ガバヴァぱばぐゞちぢ十人十色';
    const seed = mnemonicToSeed(mnemonic, passphrase, japaneseWordlist);
    expect(Buffer.from(seed).toString('hex')).toBe('a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55');
  });
  it('serializes a Signet account key with tpub and imports it watch-only', () => {
    const seed = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
    const account = deriveAccountXpub(seed, "m/48'/1'/0'/2'", 'signet');
    // Exact test-family serialization cross-check from tests/oracle/bip32_v1_public_children.rs.
    expect(account.xpub).toBe('tpubDEC8p4skY4i7mNjxt9yF3u7my5T6KtGLcvEDcH5rKA6XVtJN4JV3SsHWoePTqsHNh47WBkQ79r77KsUYc2PAmaqqasBJMvidbxiupZpJexg');
    expect(importAccountXpub(account.xpub, `${account.masterFingerprint}/48'/1'/0'/2'`, 'signet')).toEqual(account);
  });
  it('rejects origin paths that disagree with BIP32 depth and child-number metadata', () => {
    const seed = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
    const account = deriveAccountXpub(seed, "m/0'", 'mainnet');
    expect(() => importAccountXpub(account.xpub, `${account.masterFingerprint}/1'`, 'mainnet')).toThrow(/origin|metadata/i);
  });
  it('uses typed errors for invalid derivation indexes', () => {
    try { deriveChildKey({ network: 'mainnet', xpub: 'x', masterFingerprint: '00000000', originPath: 'm' }, 0x80000000, 0); throw new Error('expected error'); }
    catch (error) {
      expect(error).toBeInstanceOf(WalletDerivationError);
      expect((error as WalletDerivationError).code).toBe('INVALID_INDEX');
    }
  });
  it('rejects an unsupported network at runtime', () => {
    const seed = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
    try { deriveAccountXpub(seed, 'm', 'bitcoin-mainnet' as never); throw new Error('expected error'); }
    catch (error) {
      expect(error).toBeInstanceOf(WalletDerivationError);
      expect((error as WalletDerivationError).code).toBe('NETWORK_MISMATCH');
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
