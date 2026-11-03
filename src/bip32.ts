import { BIP32Factory } from 'bip32';
import * as ecc from 'tiny-secp256k1';
import * as bip39 from 'bip39';
import { createHash } from 'node:crypto';
const bip32 = BIP32Factory(ecc);
export type Network = 'mainnet' | 'testnet' | 'signet' | 'regtest';
export interface AccountKey { network: Network; xpub: string; masterFingerprint: string; originPath: string; }
export interface DerivedKey { branchIndex: number; addressIndex: number; compressedPublicKey: Uint8Array; xOnlyPublicKey: Uint8Array; }
function networkOf(network: Network) { return network === 'mainnet' ? undefined : { wif: 0xef, bip32: { public: 0x043587cf, private: 0x04358394 } }; }
function parsePath(path: string): string[] {
  if (path === 'm' || path === 'M' || path === '') return [];
  const normalized = path.startsWith('m/') || path.startsWith('M/') ? path.slice(2) : path;
  if (!normalized) return [];
  return normalized.split('/').map((part) => {
    if (!/^(0|[1-9]\d*)['hH]?$/.test(part)) throw new Error(`Invalid derivation path component: ${part}`);
    const value = Number.parseInt(part, 10);
    if (!Number.isSafeInteger(value) || value >= 0x80000000) throw new Error(`Invalid child index: ${part}`);
    return part;
  });
}
function fingerprint(seed: Uint8Array): string {
  const master = bip32.fromSeed(seed);
  return createHash('ripemd160').update(createHash('sha256').update(master.publicKey).digest()).digest().subarray(0, 4).toString('hex');
}
export function mnemonicToSeed(mnemonic: string, passphrase = ''): Uint8Array {
  const normalized = mnemonic.normalize('NFKD');
  if (!bip39.validateMnemonic(normalized)) throw new Error('Invalid BIP39 mnemonic');
  return bip39.mnemonicToSeedSync(normalized, passphrase.normalize('NFKD'));
}
export function deriveAccountXpub(seed: Uint8Array, path: string, network: Network): AccountKey {
  if (seed.length < 16 || seed.length > 64) throw new Error('BIP32 seed must contain 16 to 64 bytes');
  const parts = parsePath(path);
  const node = parts.reduce((parent, part) => {
    const hardened = /['hH]$/.test(part);
    const index = Number.parseInt(part, 10);
    return hardened ? parent.deriveHardened(index) : parent.derive(index);
  }, bip32.fromSeed(seed, networkOf(network)));
  const xpub = node.neutered().toBase58();
  return { network, xpub, masterFingerprint: fingerprint(seed), originPath: parts.length ? `m/${parts.join('/')}` : 'm' };
}
export function importAccountXpub(xpub: string, origin: string, network: Network): AccountKey {
  if (!/^[0-9a-fA-F]{8}(?:\/|$)/.test(origin)) throw new Error('Key origin must start with an 8-hex-digit master fingerprint');
  const [masterFingerprint, ...pathParts] = origin.split('/');
  const originPath = pathParts.length ? `m/${parsePath(pathParts.join('/')).join('/')}` : 'm';
  const expectedPrefix = network === 'mainnet' ? 'xpub' : 'tpub';
  if (!xpub.startsWith(expectedPrefix)) throw new Error(`Extended public key prefix does not match ${network}`);
  try { bip32.fromBase58(xpub, networkOf(network)); }
  catch (error) { throw new Error(`Invalid extended public key: ${error instanceof Error ? error.message : String(error)}`); }
  return { network, xpub, masterFingerprint: masterFingerprint!.toLowerCase(), originPath };
}
export function deriveChildKey(account: AccountKey, branch: number, index: number): DerivedKey {
  for (const [label, value] of [['branch', branch], ['index', index]] as const) {
    if (!Number.isInteger(value) || value < 0 || value >= 0x80000000) throw new Error(`${label} must be a non-hardened BIP32 index`);
  }
  const child = bip32.fromBase58(account.xpub, networkOf(account.network)).derive(branch).derive(index);
  return { branchIndex: branch, addressIndex: index, compressedPublicKey: Uint8Array.from(child.publicKey), xOnlyPublicKey: Uint8Array.from(child.publicKey.subarray(1)) };
}
