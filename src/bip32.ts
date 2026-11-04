import { mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist as englishWordlist } from '@scure/bip39/wordlists/english.js';
import { bip32 } from './bip32-engine.js';
import { WalletDerivationError } from './errors.js';
export type Network = 'mainnet' | 'testnet' | 'signet' | 'regtest';
export interface AccountKey { network: Network; xpub: string; masterFingerprint: string; originPath: string; }
export interface DerivedKey { branchIndex: number; addressIndex: number; compressedPublicKey: Uint8Array; xOnlyPublicKey: Uint8Array; }
export function assertNetwork(network: unknown): asserts network is Network {
  if (network !== 'mainnet' && network !== 'testnet' && network !== 'signet' && network !== 'regtest') {
    throw new WalletDerivationError('NETWORK_MISMATCH', `Unsupported Bitcoin network: ${String(network)}`);
  }
}
function networkOf(network: Network) {
  assertNetwork(network);
  return network === 'mainnet' ? undefined : { wif: 0xef, bip32: { public: 0x043587cf, private: 0x04358394 } };
}
function parsePath(path: string): string[] {
  if (path === 'm' || path === 'M' || path === '') return [];
  const normalized = path.startsWith('m/') || path.startsWith('M/') ? path.slice(2) : path;
  if (!normalized) return [];
  return normalized.split('/').map((part) => {
    if (!/^(0|[1-9]\d*)['hH]?$/.test(part)) throw new WalletDerivationError('INVALID_PATH', `Invalid derivation path component: ${part}`);
    const value = Number.parseInt(part, 10);
    if (!Number.isSafeInteger(value) || value >= 0x80000000) throw new WalletDerivationError('INVALID_INDEX', `Invalid child index: ${part}`);
    return part;
  });
}
export function mnemonicToSeed(mnemonic: string, passphrase = '', wordlist?: string[]): Uint8Array {
  const normalized = mnemonic.normalize('NFKD');
  const effectiveWordlist = wordlist ?? englishWordlist;
  if (!validateMnemonic(normalized, effectiveWordlist)) throw new WalletDerivationError('INVALID_SEED', 'Invalid BIP39 mnemonic');
  return mnemonicToSeedSync(normalized, passphrase.normalize('NFKD'));
}
export function deriveAccountXpub(seed: Uint8Array, path: string, network: Network): AccountKey {
  assertNetwork(network);
  if (seed.length < 16 || seed.length > 64) throw new WalletDerivationError('INVALID_SEED', 'BIP32 seed must contain 16 to 64 bytes');
  const parts = parsePath(path);
  const master = bip32.fromSeed(seed, networkOf(network));
  const node = parts.reduce((parent, part) => {
    const hardened = /['hH]$/.test(part);
    const index = Number.parseInt(part, 10);
    return hardened ? parent.deriveHardened(index) : parent.derive(index);
  }, master);
  const xpub = node.neutered().toBase58();
  return { network, xpub, masterFingerprint: Array.from(master.fingerprint, (byte) => byte.toString(16).padStart(2, '0')).join(''), originPath: parts.length ? `m/${parts.join('/')}` : 'm' };
}
export function importAccountXpub(xpub: string, origin: string, network: Network): AccountKey {
  assertNetwork(network);
  if (!/^[0-9a-fA-F]{8}(?:\/|$)/.test(origin)) throw new WalletDerivationError('INVALID_ORIGIN', 'Key origin must start with an 8-hex-digit master fingerprint');
  const [masterFingerprint, ...pathParts] = origin.split('/');
  const originParts = parsePath(pathParts.join('/'));
  const originPath = originParts.length ? `m/${originParts.join('/')}` : 'm';
  const expectedPrefix = network === 'mainnet' ? 'xpub' : 'tpub';
  if (!xpub.startsWith(expectedPrefix)) throw new WalletDerivationError('NETWORK_MISMATCH', `Extended public key prefix does not match ${network}`);
  let node;
  try { node = bip32.fromBase58(xpub, networkOf(network)); }
  catch (error) { throw new WalletDerivationError('INVALID_EXTENDED_KEY', `Invalid extended public key: ${error instanceof Error ? error.message : String(error)}`, { cause: error }); }
  const last = originParts.at(-1);
  const expectedIndex = last === undefined ? 0 : Number.parseInt(last, 10) + (/['hH]$/.test(last) ? 0x80000000 : 0);
  if (node.depth !== originParts.length || (last !== undefined && node.index !== expectedIndex)) throw new WalletDerivationError('INVALID_ORIGIN', 'Key origin path does not match extended-key depth/child-number metadata');
  return { network, xpub, masterFingerprint: masterFingerprint!.toLowerCase(), originPath };
}
export function deriveChildKey(account: AccountKey, branch: number, index: number): DerivedKey {
  assertNetwork(account.network);
  for (const [label, value] of [['branch', branch], ['index', index]] as const) {
    if (!Number.isInteger(value) || value < 0 || value >= 0x80000000) throw new WalletDerivationError('INVALID_INDEX', `${label} must be a non-hardened BIP32 index`);
  }
  const child = bip32.fromBase58(account.xpub, networkOf(account.network)).derive(branch).derive(index);
  return { branchIndex: branch, addressIndex: index, compressedPublicKey: Uint8Array.from(child.publicKey), xOnlyPublicKey: Uint8Array.from(child.publicKey.subarray(1)) };
}
