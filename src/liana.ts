import { Output } from '@bitcoinerlab/descriptors';
import { networks, type Network as BitcoinNetwork } from 'bitcoinjs-lib';
import { importAccountXpub, assertNetwork, type Network, type AccountKey } from './bip32.js';
import { WalletDerivationError } from './errors.js';
import { constructUnspendableInternalXpub } from './taproot.js';
import { splitDescriptorChecksum, selectMultipathBranch } from './descriptors.js';
export interface WalletDescriptor { network: Network; original: string; checksum: string; signers: AccountKey[]; }
const KEY_WITH_ORIGIN = /\[([0-9a-fA-F]{8}(?:\/(?:0|[1-9]\d*)['hH]?)*?)\]((?:xpub|tpub)[1-9A-HJ-NP-Za-km-z]+)/g;
function bitcoinNetwork(network: Network): BitcoinNetwork {
  if (network === 'mainnet') return networks.bitcoin;
  if (network === 'regtest') return { ...networks.testnet, bech32: 'bcrt' };
  return networks.testnet;
}
function splitTopLevelComma(value: string): string[] {
  const parts: string[] = [];
  let start = 0;
  let parentheses = 0;
  let braces = 0;
  let brackets = 0;
  for (let i = 0; i < value.length; i++) {
    const char = value[i]!;
    if (char === '(') parentheses++;
    else if (char === ')') parentheses--;
    else if (char === '{') braces++;
    else if (char === '}') braces--;
    else if (char === '[') brackets++;
    else if (char === ']') brackets--;
    else if (char === ',' && parentheses === 0 && braces === 0 && brackets === 0) {
      parts.push(value.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(value.slice(start));
  return parts;
}
function tapTreeLeaves(tree: string): string[] {
  const value = tree.trim();
  if (!value.startsWith('{')) return [value];
  if (!value.endsWith('}')) throw new WalletDerivationError('INVALID_DESCRIPTOR', 'Malformed Taproot tree braces');
  const children = splitTopLevelComma(value.slice(1, -1));
  if (children.length !== 2 || children.some((child) => child.trim().length === 0)) throw new WalletDerivationError('INVALID_DESCRIPTOR', 'Taproot tree nodes must contain exactly two branches');
  return children.flatMap(tapTreeLeaves);
}
function originFingerprints(value: string): string[] {
  return [...value.matchAll(KEY_WITH_ORIGIN)].map((match) => match[1]!.split('/')[0]!.toLowerCase());
}
function rejectDuplicateOrigins(fingerprints: string[], path: string): void {
  if (new Set(fingerprints).size !== fingerprints.length) {
    throw new WalletDerivationError('INVALID_DESCRIPTOR', `Liana ${path} path contains duplicate master-fingerprint origins`);
  }
}
function validateLianaTaprootPolicy(body: string): void {
  const tr = /^tr\(([^,]+)(?:,([\s\S]*))?\)$/.exec(body);
  if (!tr) throw new WalletDerivationError('INVALID_DESCRIPTOR', 'Only Liana Taproot tr() descriptors are supported');
  if (!tr[2]) throw new WalletDerivationError('INVALID_DESCRIPTOR', 'Liana Taproot descriptors require a recovery TapTree');
  const leaves = tapTreeLeaves(tr[2]);
  const recoveryLeaves = leaves.filter((leaf) => /\bolder\s*\(/.test(leaf));
  if (recoveryLeaves.length === 0) throw new WalletDerivationError('INVALID_DESCRIPTOR', 'Liana Taproot descriptors require at least one relative-timelocked recovery path');
  const recoveryTimelocks = new Set<number>();
  for (const leaf of recoveryLeaves) {
    const timelocks = [...leaf.matchAll(/\bolder\s*\(\s*(\d+)\s*\)/g)];
    const timelock = Number(timelocks[0]?.[1]);
    if (timelocks.length !== 1 || timelock < 1 || timelock > 0xffff) {
      throw new WalletDerivationError('INVALID_DESCRIPTOR', 'Each Liana recovery path must contain exactly one block-based older() timelock in the uint16 range');
    }
    if (recoveryTimelocks.has(timelock)) throw new WalletDerivationError('INVALID_DESCRIPTOR', 'Liana recovery paths must have distinct relative timelocks');
    recoveryTimelocks.add(timelock);
    if (!/(?:xpub|tpub)[1-9A-HJ-NP-Za-km-z]+/.test(leaf)) throw new WalletDerivationError('INVALID_DESCRIPTOR', 'Each Liana recovery path must contain at least one signer key');
    rejectDuplicateOrigins(originFingerprints(leaf), 'recovery');
  }
  const numsInternal = /^(?:xpub|tpub)[1-9A-HJ-NP-Za-km-z]+\/<0;1>\/\*$/.test(tr[1]!);
  const primaryLeaves = leaves.filter((leaf) => !/\bolder\s*\(/.test(leaf));
  if (numsInternal && primaryLeaves.length === 0) {
    throw new WalletDerivationError('INVALID_DESCRIPTOR', 'A NUMS internal key requires a separate always-available primary path in the TapTree');
  }
  const primaryOrigins = [...(!numsInternal ? originFingerprints(tr[1]!) : []), ...primaryLeaves.flatMap(originFingerprints)];
  rejectDuplicateOrigins(primaryOrigins, 'primary');
}
function validateNumsInternalKey(body: string, network: Network): number | undefined {
  const tr = /^tr\(([^,]+),([\s\S]*)\)$/.exec(body);
  if (!tr) return undefined;
  const internal = /^((?:xpub|tpub)[1-9A-HJ-NP-Za-km-z]+)\/<0;1>\/\*$/.exec(tr[1]!);
  if (!internal) return undefined;
  const leafXpubs = [...tr[2]!.matchAll(KEY_WITH_ORIGIN)].map((match) => match[2]!);
  if (leafXpubs.length === 0) throw new WalletDerivationError('INVALID_INTERNAL_KEY', 'NUMS internal key requires originated extended public keys in the TapTree');
  const expected = constructUnspendableInternalXpub(leafXpubs, network);
  if (internal[1] !== expected.xpub) throw new WalletDerivationError('INVALID_INTERNAL_KEY', 'NUMS internal xpub does not match the ordered TapTree leaf keys');
  return body.indexOf(tr[1]!);
}
function validateKeyOrigins(body: string, unoriginatedInternalKeyOffset?: number): void {
  const keys = [...body.matchAll(/(?:xpub|tpub)[1-9A-HJ-NP-Za-km-z]+/g)];
  const originatedOffsets = new Set([...body.matchAll(KEY_WITH_ORIGIN)].map((match) => match.index! + match[0].indexOf(match[2]!)));
  for (const key of keys) {
    if (!originatedOffsets.has(key.index!) && key.index !== unoriginatedInternalKeyOffset) {
      throw new WalletDerivationError('INVALID_ORIGIN', 'Every Liana signer extended public key must include a master-fingerprint origin');
    }
  }
}
export function parseLianaDescriptor(text: string, network: Network): WalletDescriptor {
  assertNetwork(network);
  const { body, checksum } = splitDescriptorChecksum(text);
  if (/(?<![1-9A-HJ-NP-Za-km-z])(?:xprv|tprv)[1-9A-HJ-NP-Za-km-z]+/.test(body) || /(?<![1-9A-HJ-NP-Za-km-z])(?:5[1-9A-HJ-NP-Za-km-z]{50}|[KL][1-9A-HJ-NP-Za-km-z]{51})(?![1-9A-HJ-NP-Za-km-z])/.test(body)) {
    throw new WalletDerivationError('INVALID_EXTENDED_KEY', 'Watch-only Liana descriptors must not contain private-key material');
  }
  const signers: AccountKey[] = [];
  for (const match of body.matchAll(KEY_WITH_ORIGIN)) {
    try { signers.push(importAccountXpub(match[2]!, match[1]!, network)); }
    catch (error) {
      if (error instanceof WalletDerivationError) throw error;
      throw new WalletDerivationError('INVALID_EXTENDED_KEY', `Invalid descriptor signer origin/key: ${error instanceof Error ? error.message : String(error)}`, { cause: error });
    }
  }
  if (signers.length === 0) throw new WalletDerivationError('NO_SIGNER_KEYS', 'Descriptor contains no originated xpub/tpub signer keys');
  validateLianaTaprootPolicy(body);
  const unoriginatedInternalKeyOffset = validateNumsInternalKey(body, network);
  validateKeyOrigins(body, unoriginatedInternalKeyOffset);
  try {
    const hasMultipath = body.includes('<');
    const selections = hasMultipath ? [0, 1] as const : [0] as const;
    for (const selection of selections) {
      const selected = hasMultipath ? selectMultipathBranch(body, selection) : { body };
      new Output({ descriptor: selected.body, network: bitcoinNetwork(network), index: 0, checksumRequired: false });
    }
  }
  catch (error) {
    if (error instanceof WalletDerivationError) throw error;
    throw new WalletDerivationError('UNSUPPORTED_DESCRIPTOR', `Invalid or unsupported Liana output descriptor: ${error instanceof Error ? error.message : String(error)}`, { cause: error });
  }
  return { network, original: text, checksum, signers };
}
