import { Output } from '@bitcoinerlab/descriptors';
import { networks, type Network as BitcoinNetwork } from 'bitcoinjs-lib';
import { importAccountXpub, assertNetwork, type Network, type AccountKey } from './bip32.js';
import { WalletDerivationError } from './errors.js';
import { constructUnspendableInternalXpub } from './taproot.js';
import { validateLianaPolicySemantics } from './liana-policy.js';
import { splitDescriptorChecksum, selectMultipathBranch, parseDescriptorAst, type DescriptorAst } from './descriptors.js';
export interface WalletDescriptor { network: Network; original: string; checksum: string; signers: AccountKey[]; ast: DescriptorAst; }
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

function originFingerprints(value: string): string[] {
  return [...value.matchAll(KEY_WITH_ORIGIN)].map((match) => match[1]!.split('/')[0]!.toLowerCase());
}
function rejectDuplicateOrigins(fingerprints: string[], path: string): void {
  if (new Set(fingerprints).size !== fingerprints.length) {
    throw new WalletDerivationError('INVALID_DESCRIPTOR', `Liana ${path} path contains duplicate master-fingerprint origins`);
  }
}

function descriptorCall(expression: string): { name: string; args: string[] } | undefined {
  const open = expression.indexOf('(');
  if (open <= 0 || !expression.endsWith(')')) return undefined;
  return { name: expression.slice(0, open), args: splitTopLevelComma(expression.slice(open + 1, -1)) };
}
function isDecimalToken(value: string): boolean {
  return value.length > 0 && [...value].every((char) => char >= '0' && char <= '9');
}
function isNormalChildIndex(value: string): boolean {
  if (!isDecimalToken(value)) return false;
  const index = Number(value);
  return Number.isSafeInteger(index) && index < 0x80000000;
}

function isDescriptorXpub(value: string): boolean {
  const text = value.trim();
  const match = new RegExp(`^${KEY_WITH_ORIGIN.source}`).exec(text);
  if (!match) return false;
  const suffix = text.slice(match[0].length);
  if (!suffix.endsWith('/*')) return false;
  const derivation = suffix.slice(0, -2);
  if (derivation !== '' && !derivation.startsWith('/')) return false;
  const segments = derivation === '' ? [] : derivation.slice(1).split('/');
  const multipath = segments.filter((segment) => segment.startsWith('<') && segment.endsWith('>'));
  if (multipath.length !== 1) return false;
  return segments.every((segment) => {
    if (segment.startsWith('<') && segment.endsWith('>')) {
      const branches = segment.slice(1, -1).split(';');
      return branches.length === 2 && branches.every(isNormalChildIndex);
    }
    return isNormalChildIndex(segment);
  });
}

function isLianaKeyLeaf(expression: string): boolean {
  const value = expression.startsWith('a:') ? expression.slice(2) : expression;
  const call = descriptorCall(value);
  return (call?.name === 'pk' || call?.name === 'pkh') && call.args.length === 1 && isDescriptorXpub(call.args[0]!);
}
function isLianaKeyPolicy(expression: string): boolean {
  const value = expression.startsWith('a:') ? expression.slice(2) : expression;
  const call = descriptorCall(value);
  if (!call) return false;
  if (call.name === 'pk' || call.name === 'pkh') return call.args.length === 1 && isDescriptorXpub(call.args[0]!);
  if (call.name === 'multi') {
    const threshold = call.args[0]!;
    return call.args.length >= 3 && isDecimalToken(threshold) && Number(threshold) >= 1 && Number(threshold) <= call.args.length - 1 && call.args.slice(1).every(isDescriptorXpub);
  }
  if (call.name === 'thresh') {
    const threshold = call.args[0]!;
    return call.args.length >= 3 && isDecimalToken(threshold) && Number(threshold) >= 1 && Number(threshold) <= call.args.length - 1 && call.args.slice(1).every(isLianaKeyLeaf);
  }
  return false;
}

function validateLianaWshPolicy(body: string): void {
  const root = descriptorCall(body);
  if (root?.name !== 'wsh' || root.args.length !== 1) throw new WalletDerivationError('INVALID_DESCRIPTOR', 'Malformed Liana P2WSH descriptor');
  const timelocks = new Set<number>();
  function addRecovery(recoveryPolicy: string, olderExpression: string): void {
    const older = descriptorCall(olderExpression);
    const timelockToken = older?.name === 'older' && older.args.length === 1 ? older.args[0]! : '';
    const timelock = /^[0-9]+$/.test(timelockToken) ? Number(timelockToken) : NaN;
    if (!Number.isSafeInteger(timelock) || timelock < 1 || timelock > 0xffff || /\bolder\s*\(/.test(recoveryPolicy)) {
      throw new WalletDerivationError('INVALID_DESCRIPTOR', 'Each Liana P2WSH recovery must contain one positive uint16 older() timelock');
    }
    if (timelocks.has(timelock)) throw new WalletDerivationError('INVALID_DESCRIPTOR', 'Liana recovery paths must have distinct relative timelocks');
    timelocks.add(timelock);
    if (!/(?:xpub|tpub)[1-9A-HJ-NP-Za-km-z]+/.test(recoveryPolicy) || !isLianaKeyPolicy(recoveryPolicy)) throw new WalletDerivationError('INVALID_DESCRIPTOR', 'Each Liana recovery path must be a key-only policy');
    rejectDuplicateOrigins(originFingerprints(recoveryPolicy), 'recovery');
  }
  function walk(expression: string): string {
    const call = descriptorCall(expression);
    if (call?.name === 'andor') {
      if (call.args.length !== 3) throw new WalletDerivationError('INVALID_DESCRIPTOR', 'Liana P2WSH andor policies must have recovery key, timelock and primary key arguments');
      const recoveryPolicy = call.args[0]!;
      const primary = call.args[2]!;
      if (!isLianaKeyPolicy(primary) || /\bolder\s*\(/.test(primary)) throw new WalletDerivationError('INVALID_DESCRIPTOR', 'Liana P2WSH andor requires an untimelocked key-only primary path');
      addRecovery(recoveryPolicy, call.args[1]!);
      return primary;
    }
    if (call?.name === 'or_d' || call?.name === 'or_i') {
      if (call.args.length !== 2) throw new WalletDerivationError('INVALID_DESCRIPTOR', 'Liana P2WSH recovery branches must be binary OR policies');
      const recoveryExpression = call.name === 'or_d' ? call.args[1]! : call.args[0]!;
      const previousExpression = call.name === 'or_d' ? call.args[0]! : call.args[1]!;
      const recovery = descriptorCall(recoveryExpression);
      if (recovery?.name !== 'and_v' || recovery.args.length !== 2 || !recovery.args[0]!.startsWith('v:')) {
        throw new WalletDerivationError('INVALID_DESCRIPTOR', 'Liana P2WSH recovery branches must pair signer keys with older()');
      }
      const recoveryPolicy = recovery.args[0]!.slice(2);
      addRecovery(recoveryPolicy, recovery.args[1]!);
      return walk(previousExpression);
    }
    if (/\bolder\s*\(/.test(expression) || !/(?:xpub|tpub)[1-9A-HJ-NP-Za-km-z]+/.test(expression) || !isLianaKeyPolicy(expression)) {
      throw new WalletDerivationError('INVALID_DESCRIPTOR', 'Liana P2WSH requires a key-only untimelocked primary path and timelocked recovery paths');
    }
    return expression;
  }
  const primary = walk(root.args[0]!);
  if (timelocks.size === 0) throw new WalletDerivationError('INVALID_DESCRIPTOR', 'Liana P2WSH descriptors require at least one recovery path');
  rejectDuplicateOrigins(originFingerprints(primary), 'primary');
}
function validateLianaDescriptorPolicy(body: string, unoriginatedInternalKeyOffset?: number): void {
  if (body.startsWith('tr(')) validateLianaPolicySemantics(body, unoriginatedInternalKeyOffset);
  else if (body.startsWith('wsh(')) validateLianaWshPolicy(body);
  else throw new WalletDerivationError('INVALID_DESCRIPTOR', 'Only Liana Taproot and P2WSH descriptors are supported');
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
function validatePublicKeyDerivations(body: string): void {
  for (const match of body.matchAll(/(?:xpub|tpub)[1-9A-HJ-NP-Za-km-z]+/g)) {
    const suffix = body.slice(match.index! + match[0].length).split(/[),}]/, 1)[0]!;
    for (const segment of suffix.split('/').slice(1)) {
      const branches = segment.startsWith('<') && segment.endsWith('>') ? segment.slice(1, -1).split(';') : [segment];
      if (branches.some((branch) => /^(?:\d+|\*)['hH]$/.test(branch))) {
        throw new WalletDerivationError('INVALID_PATH', 'Hardened derivation steps are not allowed below public extended keys');
      }
    }
  }
}
function validateUniqueDescriptorKeys(body: string, unoriginatedInternalKeyOffset?: number): void {
  const seen = new Set<string>();
  for (const match of body.matchAll(/(?:xpub|tpub)[1-9A-HJ-NP-Za-km-z]+/g)) {
    if (match.index === unoriginatedInternalKeyOffset) continue;
    const suffix = body.slice(match.index! + match[0].length).split(/[),}]/, 1)[0]!;
    const derivationPath = suffix.endsWith('/*') ? suffix.slice(0, -2) : suffix;
    const identity = `${match[0]}${derivationPath}`;
    if (seen.has(identity)) throw new WalletDerivationError('INVALID_DESCRIPTOR', 'Liana descriptors must not reuse the same extended key and derivation path');
    seen.add(identity);
  }
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
  validatePublicKeyDerivations(body);
  const signers: AccountKey[] = [];
  for (const match of body.matchAll(KEY_WITH_ORIGIN)) {
    try { signers.push(importAccountXpub(match[2]!, match[1]!, network)); }
    catch (error) {
      if (error instanceof WalletDerivationError) throw error;
      throw new WalletDerivationError('INVALID_EXTENDED_KEY', `Invalid descriptor signer origin/key: ${error instanceof Error ? error.message : String(error)}`, { cause: error });
    }
  }
  if (signers.length === 0) throw new WalletDerivationError('NO_SIGNER_KEYS', 'Descriptor contains no originated xpub/tpub signer keys');
  const unoriginatedInternalKeyOffset = validateNumsInternalKey(body, network);
  validateKeyOrigins(body, unoriginatedInternalKeyOffset);
  validateUniqueDescriptorKeys(body, unoriginatedInternalKeyOffset);
  validateLianaDescriptorPolicy(body, unoriginatedInternalKeyOffset);
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
  return { network, original: text, checksum, signers, ast: parseDescriptorAst(body) };
}
