import { WalletDerivationError } from './errors.js';
import { parseDescriptorAst, type DescriptorAstNode } from './descriptors.js';

const ORIGINATED_XPUB = /^\[([0-9a-fA-F]{8}(?:\/(?:0|[1-9]\d*)['hH]?)*?)\]((?:xpub|tpub)[1-9A-HJ-NP-Za-km-z]+)/;
const UINT16_MAX = 0xffff;
const MAX_MULTISIG_KEYS = 20;

type SemanticPolicy =
  | { kind: 'key'; descriptorKey: string }
  | { kind: 'older'; value: number }
  | { kind: 'after'; value: number }
  | { kind: 'hash' }
  | { kind: 'trivial' }
  | { kind: 'unsatisfiable' }
  | { kind: 'threshold'; threshold: number; subs: SemanticPolicy[] };
interface LianaKey {
  descriptorKey: string;
  fingerprint: string;
  identity: string;
}
type PathInfo = { kind: 'single'; keys: [LianaKey] } | { kind: 'multi'; threshold: number; keys: LianaKey[] };
export interface LianaPolicyPathClassification {
  primary: { kind: 'Single' | 'Multi'; threshold: number; keyCount: number };
  recovery: Array<{ older: number; kind: 'Single' | 'Multi'; threshold: number; keyCount: number }>;
}

function invalid(message: string): never {
  throw new WalletDerivationError('INVALID_DESCRIPTOR', message);
}

function call(node: DescriptorAstNode, name: string): DescriptorAstNode[] | undefined {
  return node.kind === 'call' && node.name === name ? [...node.arguments] : undefined;
}

function atomNumber(node: DescriptorAstNode | undefined): number | undefined {
  if (!node || node.kind !== 'atom' || !/^(0|[1-9]\d*)$/.test(node.raw.trim())) return undefined;
  const value = Number(node.raw.trim());
  return Number.isSafeInteger(value) ? value : undefined;
}

function keyArgument(node: DescriptorAstNode | undefined): string | undefined {
  return node?.kind === 'atom' ? node.raw.trim() : undefined;
}

function liftMiniscript(node: DescriptorAstNode): SemanticPolicy {
  if (node.kind === 'prefix') {
    if (!'ascdvjn'.includes(node.operator)) invalid(`Unsupported Miniscript wrapper '${node.operator}:' in a Liana spending policy`);
    return liftMiniscript(node.child);
  }
  if (node.kind === 'atom') {
    const atom = node.raw.trim();
    if (atom === '1') return { kind: 'trivial' };
    if (atom === '0') return { kind: 'unsatisfiable' };
    invalid(`Unsupported Miniscript atom '${atom}' in a Liana spending policy`);
  }
  if (node.kind !== 'call') invalid('Taproot tree nodes cannot appear inside a Miniscript policy');
  const args = [...node.arguments];
  if (node.name === 'pk' || node.name === 'pkh' || node.name === 'pk_k' || node.name === 'pk_h') {
    if (args.length !== 1 || !keyArgument(args[0])) invalid(`Malformed ${node.name} key policy`);
    return { kind: 'key', descriptorKey: keyArgument(args[0])! };
  }
  if (node.name === 'multi' || node.name === 'multi_a') {
    const threshold = atomNumber(args[0]);
    const keys = args.slice(1).map(keyArgument);
    if (threshold === undefined || keys.length < 1 || keys.some((key) => !key)) invalid(`Malformed ${node.name} key policy`);
    if (threshold < 1 || threshold > keys.length) invalid(`${node.name} threshold is outside its key count`);
    return { kind: 'threshold', threshold, subs: keys.map((descriptorKey) => ({ kind: 'key', descriptorKey: descriptorKey! })) };
  }
  if (node.name === 'thresh') {
    const threshold = atomNumber(args[0]);
    if (threshold === undefined || args.length < 2) invalid('Malformed thresh policy');
    if (threshold < 1 || threshold > args.length - 1) invalid('thresh threshold is outside its child count');
    return { kind: 'threshold', threshold, subs: args.slice(1).map(liftMiniscript) };
  }
  if (node.name === 'older' || node.name === 'after') {
    const value = atomNumber(args[0]);
    if (args.length !== 1 || value === undefined) invalid(`Malformed ${node.name} timelock`);
    return { kind: node.name, value };
  }
  if (['sha256', 'hash256', 'ripemd160', 'hash160'].includes(node.name)) {
    if (args.length !== 1 || args[0]!.kind !== 'atom') invalid(`Malformed ${node.name} hash policy`);
    return { kind: 'hash' };
  }
  if (['and_v', 'and_b'].includes(node.name)) {
    if (args.length !== 2) invalid(`Malformed ${node.name} policy`);
    return { kind: 'threshold', threshold: 2, subs: args.map(liftMiniscript) };
  }
  if (['or_b', 'or_c', 'or_d', 'or_i'].includes(node.name)) {
    if (args.length !== 2) invalid(`Malformed ${node.name} policy`);
    return { kind: 'threshold', threshold: 1, subs: args.map(liftMiniscript) };
  }
  if (node.name === 'andor') {
    if (args.length !== 3) invalid('Malformed andor policy');
    return {
      kind: 'threshold', threshold: 1,
      subs: [
        { kind: 'threshold', threshold: 2, subs: [liftMiniscript(args[0]!), liftMiniscript(args[1]!)] },
        liftMiniscript(args[2]!),
      ],
    };
  }
  invalid(`Unsupported Miniscript fragment '${node.name}' in a Liana spending policy`);
}

function liftTapTree(node: DescriptorAstNode): SemanticPolicy {
  if (node.kind === 'tree') {
    return { kind: 'threshold', threshold: 1, subs: [liftTapTree(node.left), liftTapTree(node.right)] };
  }
  return liftMiniscript(node);
}

function normalize(policy: SemanticPolicy): SemanticPolicy {
  if (policy.kind !== 'threshold') return policy;
  const subs = policy.subs.map(normalize);
  const trivialCount = subs.filter((sub) => sub.kind === 'trivial').length;
  const unsatisfiableCount = subs.filter((sub) => sub.kind === 'unsatisfiable').length;
  const n = subs.length - unsatisfiableCount - trivialCount;
  const m = Math.max(0, policy.threshold - trivialCount);
  const isAnd = m === n;
  const isOr = m === 1;
  const normalizedSubs: SemanticPolicy[] = [];
  for (const sub of subs) {
    if (sub.kind === 'trivial' || sub.kind === 'unsatisfiable') continue;
    if (sub.kind === 'threshold' && ((isAnd && sub.threshold === sub.subs.length) || (isOr && sub.threshold === 1))) {
      normalizedSubs.push(...sub.subs);
    } else {
      normalizedSubs.push(sub);
    }
  }
  if (m === 0) return { kind: 'trivial' };
  if (m > normalizedSubs.length) return { kind: 'unsatisfiable' };
  if (normalizedSubs.length === 1) return normalizedSubs[0]!;
  if (isAnd) return { kind: 'threshold', threshold: normalizedSubs.length, subs: normalizedSubs };
  if (isOr) return { kind: 'threshold', threshold: 1, subs: normalizedSubs };
  return { kind: 'threshold', threshold: m, subs: normalizedSubs };
}

function isKeyOrMultisig(policy: SemanticPolicy): boolean {
  return policy.kind === 'key' || (policy.kind === 'threshold' && policy.subs.every((sub) => sub.kind === 'key'));
}

function primaryPath(policy: SemanticPolicy, requireMultipath: boolean): PathInfo {
  if (policy.kind === 'key') return { kind: 'single', keys: [parseLianaKey(policy.descriptorKey, requireMultipath)] };
  if (policy.kind !== 'threshold' || !policy.subs.every((sub) => sub.kind === 'key')) invalid('Liana primary path must normalize to a key or a threshold of keys');
  const keys = policy.subs.map((sub) => parseLianaKey((sub as Extract<SemanticPolicy, { kind: 'key' }>).descriptorKey, requireMultipath));
  if (keys.length < 2 || keys.length > MAX_MULTISIG_KEYS || policy.threshold < 1 || policy.threshold > keys.length) invalid('Liana primary multisig must contain 2–20 keys and a valid threshold');
  return { kind: 'multi', threshold: policy.threshold, keys };
}

function recoveryPath(policy: SemanticPolicy, requireMultipath: boolean): { timelock: number; path: PathInfo } {
  if (policy.kind !== 'threshold') invalid('Liana recovery path must normalize to a threshold policy');
  if (policy.threshold === 2 && policy.subs.length === 2) {
    const timelock = policy.subs.find((sub) => sub.kind === 'older');
    const keys = policy.subs.find(isKeyOrMultisig);
    if (!timelock || timelock.kind !== 'older' || !keys) invalid('Liana recovery path must combine older() with a key-only policy');
    return { timelock: validTimelock(timelock.value), path: primaryPath(keys, requireMultipath) };
  }
  if (policy.threshold === policy.subs.length && policy.subs.length > 2) {
    let timelock: number | undefined;
    const keys: LianaKey[] = [];
    for (const sub of policy.subs) {
      if (sub.kind === 'older') {
        if (timelock !== undefined) invalid('Liana recovery path must contain exactly one older() timelock');
        timelock = validTimelock(sub.value);
      } else if (sub.kind === 'key') {
        keys.push(parseLianaKey(sub.descriptorKey, requireMultipath));
      } else {
        invalid('N-of-N Liana recovery paths may contain only keys and one older() timelock');
      }
    }
    if (timelock === undefined || keys.length < 2 || keys.length > MAX_MULTISIG_KEYS) invalid('N-of-N Liana recovery path has an invalid key/timelock count');
    return { timelock, path: { kind: 'multi', threshold: policy.threshold - 1, keys } };
  }
  invalid('Liana recovery path must be older() plus a key policy or N-of-N keys');
}

function validTimelock(value: number): number {
  if (value < 1 || value > UINT16_MAX) invalid('Liana recovery timelock must be a positive block-based uint16 value');
  return value;
}

function parseLianaKey(descriptorKey: string, requireMultipath: boolean): LianaKey {
  const value = descriptorKey.trim();
  const match = ORIGINATED_XPUB.exec(value);
  if (!match) invalid('Every Liana policy key must be an originated extended public key');
  const origin = match[1]!;
  const fingerprint = origin.split('/')[0]!.toLowerCase();
  const xpub = match[2]!;
  const suffix = value.slice(match[0].length);
  if (!suffix.endsWith('/*')) invalid('Every Liana policy key must have an unhardened wildcard');
  const derivation = suffix.slice(0, -2);
  if (derivation !== '' && !derivation.startsWith('/')) invalid('Malformed Liana extended-public-key derivation path');
  const segments = derivation === '' ? [] : derivation.slice(1).split('/');
  const multipathSegments = segments.filter((segment) => segment.startsWith('<') && segment.endsWith('>'));
  if (requireMultipath ? multipathSegments.length !== 1 : multipathSegments.length !== 0) invalid(requireMultipath
    ? 'Liana policy keys must contain exactly one two-choice multipath step'
    : 'Fixed-branch Liana policy keys must not contain a multipath step');
  if (!requireMultipath && segments.length === 0) invalid('Fixed-branch Liana policy keys require a normal derivation path');
  const alternatives: [string[], string[]] = [[], []];
  for (const segment of segments) {
    if (segment.startsWith('<') && segment.endsWith('>')) {
      const branches = segment.slice(1, -1).split(';');
      if (branches.length !== 2 || branches.some((branch) => !isNormalIndex(branch))) invalid('Liana multipath keys require two distinct normal child indexes');
      if (branches[0] === branches[1]) invalid('Liana multipath choices must be distinct');
      alternatives[0].push(branches[0]!);
      alternatives[1].push(branches[1]!);
    } else {
      if (!isNormalIndex(segment)) invalid('Liana public derivation paths must contain only normal child indexes');
      alternatives[0].push(segment);
      alternatives[1].push(segment);
    }
  }
  const identity = `${xpub}|${alternatives[0].join('/')}|${alternatives[1].join('/')}`;
  return { descriptorKey: value, fingerprint, identity };
}

function isNormalIndex(value: string): boolean {
  if (!/^(0|[1-9]\d*)$/.test(value)) return false;
  const index = Number(value);
  return Number.isSafeInteger(index) && index < 0x80000000;
}

function validatePathKeys(primary: PathInfo, recoveries: Iterable<PathInfo>): void {
  const identities = new Set<string>();
  const check = (path: PathInfo, label: 'primary' | 'recovery') => {
    if (path.kind === 'multi') {
      const fingerprints = new Set<string>();
      for (const key of path.keys) {
        if (fingerprints.has(key.fingerprint)) invalid(`Liana ${label} path contains duplicate master-fingerprint origins`);
        fingerprints.add(key.fingerprint);
      }
    }
    for (const key of path.keys) {
      if (identities.has(key.identity)) invalid('Liana descriptors must not reuse the same extended key and derivation path');
      identities.add(key.identity);
    }
  };
  check(primary, 'primary');
  for (const recovery of recoveries) check(recovery, 'recovery');
}

function validateTaproot(root: DescriptorAstNode, numsInternalKeyOffset: number | undefined): LianaPolicyPathClassification {
  const body = root.raw;
  const args = call(root, 'tr');
  if (!args || (args.length !== 1 && args.length !== 2)) invalid('Malformed Liana tr() descriptor');
  if (args.length !== 2) invalid('Liana Taproot descriptors require a recovery TapTree');
  const internal = args[0]!;
  const tree = args[1]!;
  const hasMultipath = body.includes('<');
  let treePolicy = liftTapTree(tree);
  const isNumsInternal = numsInternalKeyOffset !== undefined && internal.start <= numsInternalKeyOffset && numsInternalKeyOffset < internal.end;
  if (hasMultipath && !isNumsInternal) {
    try {
      parseLianaKey(keyArgument(internal) ?? invalid('Spendable Liana Taproot internal keys must be extended public keys'), true);
    } catch (error) {
      if (error instanceof WalletDerivationError) invalid('A spendable Liana Taproot internal key must be an originated multipath xpub with two normal derivation choices and an unhardened wildcard');
      throw error;
    }
  }
  if (!isNumsInternal) {
    treePolicy = { kind: 'threshold', threshold: 1, subs: [
      { kind: 'key', descriptorKey: keyArgument(internal) ?? invalid('Spendable Liana Taproot internal keys must be extended public keys') },
      treePolicy,
    ] };
  }
  return validateSpendingPolicy(normalize(treePolicy), hasMultipath);
}

function summarizePath(path: PathInfo): { kind: 'Single' | 'Multi'; threshold: number; keyCount: number } {
  return path.kind === 'single'
    ? { kind: 'Single', threshold: 1, keyCount: 1 }
    : { kind: 'Multi', threshold: path.threshold, keyCount: path.keys.length };
}

function validateSpendingPolicy(policy: SemanticPolicy, requireMultipath: boolean): LianaPolicyPathClassification {
  if (policy.kind !== 'threshold' || policy.threshold !== 1) invalid('Liana policy must normalize to one-of-N spending paths');
  let primary: PathInfo | undefined;
  const recoveries = new Map<number, PathInfo>();
  for (const sub of policy.subs) {
    if (isKeyOrMultisig(sub)) {
      if (!primary) primary = primaryPath(sub, requireMultipath);
      else if (sub.kind === 'key') {
        const additional = parseLianaKey(sub.descriptorKey, requireMultipath);
        if (primary.kind === 'single') primary = { kind: 'multi', threshold: 1, keys: [...primary.keys, additional] };
        else primary = { ...primary, keys: [...primary.keys, additional] };
      } else {
        invalid('Liana policy cannot contain multiple independent primary multisig paths');
      }
    } else {
      const recovery = recoveryPath(sub, requireMultipath);
      if (recoveries.has(recovery.timelock)) invalid('Liana recovery paths must have distinct relative timelocks');
      recoveries.set(recovery.timelock, recovery.path);
    }
  }
  if (!primary) invalid('Liana policy requires an always-available primary path');
  if (recoveries.size === 0) invalid('Liana policy requires at least one timelocked recovery path');
  validatePathKeys(primary, recoveries.values());
  return {
    primary: summarizePath(primary),
    recovery: [...recoveries.entries()]
      .sort(([left], [right]) => left - right)
      .map(([older, path]) => ({ older, ...summarizePath(path) })),
  };
}

export function validateLianaPolicySemantics(body: string, numsInternalKeyOffset: number | undefined): LianaPolicyPathClassification {
  const root = parseDescriptorAst(body).root;
  if (root.kind !== 'call' || root.name !== 'tr') invalid('Only Liana Taproot descriptors are handled by the semantic policy validator');
  return validateTaproot(root, numsInternalKeyOffset);
}
