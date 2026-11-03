import { WalletDerivationError } from './errors.js';
import { checksum as descriptorChecksum } from '@bitcoinerlab/descriptors';
export { descriptorChecksum };
export interface DescriptorKeyExpression { fingerprint: string; originPath: string; extendedPublicKey: string; branches: readonly [number, number]; wildcard: true; }
export function splitDescriptorChecksum(text: string): { body: string; checksum: string } {
  const delimiter = text.lastIndexOf('#');
  if (delimiter < 0) throw new WalletDerivationError('CHECKSUM_REQUIRED', 'Descriptor checksum is required');
  const body = text.slice(0, delimiter), checksum = text.slice(delimiter + 1);
  if (!/^[a-z0-9]{8}$/.test(checksum) || descriptorChecksum(body) !== checksum) throw new WalletDerivationError('INVALID_CHECKSUM', 'Invalid descriptor checksum');
  return { body, checksum };
}
export function selectMultipathBranch(body: string, selection: 0 | 1): { body: string; branchIndexes: number[] } {
  const matches = [...body.matchAll(/<(\d+);(\d+)>/g)];
  if (matches.length === 0) throw new WalletDerivationError('INVALID_DESCRIPTOR', 'Liana wallet descriptor has no two-choice multipath derivation');
  const branchPairs = matches.map((match) => [Number(match[1]), Number(match[2])] as const);
  if (branchPairs.some(([receive, change]) => !Number.isSafeInteger(receive) || !Number.isSafeInteger(change) || receive < 0 || change < 0 || receive >= 0x80000000 || change >= 0x80000000 || receive === change)) {
    throw new WalletDerivationError('INVALID_PATH', 'Multipath choices must be distinct non-hardened indexes');
  }
  const selectedBranchIndexes = branchPairs.map(([receive, change]) => selection === 0 ? receive : change);
  const selectedBody = body.replace(/<(\d+);(\d+)>/g, (_tuple, receive: string, change: string) => {
    return selection === 0 ? receive : change;
  });
  return { body: selectedBody, branchIndexes: selectedBranchIndexes };
}
export function parseMultipath(expression: string): DescriptorKeyExpression {
  const match = /^\[([0-9a-fA-F]{8})(?:\/([^\]]+))?\](tpub|xpub)([1-9A-HJ-NP-Za-km-z]+)\/<(\d+);(\d+)>\/\*$/.exec(expression);
  if (!match) throw new WalletDerivationError('INVALID_DESCRIPTOR', 'Expected an originated xpub/tpub with two multipath choices and an unhardened wildcard');
  const originPath = match[2] ?? '';
  if (originPath !== '' && originPath.split('/').some((part) => !/^(0|[1-9]\d*)['hH]?$/.test(part))) throw new WalletDerivationError('INVALID_ORIGIN', 'Invalid key origin path');
  const branches = [Number(match[5]), Number(match[6])] as const;
  if (branches.some((value) => !Number.isSafeInteger(value) || value >= 0x80000000) || branches[0] === branches[1]) throw new WalletDerivationError('INVALID_PATH', 'Multipath choices must be distinct non-hardened indexes');
  return { fingerprint: match[1]!.toLowerCase(), originPath, extendedPublicKey: `${match[3]}${match[4]}`, branches, wildcard: true };
}
