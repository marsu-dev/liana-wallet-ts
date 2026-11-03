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
export function parseMultipath(expression: string): DescriptorKeyExpression {
  const match = /^\[([0-9a-fA-F]{8})(?:\/([^\]]+))?\](tpub|xpub)([1-9A-HJ-NP-Za-km-z]+)\/<(\d+);(\d+)>\/\*$/.exec(expression);
  if (!match) throw new Error('Expected an originated xpub/tpub with two multipath choices and an unhardened wildcard');
  const originPath = match[2] ?? '';
  if (originPath.split('/').some((part) => !/^(0|[1-9]\d*)['hH]?$/.test(part))) throw new Error('Invalid key origin path');
  const branches = [Number(match[5]), Number(match[6])] as const;
  if (branches.some((value) => !Number.isSafeInteger(value) || value >= 0x80000000) || branches[0] === branches[1]) throw new Error('Multipath choices must be distinct non-hardened indexes');
  return { fingerprint: match[1]!.toLowerCase(), originPath, extendedPublicKey: `${match[3]}${match[4]}`, branches, wildcard: true };
}
