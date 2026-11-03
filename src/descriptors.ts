const INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const CHECKSUM_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GENERATORS = [0xf5dee51989n, 0xa9fdca3312n, 0x1bab10e32dn, 0x3706b1677an, 0x644d626ffdn];
export interface DescriptorKeyExpression { fingerprint: string; originPath: string; extendedPublicKey: string; branches: readonly [number, number]; wildcard: true; }
export function descriptorChecksum(body: string): string {
  let checksum = 1n, cls = 0, clsCount = 0;
  for (const char of body) {
    const pos = INPUT_CHARSET.indexOf(char);
    if (pos < 0) throw new Error(`Invalid descriptor character: ${char}`);
    const top = checksum >> 35n;
    checksum = ((checksum & 0x7ffffffffn) << 5n) ^ BigInt(pos & 31);
    for (let i = 0; i < 5; i++) if ((top >> BigInt(i)) & 1n) checksum ^= GENERATORS[i]!;
    cls = cls * 3 + (pos >> 5);
    if (++clsCount === 3) { checksum = polymod(checksum, cls); cls = 0; clsCount = 0; }
  }
  if (clsCount > 0) checksum = polymod(checksum, cls);
  for (let i = 0; i < 8; i++) checksum = polymod(checksum, 0);
  checksum ^= 1n;
  let result = '';
  for (let i = 0; i < 8; i++) result += CHECKSUM_CHARSET[Number((checksum >> BigInt(5 * (7 - i))) & 31n)];
  return result;
}
function polymod(checksum: bigint, value: number): bigint {
  const top = checksum >> 35n;
  checksum = ((checksum & 0x7ffffffffn) << 5n) ^ BigInt(value);
  for (let i = 0; i < 5; i++) if ((top >> BigInt(i)) & 1n) checksum ^= GENERATORS[i]!;
  return checksum;
}
export function splitDescriptorChecksum(text: string): { body: string; checksum: string } {
  const delimiter = text.lastIndexOf('#');
  if (delimiter < 0) throw new Error('Descriptor checksum is required');
  const body = text.slice(0, delimiter), checksum = text.slice(delimiter + 1);
  if (!/^[a-z0-9]{8}$/.test(checksum) || descriptorChecksum(body) !== checksum) throw new Error('Invalid descriptor checksum');
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
