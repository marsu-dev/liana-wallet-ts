import { WalletDerivationError } from './errors.js';
import { checksum as descriptorChecksum } from '@bitcoinerlab/descriptors';
export { descriptorChecksum };
export interface DescriptorKeyExpression { fingerprint: string; originPath: string; extendedPublicKey: string; branches: readonly [number, number]; wildcard: true; }
export type DescriptorAstNode =
  | { kind: 'empty'; raw: string; start: number; end: number }
  | { kind: 'atom'; raw: string; start: number; end: number }
  | { kind: 'prefix'; operator: string; child: DescriptorAstNode; raw: string; start: number; end: number }
  | { kind: 'call'; name: string; arguments: readonly DescriptorAstNode[]; raw: string; start: number; end: number }
  | { kind: 'tree'; left: DescriptorAstNode; right: DescriptorAstNode; raw: string; start: number; end: number };
export interface DescriptorAst { source: string; root: DescriptorAstNode; }
function trimmedRange(source: string, start: number, end: number): [number, number] {
  while (start < end && /\s/.test(source[start]!)) start++;
  while (end > start && /\s/.test(source[end - 1]!)) end--;
  return [start, end];
}
function topLevelCommas(source: string, start: number, end: number): number[] {
  const positions: number[] = [];
  let parentheses = 0, braces = 0, brackets = 0;
  for (let index = start; index < end; index++) {
    const char = source[index]!;
    if (char === '(') parentheses++;
    else if (char === ')') parentheses--;
    else if (char === '{') braces++;
    else if (char === '}') braces--;
    else if (char === '[') brackets++;
    else if (char === ']') brackets--;
    else if (char === ',' && parentheses === 0 && braces === 0 && brackets === 0) positions.push(index);
    if (parentheses < 0 || braces < 0 || brackets < 0) throw new WalletDerivationError('INVALID_DESCRIPTOR', 'Unbalanced descriptor delimiters');
  }
  if (parentheses !== 0 || braces !== 0 || brackets !== 0) throw new WalletDerivationError('INVALID_DESCRIPTOR', 'Unbalanced descriptor delimiters');
  return positions;
}
function matchingDelimiter(source: string, start: number, end: number, open: string, close: string): number | undefined {
  let depth = 0;
  for (let index = start; index < end; index++) {
    if (source[index] === open) depth++;
    else if (source[index] === close && --depth === 0) return index;
  }
  return undefined;
}
function parseAstRange(source: string, start: number, end: number): DescriptorAstNode {
  const [contentStart, contentEnd] = trimmedRange(source, start, end);
  const raw = source.slice(start, end);
  const base = { raw, start, end };
  if (contentStart === contentEnd) return { kind: 'empty', ...base };
  const prefix = /^([a-z]):/.exec(source.slice(contentStart, contentEnd));
  if (prefix) return { kind: 'prefix', operator: prefix[1]!, child: parseAstRange(source, contentStart + prefix[0].length, contentEnd), ...base };
  if (source[contentStart] === '{' && source[contentEnd - 1] === '}') {
    const close = matchingDelimiter(source, contentStart, contentEnd, '{', '}');
    if (close === contentEnd - 1) {
      const commas = topLevelCommas(source, contentStart + 1, contentEnd - 1);
      if (commas.length !== 1) throw new WalletDerivationError('INVALID_DESCRIPTOR', 'Taproot tree nodes must contain exactly two branches');
      return {
        kind: 'tree',
        left: parseAstRange(source, contentStart + 1, commas[0]!),
        right: parseAstRange(source, commas[0]! + 1, contentEnd - 1),
        ...base,
      };
    }
  }
  const callMatch = /^([A-Za-z_][A-Za-z0-9_]*)\s*\(/.exec(source.slice(contentStart, contentEnd));
  if (callMatch) {
    const open = contentStart + callMatch[0].lastIndexOf('(');
    const close = matchingDelimiter(source, open, contentEnd, '(', ')');
    if (close === contentEnd - 1) {
      const commas = topLevelCommas(source, open + 1, close);
      const boundaries = [open + 1, ...commas.map((comma) => comma + 1)];
      const ends = [...commas, close];
      const arguments_ = open + 1 === close ? [] : boundaries.map((argStart, index) => parseAstRange(source, argStart, ends[index]!));
      return { kind: 'call', name: callMatch[1]!, arguments: arguments_, ...base };
    }
  }
  return { kind: 'atom', ...base };
}
export function parseDescriptorAst(source: string): DescriptorAst {
  return { source, root: parseAstRange(source, 0, source.length) };
}
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
