#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { descriptorChecksum } from '../../src/descriptors.js';
import { constructUnspendableInternalXpub } from '../../src/taproot.js';

const SOURCE_ID = 'liana-v9-rust-taproot-multisig-vectors';
const LIANA_COMMIT = '398e622596e7530a328de3027cb2c09905f708c6';
const MINISCRIPT_VERSION = '11.2.0';
const RUSTC = '1.80.0 (051478957 2024-07-21)';
const CASE_ID = 'multisig-one-recovery';

function splitTopLevelPair(value: string): [string, string] {
  let parentheses = 0, braces = 0, brackets = 0;
  for (let i = 0; i < value.length; i++) {
    const char = value[i]!;
    if (char === '(') parentheses++;
    else if (char === ')') parentheses--;
    else if (char === '{') braces++;
    else if (char === '}') braces--;
    else if (char === '[') brackets++;
    else if (char === ']') brackets--;
    else if (char === ',' && parentheses === 0 && braces === 0 && brackets === 0) {
      return [value.slice(0, i), value.slice(i + 1)];
    }
  }
  throw new Error('expected exactly two top-level branches');
}

function makeDescriptor(tree: string): string {
  const xpubs = [...tree.matchAll(/(?:xpub|tpub)[1-9A-HJ-NP-Za-km-z]+/g)].map((match) => match[0]);
  const internal = constructUnspendableInternalXpub(xpubs, 'mainnet').descriptorKey;
  const body = `tr(${internal},${tree})`;
  return `${body}#${descriptorChecksum(body)}`;
}

function main(): void {
  const [sourcePath, outputPath] = process.argv.slice(2);
  if (!sourcePath || !outputPath) throw new Error(`Usage: ${process.argv[1]} SOURCE_FIXTURE.json OUTPUT.json`);
  const source = JSON.parse(readFileSync(sourcePath, 'utf8')) as {
    id: string;
    provenance: { lianaVersion: string; lianaCommit: string; miniscriptVersion: string; rustc: string; network: string };
    cases: Array<{ id: string; descriptor: string }>;
  };
  if (source.id !== SOURCE_ID) throw new Error('unexpected source fixture id');
  if (source.provenance.lianaVersion !== '9.0.0' || source.provenance.lianaCommit !== LIANA_COMMIT || source.provenance.miniscriptVersion !== MINISCRIPT_VERSION || source.provenance.rustc !== RUSTC || source.provenance.network !== 'mainnet') {
    throw new Error('source fixture does not match the pinned Liana/Miniscript/Rust mainnet provenance');
  }
  const item = source.cases.find((candidate) => candidate.id === CASE_ID);
  if (!item) throw new Error('source fixture is missing multisig-one-recovery');
  const sourceBody = item.descriptor.slice(0, item.descriptor.lastIndexOf('#'));
  if (descriptorChecksum(sourceBody) !== item.descriptor.slice(item.descriptor.lastIndexOf('#') + 1)) throw new Error('source descriptor checksum does not match its body');
  if (!sourceBody.startsWith('tr(') || !sourceBody.endsWith('})')) throw new Error('source descriptor has unexpected Taproot form');
  const internalStart = sourceBody.indexOf('tr(') + 3;
  const internalEnd = sourceBody.indexOf(',', internalStart);
  const sourceInternal = sourceBody.slice(internalStart, internalEnd);
  const [recovery, primary] = splitTopLevelPair(sourceBody.slice(internalEnd + 1, -1).trim().slice(1, -1));
  const primaryMatch = /^multi_a\(3,([\s\S]*)\)$/.exec(primary);
  const recoveryMatch = /and_v\(v:multi_a\(2,([^,]+),([^,]+),/.exec(recovery);
  if (!primaryMatch || !recoveryMatch || !sourceInternal.startsWith('xpub')) throw new Error('unexpected source primary/recovery policy shape');
  const primaryKeys = primaryMatch[1]!.split(',');
  if (primaryKeys.length !== 3) throw new Error('source primary must contain exactly three keys');
  const extraA = recoveryMatch[1]!
    .replace(/^\[4ba43603\]/, '[deadbeef]')
    .replace('/1/<0;1>/*', '/2/<0;1>/*');
  const extraB = recoveryMatch[2]!
    .replace(/^\[8dfc9b34\]/, '[cafebabe]')
    .replace('/1/<0;1>/*', '/2/<0;1>/*');
  if (extraA === recoveryMatch[1] || extraB === recoveryMatch[2]) throw new Error('candidate key derivation mutation did not apply');
  const cases = [
    {
      id: 'primary-multisig-then-single-key',
      tree: `{${recovery},{${primary},pk(${extraA})}}`,
      transformation: 'Keep the source recovery and primary multisig; append one separate single-key primary leaf with a distinct origin and derivation path.',
      expected: { accepted: true, primary: { threshold: 3, keyCount: 4 }, recovery: [{ older: 26352, threshold: 2, keyCount: 3 }] },
    },
    {
      id: 'primary-single-key-then-multisig',
      tree: `{${recovery},{pk(${extraA}),${primary}}}`,
      transformation: 'Keep the source recovery and primary multisig; place a separate single-key primary leaf before the multisig leaf.',
      expected: { accepted: false, error: 'IncompatibleDesc' },
    },
    {
      id: 'two-primary-multisig-leaves',
      tree: `{${recovery},{${primary},multi_a(2,${extraA},${extraB})}}`,
      transformation: 'Keep the source recovery and primary multisig; add a second distinct primary multisig leaf.',
      expected: { accepted: false, error: 'IncompatibleDesc' },
    },
    {
      id: 'two-primary-single-key-leaves',
      tree: `{${recovery},{pk(${extraA}),pk(${extraB})}}`,
      transformation: 'Replace the source primary multisig leaf with two ordered single-key primary leaves; retain the recovery path.',
      expected: { accepted: true, primary: { threshold: 1, keyCount: 2 }, recovery: [{ older: 26352, threshold: 2, keyCount: 3 }] },
    },
  ].map((entry) => ({
    ...entry,
    descriptor: makeDescriptor(entry.tree),
  }));
  const result = {
    id: 'liana-v9-rust-taproot-primary-path-shapes',
    provenance: { lianaVersion: '9.0.0', lianaCommit: LIANA_COMMIT, miniscriptVersion: MINISCRIPT_VERSION, rustc: RUSTC, network: 'mainnet', secretsOmitted: true },
    sourceFixture: SOURCE_ID,
    sourceCase: CASE_ID,
    cases,
  };
  writeFileSync(outputPath, `${JSON.stringify(result, null, 2)}\n`);
}

main();
