import { describe, expect, it } from 'vitest';
import { descriptorChecksum, splitDescriptorChecksum, parseMultipath, deriveDescriptorAddress, parseLianaDescriptor, deriveWalletAddress, WalletDerivationError, constructUnspendableInternalXpub, type DescriptorAstNode } from '../src/index.js';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseDescriptorAst } from '../src/descriptors.js';
import { validateLianaPolicySemantics } from '../src/liana-policy.js';
import { createHash } from 'node:crypto';
import { checksum as referenceDescriptorChecksum } from '@bitcoinerlab/descriptors';

const fixture = JSON.parse(readFileSync(resolve('tests/fixtures/liana-v9-signet-single-primary-recovery.json'), 'utf8')) as {
  receive: { descriptor: string; addressIndex0: string; scriptPubKeyIndex0: string; addresses0to9: string[] };
  change: { descriptor: string; addressIndex0: string; addresses0to9: string[] };
};

const rustMultisigFixture = JSON.parse(readFileSync(resolve('tests/fixtures/liana-v9-rust-taproot-multisig.json'), 'utf8')) as {
  provenance: { lianaCommit: string; miniscriptVersion: string; network: string };
  cases: Array<{
    id: string;
    descriptor: string;
    expected: Record<'receive' | 'change', Record<string, { address: string; scriptPubKey: string }>>;
  }>;
};
const rustTaprootThreshPrimaryFixture = JSON.parse(readFileSync(resolve('tests/fixtures/liana-v9-rust-taproot-thresh-primary.json'), 'utf8')) as {
  id: string;
  provenance: { lianaCommit: string; miniscriptVersion: string; rustc: string; network: string; secretsOmitted: boolean };
  sourceFixture: string;
  sourceCase: string;
  transformation: string;
  inferredPolicy: { primary: { threshold: number; keyCount: number }; recovery: Array<{ older: number; threshold: number; keyCount: number }> };
  descriptor: string;
  expected: Record<'receive' | 'change', Record<string, { address: string; scriptPubKey: string }>>;
};
const rustTaprootThreshRecoveryFixture = JSON.parse(readFileSync(resolve('tests/fixtures/liana-v9-rust-taproot-thresh-recovery.json'), 'utf8')) as {
  id: string;
  provenance: { lianaCommit: string; miniscriptVersion: string; rustc: string; network: string; secretsOmitted: boolean };
  sourceFixture: string;
  sourceCase: string;
  transformation: string;
  inferredPolicy: { primary: { threshold: number; keyCount: number }; recovery: Array<{ older: number; threshold: number; keyCount: number }> };
  descriptor: string;
  expected: Record<'receive' | 'change', Record<string, { address: string; scriptPubKey: string }>>;
};
const rustTaprootPrimaryPathShapesFixture = JSON.parse(readFileSync(resolve('tests/fixtures/liana-v9-rust-taproot-primary-path-shapes.json'), 'utf8')) as {
  id: string;
  provenance: { lianaCommit: string; miniscriptVersion: string; rustc: string; network: string; secretsOmitted: boolean };
  sourceFixture: string;
  sourceCase: string;
  purpose: string;
  cases: Array<{ id: string; transformation: string; expected: { accepted: boolean; primary?: { threshold: number; keyCount: number }; recovery?: Array<{ older: number; threshold: number; keyCount: number }>; error?: string }; descriptor: string }>;
};
const rustTaprootDuplicateOriginFixture = JSON.parse(readFileSync(resolve('tests/fixtures/liana-v9-rust-taproot-duplicate-origin-same-path.json'), 'utf8')) as {
  id: string;
  provenance: { lianaCommit: string; miniscriptVersion: string; rustc: string; network: string; secretsOmitted: boolean };
  sourceFixture: string;
  sourceCase: string;
  transformation: string;
  expectedRejection: string;
  descriptor: string;
};
const rustTaprootDuplicateOriginRecoveryFixture = JSON.parse(readFileSync(resolve('tests/fixtures/liana-v9-rust-taproot-duplicate-origin-recovery-same-path.json'), 'utf8')) as {
  id: string;
  provenance: { lianaCommit: string; miniscriptVersion: string; rustc: string; network: string; secretsOmitted: boolean };
  sourceFixture: string;
  sourceCase: string;
  transformation: string;
  expectedRejection: string;
  descriptor: string;
};
const rustPolicyRejectionFixture = JSON.parse(readFileSync(resolve('tests/fixtures/liana-v9-rust-policy-rejections.json'), 'utf8')) as {
  provenance: { lianaCommit: string; miniscriptVersion: string; rustc: string; oracle: string };
  cases: Array<{ id: string; descriptor: string; expected: { accepted: boolean; error: string } }>;
};
const rustSignetSinglePrimaryFixture = JSON.parse(readFileSync(resolve('tests/fixtures/liana-v9-rust-signet-single-primary-recovery.json'), 'utf8')) as {
  provenance: { lianaCommit: string; miniscriptVersion: string; network: string };
  multipathDescriptorBody: string;
};
const rustSignetSingleKeyMultiAFixture = JSON.parse(readFileSync(resolve('tests/fixtures/liana-v9-rust-signet-single-key-multi-a.json'), 'utf8')) as {
  provenance: { lianaCommit: string; miniscriptVersion: string; network: string; rustc: string };
  transformation: string;
  inferredPolicy: { primary: string; recovery: { older: number; path: string } };
  descriptor: string;
  expected: Record<'receive' | 'change', Record<string, { address: string; scriptPubKey: string }>>;
};
const rustSignetDuplicateXpubFixture = JSON.parse(readFileSync(resolve('tests/fixtures/liana-v9-rust-signet-duplicate-xpub.json'), 'utf8')) as {
  provenance: { sourceFixture: string; lianaCommit: string; miniscriptVersion: string; network: string; rustc: string };
  transformation: string;
  expectedRejection: string;
  descriptor: string;
};
const rustSignetFlattenedInternalKeyFixture = JSON.parse(readFileSync(resolve('tests/fixtures/liana-v9-rust-signet-flattened-internal-key-rejection.json'), 'utf8')) as {
  id: string;
  provenance: { lianaCommit: string; miniscriptVersion: string; rustc: string; network: string; secretsOmitted: boolean };
  sourceFixture: string;
  transformation: string;
  expectedRejection: string;
  descriptor: string;
};
const rustSignetInternalPrimaryLeafDuplicateOriginFixture = JSON.parse(readFileSync(resolve('tests/fixtures/liana-v9-rust-signet-internal-primary-leaf-duplicate-origin.json'), 'utf8')) as {
  id: string;
  provenance: { lianaCommit: string; miniscriptVersion: string; rustc: string; network: string; secretsOmitted: boolean };
  sourceFixture: string;
  transformation: string;
  expectedRejection: string;
  descriptor: string;
};
const rustSignetFixedBranchRecoveryFixture = JSON.parse(readFileSync(resolve('tests/fixtures/liana-v9-rust-signet-fixed-branch-recovery.json'), 'utf8')) as {
  provenance: { sourceFixture: string; lianaCommit: string; miniscriptVersion: string; network: string; rustc: string };
  transformation: string;
  expectedRejection: string;
  descriptor: string;
};

const legacyWshFixture = JSON.parse(readFileSync(resolve('tests/fixtures/liana-v9-rust-legacy-wsh.json'), 'utf8')) as {
  provenance: { lianaCommit: string; miniscriptVersion: string; network: string };
  descriptor: string;
  expected: Record<'receive' | 'change', Record<string, { address: string; scriptPubKey: string }>>;
};

const legacyWshMultisigFixture = JSON.parse(readFileSync(resolve('tests/fixtures/liana-v9-rust-legacy-wsh-multisig.json'), 'utf8')) as {
  provenance: { lianaCommit: string; miniscriptVersion: string; network: string };
  descriptor: string;
  expected: Record<'receive' | 'change', Record<string, { address: string; scriptPubKey: string }>>;
};
const legacyWshMultipleRecoveryFixture = JSON.parse(readFileSync(resolve('tests/fixtures/liana-v9-rust-legacy-wsh-multiple-recovery.json'), 'utf8')) as {
  provenance: { lianaCommit: string; miniscriptVersion: string; network: string };
  descriptor: string;
  expected: Record<'receive' | 'change', Record<string, { address: string; scriptPubKey: string }>>;
};
const legacyWshAndorFixture = JSON.parse(readFileSync(resolve('tests/fixtures/liana-v9-rust-legacy-wsh-andor.json'), 'utf8')) as {
  provenance: { lianaCommit: string; miniscriptVersion: string; network: string };
  descriptor: string;
  expected: Record<'receive' | 'change', Record<string, { address: string; scriptPubKey: string }>>;
};
const legacyWshV2ThresholdsFixture = JSON.parse(readFileSync(resolve('tests/fixtures/liana-v9-rust-legacy-wsh-v2-thresholds.json'), 'utf8')) as {
  provenance: { lianaCommit: string; miniscriptVersion: string; network: string };
  descriptor: string;
  expected: Record<'receive' | 'change', Record<string, { address: string; scriptPubKey: string }>>;
};
const signetV2Bip32Fixture = JSON.parse(readFileSync(resolve('tests/fixtures/liana-v9-rust-signet-v2-bip32-derivs.json'), 'utf8')) as {
  provenance: { lianaCommit: string; miniscriptVersion: string; network: string };
  descriptor: string;
  expected: Record<'receive' | 'change', Record<string, { address: string; scriptPubKey: string }>>;
};

function descriptorWithBody(body: string): string {
  return `${body}#${descriptorChecksum(body)}`;
}
function assertAstSourceRanges(node: DescriptorAstNode, source: string): void {
  expect(source.slice(node.start, node.end)).toBe(node.raw);
  if (node.kind === 'call') node.arguments.forEach((argument) => assertAstSourceRanges(argument, source));
  else if (node.kind === 'tree') {
    assertAstSourceRanges(node.left, source);
    assertAstSourceRanges(node.right, source);
  } else if (node.kind === 'prefix') assertAstSourceRanges(node.child, source);
}

describe('descriptor primitives', () => {
  it('distinguishes zero-argument calls from explicit empty argument nodes', () => {
    const zero = parseDescriptorAst('probe()').root;
    expect(zero.kind).toBe('call');
    if (zero.kind !== 'call') throw new Error('expected call node');
    expect(zero.arguments).toHaveLength(0);

    const withEmpty = parseDescriptorAst('probe(,x)').root;
    expect(withEmpty.kind).toBe('call');
    if (withEmpty.kind !== 'call') throw new Error('expected call node');
    expect(withEmpty.arguments).toHaveLength(2);
    expect(withEmpty.arguments[0]).toMatchObject({ kind: 'empty', raw: '', start: 6, end: 6 });
  });
  it('uses the descriptor library checksum implementation', () => {
    expect(descriptorChecksum).toBe(referenceDescriptorChecksum);
  });
  it('reports typed failures for malformed multipath syntax and metadata', () => {
    expect(parseMultipath('[0123abcd]tpubABC/<0;1>/*').originPath).toBe('');
    expect(() => parseMultipath('not a descriptor')).toThrowError(expect.objectContaining({ code: 'INVALID_DESCRIPTOR' }));
    expect(() => parseMultipath('[0123abcd/invalid]tpubABC/<0;1>/*')).toThrowError(expect.objectContaining({ code: 'INVALID_ORIGIN' }));
    expect(() => parseMultipath('[0123abcd]tpubABC/<1;1>/*')).toThrowError(expect.objectContaining({ code: 'INVALID_PATH' }));
  });
  it('computes the Bitcoin Core checksum vector for raw(deadbeef)', () => {
    expect(descriptorChecksum('raw(deadbeef)')).toBe('89f8spxm');
  });
  it('verifies receive and change checksums in the Liana Signet fixture', () => {
    expect(splitDescriptorChecksum(fixture.receive.descriptor).checksum).toBe('22y0dhdd');
    expect(splitDescriptorChecksum(fixture.change.descriptor).checksum).toBe('gcgkq5nc');
    expect(fixture.receive.addressIndex0).toBe('tb1pvpqeka564yfls5ma8ps56q2xd4sn8mstm7pe6nfxezw3wc963pysnda6x9');
    expect(fixture.change.addressIndex0).toBe('tb1prn8cy7j5q8sc2g7ahgexmjfxauwvluvp7m80gvw9rzzrdnpculpsw6h524');
  });
  it('derives the receive fixture index-0 address and scriptPubKey', () => {
    const derived = deriveDescriptorAddress(fixture.receive.descriptor, 0, 'signet');
    expect(derived.address).toBe(fixture.receive.addressIndex0);
    expect(Buffer.from(derived.scriptPubKey).toString('hex')).toBe(fixture.receive.scriptPubKeyIndex0);
  });
  it('derives the change fixture index-0 address', () => {
    expect(deriveDescriptorAddress(fixture.change.descriptor, 0, 'signet').address).toBe(fixture.change.addressIndex0);
  });
  it('matches all ten receive and change addresses from the independent fixture', () => {
    expect(fixture.receive.addresses0to9).toHaveLength(10);
    expect(fixture.change.addresses0to9).toHaveLength(10);
    for (const [index, address] of fixture.receive.addresses0to9.entries()) expect(deriveDescriptorAddress(fixture.receive.descriptor, index, 'signet').address).toBe(address);
    for (const [index, address] of fixture.change.addresses0to9.entries()) expect(deriveDescriptorAddress(fixture.change.descriptor, index, 'signet').address).toBe(address);
  });
  it('maps receive/change to the ordered values in a multipath descriptor', () => {
    const body = fixture.receive.descriptor.slice(0, fixture.receive.descriptor.lastIndexOf('#')).replaceAll('/0/*', '/<0;1>/*');
    const multipath = `${body}#${descriptorChecksum(body)}`;
    const wallet = parseLianaDescriptor(multipath, 'signet');
    expect(deriveWalletAddress(wallet, 'receive', 0).address).toBe(fixture.receive.addressIndex0);
    expect(deriveWalletAddress(wallet, 'change', 0).address).toBe(fixture.change.addressIndex0);
  });
  it('matches the pinned Liana Rust Taproot single-key and multisig address/script vectors', () => {
    expect(rustMultisigFixture.provenance).toMatchObject({ lianaCommit: '398e622596e7530a328de3027cb2c09905f708c6', miniscriptVersion: '11.2.0', network: 'mainnet' });
    expect(rustMultisigFixture.cases.map((item) => item.id)).toEqual(['single-primary-recovery', 'multisig-one-recovery', 'multisig-distinct-branch-values', 'multisig-multiple-recovery', 'taproot-multi-a-multiple-recovery']);
    let checked = 0;
    for (const item of rustMultisigFixture.cases) {
      const wallet = parseLianaDescriptor(item.descriptor, 'mainnet');
      const body = splitDescriptorChecksum(item.descriptor).body;
      expect(wallet.original).toBe(item.descriptor);
      expect(wallet.ast.source).toBe(body);
      assertAstSourceRanges(wallet.ast.root, body);
      for (const branch of ['receive', 'change'] as const) {
        for (const index of [0, 1]) {
          const actual = deriveWalletAddress(wallet, branch, index);
          const expected = item.expected[branch][String(index)]!;
          expect(actual.address, `${item.id} ${branch} ${index} address`).toBe(expected.address);
          expect(Buffer.from(actual.scriptPubKey).toString('hex'), `${item.id} ${branch} ${index} scriptPubKey`).toBe(expected.scriptPubKey);
          checked++;
        }
      }
    }
    expect(checked).toBe(20);
  });
  it('matches the pinned parser-derived key-only thresh primary policy', () => {
    expect(rustTaprootThreshPrimaryFixture.id).toBe('liana-v9-rust-taproot-thresh-primary-vectors');
    expect(rustTaprootThreshPrimaryFixture.provenance).toMatchObject({
      lianaCommit: '398e622596e7530a328de3027cb2c09905f708c6',
      miniscriptVersion: '11.2.0',
      rustc: '1.80.0 (051478957 2024-07-21)',
      network: 'mainnet',
      secretsOmitted: true,
    });
    expect(rustTaprootThreshPrimaryFixture.sourceFixture).toBe('liana-v9-rust-taproot-multisig-vectors');
    expect(rustTaprootThreshPrimaryFixture.sourceCase).toBe('multisig-one-recovery');
    expect(rustTaprootThreshPrimaryFixture.inferredPolicy).toEqual({
      primary: { threshold: 3, keyCount: 3 },
      recovery: [{ older: 26352, threshold: 2, keyCount: 3 }],
    });
    expect(rustTaprootThreshPrimaryFixture.transformation).toContain('only the primary multi_a(3,key1,key2,key3) leaf');

    const source = rustMultisigFixture.cases.find((item) => item.id === rustTaprootThreshPrimaryFixture.sourceCase);
    if (!source) throw new Error('expected pinned Rust source multisig case');
    const sourceBody = splitDescriptorChecksum(source.descriptor).body;
    const primaryStart = sourceBody.indexOf('multi_a(3,');
    const primaryEnd = sourceBody.indexOf(')', primaryStart) + 1;
    expect(primaryStart).toBeGreaterThan(0);
    expect(primaryEnd).toBeGreaterThan(primaryStart);
    const sourcePrimary = sourceBody.slice(primaryStart, primaryEnd);
    const keys = sourcePrimary.slice('multi_a(3,'.length, -1).split(',');
    expect(keys).toHaveLength(3);
    const candidatePrimary = `thresh(3,pk(${keys[0]}),s:pk(${keys[1]}),s:pk(${keys[2]}))`;
    const candidateBody = sourceBody.replace(sourcePrimary, candidatePrimary);
    expect(candidateBody.replace(candidatePrimary, sourcePrimary)).toBe(sourceBody);
    expect(rustTaprootThreshPrimaryFixture.descriptor).toBe(descriptorWithBody(candidateBody));

    const wallet = parseLianaDescriptor(rustTaprootThreshPrimaryFixture.descriptor, 'mainnet');
    expect(wallet.original).toBe(rustTaprootThreshPrimaryFixture.descriptor);
    let checked = 0;
    for (const branch of ['receive', 'change'] as const) {
      for (let index = 0; index < 10; index++) {
        const actual = deriveWalletAddress(wallet, branch, index);
        const expected = rustTaprootThreshPrimaryFixture.expected[branch][String(index)]!;
        expect(actual.address, `${branch} ${index} address`).toBe(expected.address);
        expect(Buffer.from(actual.scriptPubKey).toString('hex'), `${branch} ${index} scriptPubKey`).toBe(expected.scriptPubKey);
        checked++;
      }
    }
    expect(checked).toBe(20);
  });
  it('matches the pinned parser-derived key-only thresh recovery policy', () => {
    expect(rustTaprootThreshRecoveryFixture.id).toBe('liana-v9-rust-taproot-thresh-recovery-vectors');
    expect(rustTaprootThreshRecoveryFixture.provenance).toMatchObject({
      lianaCommit: '398e622596e7530a328de3027cb2c09905f708c6',
      miniscriptVersion: '11.2.0',
      rustc: '1.80.0 (051478957 2024-07-21)',
      network: 'mainnet',
      secretsOmitted: true,
    });
    expect(rustTaprootThreshRecoveryFixture.sourceFixture).toBe('liana-v9-rust-taproot-multisig-vectors');
    expect(rustTaprootThreshRecoveryFixture.sourceCase).toBe('multisig-one-recovery');
    expect(rustTaprootThreshRecoveryFixture.inferredPolicy).toEqual({
      primary: { threshold: 3, keyCount: 3 },
      recovery: [{ older: 26352, threshold: 2, keyCount: 3 }],
    });
    expect(rustTaprootThreshRecoveryFixture.transformation).toContain('only the recovery multi_a(2,key1,key2,key3) leaf');

    const source = rustMultisigFixture.cases.find((item) => item.id === rustTaprootThreshRecoveryFixture.sourceCase);
    if (!source) throw new Error('expected pinned Rust source multisig case');
    const sourceBody = splitDescriptorChecksum(source.descriptor).body;
    const recoveryStart = sourceBody.indexOf('and_v(v:multi_a(2,');
    const policyStart = sourceBody.indexOf('multi_a(2,', recoveryStart);
    const policyEnd = sourceBody.indexOf(')', policyStart) + 1;
    expect(recoveryStart).toBeGreaterThan(0);
    expect(policyStart).toBeGreaterThan(recoveryStart);
    expect(policyEnd).toBeGreaterThan(policyStart);
    const sourcePolicy = sourceBody.slice(policyStart, policyEnd);
    const keys = sourcePolicy.slice('multi_a(2,'.length, -1).split(',');
    expect(keys).toHaveLength(3);
    const candidatePolicy = `thresh(2,pk(${keys[0]}),s:pk(${keys[1]}),s:pk(${keys[2]}))`;
    const candidateBody = sourceBody.replace(sourcePolicy, candidatePolicy);
    expect(candidateBody.replace(candidatePolicy, sourcePolicy)).toBe(sourceBody);
    expect(candidateBody).toContain('multi_a(3,');
    expect(rustTaprootThreshRecoveryFixture.descriptor).toBe(descriptorWithBody(candidateBody));

    const wallet = parseLianaDescriptor(rustTaprootThreshRecoveryFixture.descriptor, 'mainnet');
    expect(wallet.original).toBe(rustTaprootThreshRecoveryFixture.descriptor);
    let checked = 0;
    for (const branch of ['receive', 'change'] as const) {
      for (let index = 0; index < 10; index++) {
        const actual = deriveWalletAddress(wallet, branch, index);
        const expected = rustTaprootThreshRecoveryFixture.expected[branch][String(index)]!;
        expect(actual.address, `${branch} ${index} address`).toBe(expected.address);
        expect(Buffer.from(actual.scriptPubKey).toString('hex'), `${branch} ${index} scriptPubKey`).toBe(expected.scriptPubKey);
        checked++;
      }
    }
    expect(checked).toBe(20);
  });
  it('matches Rust primary-path extraction for ordered Taproot primary leaves', () => {
    expect(rustTaprootPrimaryPathShapesFixture.id).toBe('liana-v9-rust-taproot-primary-path-shapes');
    expect(rustTaprootPrimaryPathShapesFixture.provenance).toMatchObject({
      lianaCommit: '398e622596e7530a328de3027cb2c09905f708c6',
      miniscriptVersion: '11.2.0',
      rustc: '1.80.0 (051478957 2024-07-21)',
      network: 'mainnet',
      secretsOmitted: true,
    });
    expect(rustTaprootPrimaryPathShapesFixture.sourceFixture).toBe('liana-v9-rust-taproot-multisig-vectors');
    expect(rustTaprootPrimaryPathShapesFixture.sourceCase).toBe('multisig-one-recovery');
    expect(rustTaprootPrimaryPathShapesFixture.cases.every((item) => !('expectedOutputs' in item))).toBe(true);

    const source = rustMultisigFixture.cases.find((item) => item.id === rustTaprootPrimaryPathShapesFixture.sourceCase);
    if (!source) throw new Error('expected pinned Rust source multisig case');
    const sourceBody = splitDescriptorChecksum(source.descriptor).body;
    const sourceAst = parseDescriptorAst(sourceBody).root;
    if (sourceAst.kind !== 'call' || sourceAst.name !== 'tr' || sourceAst.arguments[1]?.kind !== 'tree') throw new Error('expected binary Taproot source tree');
    const recovery = sourceAst.arguments[1].left.raw;
    const primary = sourceAst.arguments[1].right.raw;
    const recoveryPolicy = /multi_a\(2,([^)]*)\)/.exec(recovery)?.[1];
    if (!recoveryPolicy) throw new Error('expected source recovery multi_a leaf');
    const recoveryKeys = recoveryPolicy.split(',');
    expect(recoveryKeys).toHaveLength(3);
    const extraA = recoveryKeys[0]!.replace(/^\[4ba43603\]/, '[deadbeef]').replace('/1/<0;1>/*', '/2/<0;1>/*');
    const extraB = recoveryKeys[1]!.replace(/^\[8dfc9b34\]/, '[cafebabe]').replace('/1/<0;1>/*', '/2/<0;1>/*');
    expect(extraA).not.toBe(recoveryKeys[0]);
    expect(extraB).not.toBe(recoveryKeys[1]);

    const trees: Record<string, string> = {
      'primary-multisig-then-single-key': `{${recovery},{${primary},pk(${extraA})}}`,
      'primary-single-key-then-multisig': `{${recovery},{pk(${extraA}),${primary}}}`,
      'two-primary-multisig-leaves': `{${recovery},{${primary},multi_a(2,${extraA},${extraB})}}`,
      'two-primary-single-key-leaves': `{${recovery},{pk(${extraA}),pk(${extraB})}}`,
    };
    for (const item of rustTaprootPrimaryPathShapesFixture.cases) {
      const tree = trees[item.id];
      if (!tree) throw new Error(`unexpected primary-path oracle case: ${item.id}`);
      const leafXpubs = [...tree.matchAll(/(?:xpub|tpub)[1-9A-HJ-NP-Za-km-z]+/g)].map((match) => match[0]);
      const internal = constructUnspendableInternalXpub(leafXpubs, 'mainnet').descriptorKey;
      const body = `tr(${internal},${tree})`;
      expect(item.descriptor).toBe(descriptorWithBody(body));
      if (item.expected.accepted) {
        const wallet = parseLianaDescriptor(item.descriptor, 'mainnet');
        expect(wallet.original).toBe(item.descriptor);
        expect(wallet.ast.source).toBe(body);
        const root = parseDescriptorAst(body).root;
        if (root.kind !== 'call' || root.arguments[0]?.kind !== 'atom') throw new Error('expected descriptor with an internal key');
        const internalOffset = body.indexOf(root.arguments[0].raw.trim());
        const inferred = validateLianaPolicySemantics(body, internalOffset);
        expect(inferred).toEqual({
          primary: { kind: 'Multi', threshold: item.expected.primary!.threshold, keyCount: item.expected.primary!.keyCount },
          recovery: item.expected.recovery!.map((path) => ({
            older: path.older,
            kind: path.keyCount === 1 ? 'Single' : 'Multi',
            threshold: path.threshold,
            keyCount: path.keyCount,
          })),
        });
      } else {
        expect(item.expected.error).toBe('IncompatibleDesc');
        expect(() => parseLianaDescriptor(item.descriptor, 'mainnet')).toThrowError(expect.objectContaining({ code: 'INVALID_DESCRIPTOR' }));
      }
    }
  });
  it('matches the pinned DuplicateOriginSamePath rejection when primary key origins repeat', () => {
    expect(rustTaprootDuplicateOriginFixture.id).toBe('liana-v9-rust-taproot-duplicate-origin-same-path');
    expect(rustTaprootDuplicateOriginFixture.provenance).toMatchObject({
      lianaCommit: '398e622596e7530a328de3027cb2c09905f708c6',
      miniscriptVersion: '11.2.0',
      rustc: '1.80.0 (051478957 2024-07-21)',
      network: 'mainnet',
      secretsOmitted: true,
    });
    expect(rustTaprootDuplicateOriginFixture.sourceFixture).toBe('liana-v9-rust-taproot-multisig-vectors');
    expect(rustTaprootDuplicateOriginFixture.sourceCase).toBe('multisig-one-recovery');
    expect(rustTaprootDuplicateOriginFixture.expectedRejection).toBe('DuplicateOriginSamePath');
    expect(rustTaprootDuplicateOriginFixture.transformation).toContain('only the primary multisig\'s second key origin fingerprint');

    const source = rustMultisigFixture.cases.find((item) => item.id === rustTaprootDuplicateOriginFixture.sourceCase);
    if (!source) throw new Error('expected pinned Rust source multisig case');
    const sourceBody = splitDescriptorChecksum(source.descriptor).body;
    const primaryStart = sourceBody.indexOf('multi_a(3,');
    const primaryEnd = sourceBody.indexOf(')', primaryStart) + 1;
    expect(primaryStart).toBeGreaterThan(0);
    expect(primaryEnd).toBeGreaterThan(primaryStart);
    const sourcePrimary = sourceBody.slice(primaryStart, primaryEnd);
    const keys = sourcePrimary.slice('multi_a(3,'.length, -1).split(',');
    expect(keys).toHaveLength(3);
    expect(keys[0]).toMatch(/^\[4ba43603\]/);
    expect(keys[1]).toMatch(/^\[8dfc9b34\]/);
    expect(keys[0]!.slice('[4ba43603]'.length)).not.toBe(keys[1]!.slice('[8dfc9b34]'.length));
    const changedKey = keys[1]!.replace(/^\[8dfc9b34\]/, '[4ba43603]');
    expect(changedKey.slice('[4ba43603]'.length)).toBe(keys[1]!.slice('[8dfc9b34]'.length));
    const candidatePrimary = `multi_a(3,${keys[0]},${changedKey},${keys[2]})`;
    const candidateBody = sourceBody.replace(sourcePrimary, candidatePrimary);
    expect(candidateBody.replace(candidatePrimary, sourcePrimary)).toBe(sourceBody);
    expect(candidateBody).toContain('and_v(v:multi_a(2,');
    expect(rustTaprootDuplicateOriginFixture.descriptor).toBe(descriptorWithBody(candidateBody));

    expect(() => parseLianaDescriptor(rustTaprootDuplicateOriginFixture.descriptor, 'mainnet')).toThrowError(
      expect.objectContaining({ code: 'INVALID_DESCRIPTOR', message: expect.stringContaining('duplicate master-fingerprint origins') }),
    );
  });
  it('matches the pinned DuplicateOriginSamePath rejection when recovery key origins repeat', () => {
    expect(rustTaprootDuplicateOriginRecoveryFixture.id).toBe('liana-v9-rust-taproot-duplicate-origin-recovery-same-path');
    expect(rustTaprootDuplicateOriginRecoveryFixture.provenance).toMatchObject({
      lianaCommit: '398e622596e7530a328de3027cb2c09905f708c6',
      miniscriptVersion: '11.2.0',
      rustc: '1.80.0 (051478957 2024-07-21)',
      network: 'mainnet',
      secretsOmitted: true,
    });
    expect(rustTaprootDuplicateOriginRecoveryFixture.sourceFixture).toBe('liana-v9-rust-taproot-multisig-vectors');
    expect(rustTaprootDuplicateOriginRecoveryFixture.sourceCase).toBe('multisig-one-recovery');
    expect(rustTaprootDuplicateOriginRecoveryFixture.expectedRejection).toBe('DuplicateOriginSamePath');
    expect(rustTaprootDuplicateOriginRecoveryFixture.transformation).toContain('only the recovery multi_a(2,...) second key origin fingerprint');

    const source = rustMultisigFixture.cases.find((item) => item.id === rustTaprootDuplicateOriginRecoveryFixture.sourceCase);
    if (!source) throw new Error('expected pinned Rust source multisig case');
    const sourceBody = splitDescriptorChecksum(source.descriptor).body;
    const recoveryStart = sourceBody.indexOf('and_v(v:multi_a(2,');
    const policyStart = sourceBody.indexOf('multi_a(2,', recoveryStart);
    const policyEnd = sourceBody.indexOf(')', policyStart) + 1;
    expect(recoveryStart).toBeGreaterThan(0);
    expect(policyStart).toBeGreaterThan(recoveryStart);
    expect(policyEnd).toBeGreaterThan(policyStart);
    const sourcePolicy = sourceBody.slice(policyStart, policyEnd);
    const keys = sourcePolicy.slice('multi_a(2,'.length, -1).split(',');
    expect(keys).toHaveLength(3);
    expect(keys[0]).toMatch(/^\[4ba43603\]/);
    expect(keys[1]).toMatch(/^\[8dfc9b34\]/);
    expect(keys[0]!.slice('[4ba43603]'.length)).not.toBe(keys[1]!.slice('[8dfc9b34]'.length));
    const changedKey = keys[1]!.replace(/^\[8dfc9b34\]/, '[4ba43603]');
    expect(changedKey.slice('[4ba43603]'.length)).toBe(keys[1]!.slice('[8dfc9b34]'.length));
    const candidatePolicy = `multi_a(2,${keys[0]},${changedKey},${keys[2]})`;
    const candidateBody = sourceBody.replace(sourcePolicy, candidatePolicy);
    expect(candidateBody.replace(candidatePolicy, sourcePolicy)).toBe(sourceBody);
    expect(candidateBody.slice(0, recoveryStart)).toBe(sourceBody.slice(0, recoveryStart));
    expect(candidateBody).toContain('multi_a(3,');
    expect(rustTaprootDuplicateOriginRecoveryFixture.descriptor).toBe(descriptorWithBody(candidateBody));

    expect(() => parseLianaDescriptor(rustTaprootDuplicateOriginRecoveryFixture.descriptor, 'mainnet')).toThrowError(
      expect.objectContaining({ code: 'INVALID_DESCRIPTOR', message: expect.stringContaining('recovery path contains duplicate master-fingerprint origins') }),
    );
  });
  it('matches DuplicateOriginSamePath across internal primary and primary leaf keys', () => {
    expect(rustSignetInternalPrimaryLeafDuplicateOriginFixture.id).toBe('liana-v9-rust-signet-internal-primary-leaf-duplicate-origin');
    expect(rustSignetInternalPrimaryLeafDuplicateOriginFixture.provenance).toMatchObject({
      lianaCommit: '398e622596e7530a328de3027cb2c09905f708c6',
      miniscriptVersion: '11.2.0',
      rustc: '1.80.0 (051478957 2024-07-21)',
      network: 'signet',
      secretsOmitted: true,
    });
    expect(rustSignetInternalPrimaryLeafDuplicateOriginFixture.sourceFixture).toBe('liana-v9-rust-signet-single-primary-recovery-vectors');
    expect(rustSignetInternalPrimaryLeafDuplicateOriginFixture.expectedRejection).toBe('DuplicateOriginSamePath');
    expect(rustSignetInternalPrimaryLeafDuplicateOriginFixture.transformation).toContain('change only its origin fingerprint to match the distinct spendable internal primary xpub');

    const sourceBody = rustSignetSinglePrimaryFixture.multipathDescriptorBody;
    const internalStart = sourceBody.indexOf('tr(') + 'tr('.length;
    const internalEnd = sourceBody.indexOf(',', internalStart);
    const internal = sourceBody.slice(internalStart, internalEnd);
    const recovery = sourceBody.slice(internalEnd + 1, -1);
    expect(internal).toMatch(/^\[07fd816d\//);
    expect(recovery).toMatch(/^and_v\(v:pk\(\[da855a1f\//);
    const recoveryKey = recovery.slice('and_v(v:pk('.length, -'),older(36))'.length);
    const primaryKey = recoveryKey
      .replace(/^\[da855a1f\//, '[07fd816d/')
      .replace('/<0;1>/*', '/0/<0;1>/*');
    expect(primaryKey.replace('/0/<0;1>/*', '/<0;1>/*').replace(/^\[07fd816d\//, '[da855a1f/')).toBe(recoveryKey);
    const primaryXpub = primaryKey.slice(primaryKey.indexOf(']') + 1).split('/')[0];
    const recoveryXpub = recoveryKey.slice(recoveryKey.indexOf(']') + 1).split('/')[0];
    const internalXpub = internal.slice(internal.indexOf(']') + 1).split('/')[0];
    expect(primaryXpub).toBe(recoveryXpub);
    expect(primaryXpub).not.toBe(internalXpub);
    const candidateBody = `tr(${internal},{pk(${primaryKey}),${recovery}})`;
    expect(candidateBody.replace(`{pk(${primaryKey}),`, '').replace('}', '')).toBe(sourceBody);
    expect(rustSignetInternalPrimaryLeafDuplicateOriginFixture.descriptor).toBe(descriptorWithBody(candidateBody));
    expect(() => parseLianaDescriptor(rustSignetInternalPrimaryLeafDuplicateOriginFixture.descriptor, 'signet')).toThrowError(
      expect.objectContaining({ code: 'INVALID_DESCRIPTOR', message: 'Liana primary path contains duplicate master-fingerprint origins' }),
    );
  });
  it('rejects Taproot recovery paths with a hashlock despite a valid older() condition', () => {
    expect(rustPolicyRejectionFixture.provenance).toMatchObject({ lianaCommit: '398e622596e7530a328de3027cb2c09905f708c6', miniscriptVersion: '11.2.0', rustc: '1.80.0 (051478957 2024-07-21)' });
    const item = rustPolicyRejectionFixture.cases.find((candidate) => candidate.id === 'taproot-recovery-hashlock');
    if (!item) throw new Error('expected a pinned Rust policy-rejection vector');
    expect(item.expected.accepted).toBe(false);
    expect(item.expected.error).toBe('Descriptor is not compatible with a Liana spending policy.');
    expect(() => parseLianaDescriptor(item.descriptor, 'mainnet')).toThrowError(expect.objectContaining({ code: 'INVALID_DESCRIPTOR' }));
  });
  it('rejects a Taproot primary leaf constrained by a hashlock', () => {
    const item = rustPolicyRejectionFixture.cases.find((candidate) => candidate.id === 'taproot-primary-hashlock');
    if (!item) throw new Error('expected a pinned Rust primary-policy rejection vector');
    expect(item.expected.accepted).toBe(false);
    expect(() => parseLianaDescriptor(item.descriptor, 'mainnet')).toThrowError(expect.objectContaining({ code: 'INVALID_DESCRIPTOR' }));
  });
  it('matches the pinned IncompatibleDesc rejection when the internal primary is flattened', () => {
    expect(rustSignetFlattenedInternalKeyFixture.id).toBe('liana-v9-rust-signet-flattened-internal-key-rejection');
    expect(rustSignetFlattenedInternalKeyFixture.provenance).toMatchObject({
      lianaCommit: '398e622596e7530a328de3027cb2c09905f708c6',
      miniscriptVersion: '11.2.0',
      rustc: '1.80.0 (051478957 2024-07-21)',
      network: 'signet',
      secretsOmitted: true,
    });
    expect(rustSignetFlattenedInternalKeyFixture.sourceFixture).toBe('liana-v9-rust-signet-single-primary-recovery-vectors');
    expect(rustSignetFlattenedInternalKeyFixture.expectedRejection).toBe('IncompatibleDesc');
    expect(rustSignetFlattenedInternalKeyFixture.transformation).toContain('only the spendable internal primary key branch');

    const sourceBody = rustSignetSinglePrimaryFixture.multipathDescriptorBody;
    const recoveryStart = sourceBody.indexOf('and_v(');
    const internalBranch = sourceBody.indexOf('/<0;1>/*');
    expect(recoveryStart).toBeGreaterThan(0);
    expect(internalBranch).toBeGreaterThanOrEqual(0);
    expect(internalBranch).toBeLessThan(recoveryStart);
    const candidateBody = `${sourceBody.slice(0, internalBranch)}/0/*${sourceBody.slice(internalBranch + '/<0;1>/*'.length)}`;
    expect(candidateBody.replace('/0/*', '/<0;1>/*')).toBe(sourceBody);
    const candidateRecoveryStart = candidateBody.indexOf('and_v(');
    expect(candidateBody.slice(candidateRecoveryStart)).toBe(sourceBody.slice(recoveryStart));
    expect(candidateBody.slice(0, candidateRecoveryStart)).toContain('/0/*');
    expect(candidateBody.slice(candidateRecoveryStart)).toContain('/<0;1>/*');
    expect(rustSignetFlattenedInternalKeyFixture.descriptor).toBe(descriptorWithBody(candidateBody));
    expect(() => parseLianaDescriptor(rustSignetFlattenedInternalKeyFixture.descriptor, 'signet')).toThrowError(
      expect.objectContaining({
        code: 'INVALID_DESCRIPTOR',
        message: 'A spendable Liana Taproot internal key must be an originated multipath xpub with two normal derivation choices and an unhardened wildcard',
      }),
    );
  });
  it('matches the pinned IncompatibleDesc rejection for a fixed-branch recovery signer', () => {
    expect(rustSignetFixedBranchRecoveryFixture.provenance).toMatchObject({
      sourceFixture: 'liana-v9-rust-signet-single-primary-recovery-vectors',
      lianaCommit: '398e622596e7530a328de3027cb2c09905f708c6',
      miniscriptVersion: '11.2.0',
      network: 'signet',
      rustc: '1.80.0 (051478957 2024-07-21)',
    });
    expect(rustSignetFixedBranchRecoveryFixture.expectedRejection).toBe('IncompatibleDesc');
    expect(rustSignetFixedBranchRecoveryFixture.transformation).toContain('internal primary remains /<0;1>/*');
    const body = splitDescriptorChecksum(rustSignetFixedBranchRecoveryFixture.descriptor).body;
    const sourceBody = rustSignetSinglePrimaryFixture.multipathDescriptorBody;
    const recoveryStart = sourceBody.indexOf('and_v(');
    const recoveryBranch = sourceBody.indexOf('/<0;1>/*', recoveryStart);
    expect(recoveryStart).toBeGreaterThan(0);
    expect(recoveryBranch).toBeGreaterThan(recoveryStart);
    const malformedBody = `${sourceBody.slice(0, recoveryBranch)}/0/*${sourceBody.slice(recoveryBranch + '/<0;1>/*'.length)}`;
    expect(body.slice(0, recoveryStart)).toBe(sourceBody.slice(0, recoveryStart));
    expect(body.slice(0, recoveryStart)).toContain('/<0;1>/*');
    expect(body.slice(recoveryStart)).toContain('/0/*');
    expect(body.slice(recoveryStart)).not.toContain('/<0;1>/*');
    expect(rustSignetFixedBranchRecoveryFixture.descriptor).toBe(descriptorWithBody(malformedBody));
    expect(() => parseLianaDescriptor(rustSignetFixedBranchRecoveryFixture.descriptor, 'signet')).toThrowError(expect.objectContaining({ code: 'INVALID_DESCRIPTOR' }));
  });
  it('matches the pinned DuplicateKey rejection when origin fingerprints differ', () => {
    expect(rustSignetDuplicateXpubFixture.provenance).toMatchObject({
      sourceFixture: 'liana-v9-rust-signet-single-primary-recovery-vectors',
      lianaCommit: '398e622596e7530a328de3027cb2c09905f708c6',
      miniscriptVersion: '11.2.0',
      network: 'signet',
      rustc: '1.80.0 (051478957 2024-07-21)',
    });
    expect(rustSignetDuplicateXpubFixture.expectedRejection).toBe('DuplicateKey');
    expect(rustSignetDuplicateXpubFixture.transformation).toContain('origin fingerprint differs');
    const body = splitDescriptorChecksum(rustSignetDuplicateXpubFixture.descriptor).body;
    const multipathSuffix = '/<0;1>/*';
    const internalStart = body.indexOf('[');
    const internalEnd = body.indexOf(multipathSuffix, internalStart) + multipathSuffix.length;
    const recoveryStart = body.indexOf('and_v(');
    const recoveryKeyStart = body.indexOf('[', recoveryStart);
    const recoveryKeyEnd = body.indexOf(multipathSuffix, recoveryKeyStart) + multipathSuffix.length;
    expect(internalEnd).toBeGreaterThan(internalStart);
    expect(recoveryKeyEnd).toBeGreaterThan(recoveryKeyStart);
    const internalKey = body.slice(internalStart, internalEnd);
    const duplicateRecoveryKey = internalKey.replace(/^\[([0-9a-fA-F]{8})/, '[deadbeef');
    const malformedBody = `${body.slice(0, recoveryKeyStart)}${duplicateRecoveryKey}${body.slice(recoveryKeyEnd)}`;
    expect(duplicateRecoveryKey).not.toBe(internalKey);
    expect(duplicateRecoveryKey.slice(9)).toBe(internalKey.slice(9));
    expect(rustSignetDuplicateXpubFixture.descriptor).toBe(descriptorWithBody(malformedBody));
    expect(() => parseLianaDescriptor(rustSignetDuplicateXpubFixture.descriptor, 'signet')).toThrowError(expect.objectContaining({ code: 'INVALID_DESCRIPTOR' }));
  });
  it('matches the pinned Liana Rust vector for a single-key multi_a recovery', () => {
    expect(rustSignetSingleKeyMultiAFixture.provenance).toMatchObject({
      lianaCommit: '398e622596e7530a328de3027cb2c09905f708c6',
      miniscriptVersion: '11.2.0',
      network: 'signet',
      rustc: '1.80.0 (051478957 2024-07-21)',
    });
    expect(rustSignetSingleKeyMultiAFixture.inferredPolicy).toEqual({
      primary: 'PathInfo::Single',
      recovery: { older: 36, path: 'PathInfo::Single' },
    });
    expect(rustSignetSingleKeyMultiAFixture.transformation).toContain('v:pk(key) -> v:multi_a(1,key)');
    const wallet = parseLianaDescriptor(rustSignetSingleKeyMultiAFixture.descriptor, 'signet');
    const body = splitDescriptorChecksum(rustSignetSingleKeyMultiAFixture.descriptor).body;
    expect(wallet.original).toBe(rustSignetSingleKeyMultiAFixture.descriptor);
    expect(wallet.ast.source).toBe(body);
    expect(body).toContain('v:multi_a(1,');
    let checked = 0;
    for (const branch of ['receive', 'change'] as const) {
      for (let index = 0; index < 10; index++) {
        const actual = deriveWalletAddress(wallet, branch, index);
        const expected = rustSignetSingleKeyMultiAFixture.expected[branch][String(index)]!;
        expect(actual.address, `${branch}/${index} address`).toBe(expected.address);
        expect(Buffer.from(actual.scriptPubKey).toString('hex'), `${branch}/${index} scriptPubKey`).toBe(expected.scriptPubKey);
        checked++;
      }
    }
    expect(checked).toBe(20);
  });
  it('continues to import the fixed-branch community receive/change descriptors', () => {
    expect(parseLianaDescriptor(fixture.receive.descriptor, 'signet').network).toBe('signet');
    expect(parseLianaDescriptor(fixture.change.descriptor, 'signet').network).toBe('signet');
  });
  it('retains a multi_a Taproot recovery leaf beside multiple timelocked recovery branches', () => {
    const item = rustMultisigFixture.cases.find((candidate) => candidate.id === 'taproot-multi-a-multiple-recovery');
    if (!item) throw new Error('expected pinned multi_a recovery fixture');
    const body = splitDescriptorChecksum(item.descriptor).body;
    const wallet = parseLianaDescriptor(item.descriptor, 'mainnet');
    expect(wallet.ast.source).toBe(body);
    assertAstSourceRanges(wallet.ast.root, body);
    expect([...body.matchAll(/and_v\(v:multi_a\([^)]*\),older\((\d+)\)\)/g)].map((match) => Number(match[1]))).toEqual([1678, 42, 43]);
    expect([...body.matchAll(/multi_a\(/g)]).toHaveLength(4);
  });
  it('retains an ordered lossless syntax tree tied to the original Taproot source', () => {
    const item = rustMultisigFixture.cases.find((candidate) => candidate.id === 'multisig-multiple-recovery')!;
    const wallet = parseLianaDescriptor(item.descriptor, 'mainnet');
    const body = splitDescriptorChecksum(item.descriptor).body;
    expect(wallet.original).toBe(item.descriptor);
    expect(wallet.ast.source).toBe(body);
    expect(wallet.ast.root.raw).toBe(body);
    assertAstSourceRanges(wallet.ast.root, body);
    expect(wallet.ast.root.kind).toBe('call');
    if (wallet.ast.root.kind !== 'call') throw new Error('expected tr() root');
    expect(wallet.ast.root.name).toBe('tr');
    expect(wallet.ast.root.arguments).toHaveLength(2);
    const tree = wallet.ast.root.arguments[1]!;
    expect(tree.kind).toBe('tree');
    if (tree.kind !== 'tree') throw new Error('expected Taproot binary tree');
    expect(tree.left.kind).toBe('tree');
    if (tree.left.kind !== 'tree') throw new Error('expected recovery subtree');
    expect(tree.left.left.raw).toContain('older(1678)');
    expect(tree.left.left.kind).toBe('call');
    if (tree.left.left.kind !== 'call') throw new Error('expected timelocked recovery expression');
    expect(tree.left.left.name).toBe('and_v');
    expect(tree.left.left.arguments[0]!.kind).toBe('prefix');
    if (tree.left.left.arguments[0]!.kind !== 'prefix') throw new Error('expected Miniscript prefix node');
    expect(tree.left.left.arguments[0]!.operator).toBe('v');
    expect(wallet.ast.source.slice(tree.left.left.arguments[0]!.start, tree.left.left.arguments[0]!.end)).toBe(tree.left.left.arguments[0]!.raw);
    expect(tree.left.right.kind).toBe('tree');
    if (tree.left.right.kind !== 'tree') throw new Error('expected nested recovery subtree');
    expect(tree.left.right.left.raw).toContain('older(42)');
    expect(tree.left.right.right.raw).toContain('older(43)');
    expect(tree.right.raw).toContain('/0/<0;1>/*');
    expect(tree.right.kind).toBe('call');
    if (tree.right.kind !== 'call') throw new Error('expected ordered primary multisig expression');
    expect(tree.right.name).toBe('multi_a');
    expect(tree.right.arguments).toHaveLength(4);
    expect(tree.right.arguments.slice(1).map((argument) => /^\[([0-9a-f]{8})\]/.exec(argument.raw)?.[1])).toEqual(['4ba43603', '8dfc9b34', '56c4fac3']);
    expect(tree.raw).toBe(body.slice(body.indexOf('{'), -1));
  });
  it('retains nested P2WSH multi-recovery syntax in source order', () => {
    const body = splitDescriptorChecksum(legacyWshMultipleRecoveryFixture.descriptor).body;
    const wallet = parseLianaDescriptor(legacyWshMultipleRecoveryFixture.descriptor, 'mainnet');
    expect(wallet.ast.source).toBe(body);
    expect(wallet.ast.root.raw).toBe(body);
    assertAstSourceRanges(wallet.ast.root, body);
    expect(wallet.ast.root.kind).toBe('call');
    if (wallet.ast.root.kind !== 'call') throw new Error('expected wsh() root');
    expect(wallet.ast.root.name).toBe('wsh');
    const recoveryTree = wallet.ast.root.arguments[0]!;
    expect(recoveryTree.kind).toBe('call');
    if (recoveryTree.kind !== 'call') throw new Error('expected nested multi-recovery OR');
    expect(recoveryTree.name).toBe('or_i');
    expect(recoveryTree.arguments[0]!.raw).toContain('older(1678)');
    expect(recoveryTree.arguments[1]!.raw).toContain('older(43)');
  });
  it('retains the Liana v2 threshold-recovery policy source exactly', () => {
    const body = splitDescriptorChecksum(legacyWshV2ThresholdsFixture.descriptor).body;
    const wallet = parseLianaDescriptor(legacyWshV2ThresholdsFixture.descriptor, 'mainnet');
    expect(wallet.ast.source).toBe(body);
    assertAstSourceRanges(wallet.ast.root, body);
    expect(wallet.ast.root.kind).toBe('call');
    if (wallet.ast.root.kind !== 'call') throw new Error('expected wsh() root');
    expect(wallet.ast.root.arguments[0]!.raw).toContain('or_i(and_v(v:thresh(3,pkh(');
    expect(wallet.ast.root.arguments[0]!.raw).toContain('or_d(multi(3,');
    expect(wallet.ast.root.arguments[0]!.raw).toContain('and_v(v:thresh(2,pkh(');
    expect(wallet.ast.root.arguments[0]!.raw).toContain('/<4;5>/*');
    expect(wallet.ast.root.arguments[0]!.raw).toContain('/<2;3>/*');
  });
  it('retains the pinned Liana v2 Signet descriptor verbatim', () => {
    const source = readFileSync(resolve('tests/oracle/liana-v2-signet-descriptor.txt'), 'utf8').trim();
    expect(signetV2Bip32Fixture.descriptor).toBe(source);
    expect(Object.keys(signetV2Bip32Fixture.expected.receive)).toEqual(['0', '1']);
    expect(Object.keys(signetV2Bip32Fixture.expected.change)).toEqual(['0', '1']);
    for (const branch of ['receive', 'change'] as const) {
      for (const vector of Object.values(signetV2Bip32Fixture.expected[branch])) {
        expect(vector.address).toMatch(/^tb1q/);
        expect(vector.scriptPubKey).toMatch(/^0020/);
      }
    }
    const wallet = parseLianaDescriptor(source, 'signet');
    expect(wallet.original).toBe(source);
    expect(wallet.signers).toHaveLength(9);
    expect(wallet.ast.source).toBe(splitDescriptorChecksum(source).body);
    assertAstSourceRanges(wallet.ast.root, wallet.ast.source);
  });
  it('preserves P2WSH or_d ordering and rejects reversed multi-recovery or_i branches', () => {
    const single = parseLianaDescriptor(legacyWshFixture.descriptor, 'mainnet');
    expect(single.ast.root.kind).toBe('call');
    if (single.ast.root.kind !== 'call') throw new Error('expected wsh() root');
    const singlePolicy = single.ast.root.arguments[0]!;
    expect(singlePolicy.kind).toBe('call');
    if (singlePolicy.kind !== 'call') throw new Error('expected or_d policy');
    expect(singlePolicy.name).toBe('or_d');
    expect(singlePolicy.arguments[0]!.raw).not.toContain('older(');
    expect(singlePolicy.arguments[1]!.raw).toContain('older(');

    const andor = parseLianaDescriptor(legacyWshAndorFixture.descriptor, 'mainnet');
    if (andor.ast.root.kind !== 'call') throw new Error('expected wsh() root');
    const andorPolicy = andor.ast.root.arguments[0]!;
    if (andorPolicy.kind !== 'call' || andorPolicy.name !== 'andor') throw new Error('expected Liana andor policy');
    expect(andorPolicy.arguments).toHaveLength(3);
    expect(andorPolicy.arguments[0]!.raw).toContain('[4ba43603]');
    expect(andorPolicy.arguments[0]!.raw).not.toContain('older(');
    expect(andorPolicy.arguments[1]!.raw).toBe('older(42)');
    expect(andorPolicy.arguments[2]!.raw).toContain('[8dfc9b34]');
    expect(andorPolicy.arguments[2]!.raw).not.toContain('older(');

    const multi = parseLianaDescriptor(legacyWshMultipleRecoveryFixture.descriptor, 'mainnet');
    if (multi.ast.root.kind !== 'call') throw new Error('expected wsh() root');
    const policy = multi.ast.root.arguments[0]!;
    if (policy.kind !== 'call' || policy.name !== 'or_i') throw new Error('expected Liana or_i policy');
    const reversed = descriptorWithBody(`wsh(or_i(${policy.arguments[1]!.raw},${policy.arguments[0]!.raw}))`);
    expect(() => parseLianaDescriptor(reversed, 'mainnet')).toThrowError(expect.objectContaining({ code: 'INVALID_DESCRIPTOR' }));
  });
  it('imports Liana P2WSH policies and matches pinned Rust outputs', () => {
    let checked = 0;
    for (const item of [legacyWshFixture, legacyWshMultisigFixture, legacyWshMultipleRecoveryFixture, legacyWshAndorFixture, legacyWshV2ThresholdsFixture, signetV2Bip32Fixture]) {
      expect(item.provenance).toMatchObject({ lianaCommit: '398e622596e7530a328de3027cb2c09905f708c6', miniscriptVersion: '11.2.0' });
      expect(['mainnet', 'signet']).toContain(item.provenance.network);
      const network = item.provenance.network === 'signet' ? 'signet' : 'mainnet';
      const wallet = parseLianaDescriptor(item.descriptor, network);
      const body = splitDescriptorChecksum(item.descriptor).body;
      expect(wallet.original).toBe(item.descriptor);
      expect(wallet.ast.source).toBe(body);
      assertAstSourceRanges(wallet.ast.root, body);
      for (const branch of ['receive', 'change'] as const) {
        for (const index of [0, 1]) {
          const actual = deriveWalletAddress(wallet, branch, index);
          const expected = item.expected[branch][String(index)]!;
          expect(actual.address, `${branch} ${index} P2WSH address`).toBe(expected.address);
          expect(Buffer.from(actual.scriptPubKey).toString('hex'), `${branch} ${index} P2WSH scriptPubKey`).toBe(expected.scriptPubKey);
          checked++;
        }
      }
    }
    expect(checked).toBe(24);
  });
  it('rejects P2WSH descriptors without recovery and duplicate recovery timelocks', () => {
    const source = splitDescriptorChecksum(legacyWshFixture.descriptor).body;
    const policy = source.slice('wsh('.length, -1);
    const recoveryAt = policy.indexOf(',and_v(');
    const primary = policy.slice('or_d('.length, recoveryAt);
    const recovery = policy.slice(recoveryAt + 1, -1);
    const withoutRecovery = descriptorWithBody(`wsh(${primary})`);
    const duplicateTimelock = descriptorWithBody(`wsh(or_d(or_d(${primary},${recovery}),${recovery}))`);
    const emptyArgument = descriptorWithBody(source.replace('or_d(', 'or_d(,'));
    const andorBody = splitDescriptorChecksum(legacyWshAndorFixture.descriptor).body;
    const malformedAndor = descriptorWithBody(andorBody.replace(',older(42),', ','));
    const zeroAndorTimelock = descriptorWithBody(andorBody.replace('older(42)', 'older(0)'));
    const oversizedAndorTimelock = descriptorWithBody(andorBody.replace('older(42)', 'older(65536)'));
    const malformedAndorTimelock = descriptorWithBody(andorBody.replace('older(42)', 'older(0x2a)'));
    const andorKeys = andorBody.match(/\[[0-9a-fA-F]{8}\](?:xpub|tpub)[1-9A-HJ-NP-Za-km-z]+/g)!;
    const duplicateAndorRecoveryOrigin = descriptorWithBody(`wsh(andor(multi(1,${andorKeys[0]!}/0/<0;1>/*,${andorKeys[0]!}/2/<0;1>/*),older(42),pk(${andorKeys[1]!}/1/<0;1>/*)))`);
    expect(() => parseLianaDescriptor(withoutRecovery, 'mainnet')).toThrowError(expect.objectContaining({ code: 'INVALID_DESCRIPTOR' }));
    expect(() => parseLianaDescriptor(duplicateTimelock, 'mainnet')).toThrowError(expect.objectContaining({ code: 'INVALID_DESCRIPTOR' }));
    expect(() => parseLianaDescriptor(emptyArgument, 'mainnet')).toThrowError(expect.objectContaining({ code: 'INVALID_DESCRIPTOR' }));
    expect(() => parseLianaDescriptor(malformedAndor, 'mainnet')).toThrowError(expect.objectContaining({ code: 'INVALID_DESCRIPTOR' }));
    expect(() => parseLianaDescriptor(zeroAndorTimelock, 'mainnet')).toThrowError(expect.objectContaining({ code: 'INVALID_DESCRIPTOR' }));
    expect(() => parseLianaDescriptor(oversizedAndorTimelock, 'mainnet')).toThrowError(expect.objectContaining({ code: 'INVALID_DESCRIPTOR' }));
    expect(() => parseLianaDescriptor(malformedAndorTimelock, 'mainnet')).toThrowError(expect.objectContaining({ code: 'INVALID_DESCRIPTOR' }));
    expect(() => parseLianaDescriptor(duplicateAndorRecoveryOrigin, 'mainnet')).toThrowError(expect.objectContaining({ code: 'INVALID_DESCRIPTOR' }));
    const nonKeyPrimary = descriptorWithBody(`wsh(or_d(and_v(v:${primary},sha256(${'00'.repeat(32)})),${recovery}))`);
    expect(() => parseLianaDescriptor(nonKeyPrimary, 'mainnet')).toThrowError(expect.objectContaining({ code: 'INVALID_DESCRIPTOR' }));
    const malformedTimelock = descriptorWithBody(source.replace('older(36)', 'older(0x10)'));
    expect(() => parseLianaDescriptor(malformedTimelock, 'mainnet')).toThrowError(expect.objectContaining({ code: 'INVALID_DESCRIPTOR' }));
    const keyPrefixes = source.match(/\[[0-9a-fA-F]{8}\](?:xpub|tpub)[1-9A-HJ-NP-Za-km-z]+/g)!;
    const reusedKey = descriptorWithBody(source.replace(`${keyPrefixes[1]!}/1/<0;1>/*`, `${keyPrefixes[0]!}/0/<0;1>/*`));
    expect(() => parseLianaDescriptor(reusedKey, 'mainnet')).toThrowError(expect.objectContaining({ code: 'INVALID_DESCRIPTOR' }));
    const multisigBody = splitDescriptorChecksum(legacyWshMultisigFixture.descriptor).body;
    const multisigKeys = multisigBody.match(/\[[0-9a-fA-F]{8}\](?:xpub|tpub)[1-9A-HJ-NP-Za-km-z]+/g)!.slice(0, 3).map((key) => `${key}/0/<0;1>/*`);
    const nestedPrimary = `thresh(1,thresh(1,pkh(${multisigKeys[0]}),pkh(${multisigKeys[1]})),pkh(${multisigKeys[2]}))`;
    const nestedThreshold = descriptorWithBody(`wsh(or_d(${nestedPrimary},${recovery}))`);
    expect(() => parseLianaDescriptor(nestedThreshold, 'mainnet')).toThrowError(expect.objectContaining({ code: 'INVALID_DESCRIPTOR' }));
  });
  it('rejects hardened derivation steps below public extended keys', () => {
    const body = splitDescriptorChecksum(legacyWshFixture.descriptor).body.replaceAll('/<0;1>/*', "/0'/*");
    expect(() => parseLianaDescriptor(descriptorWithBody(body), 'mainnet')).toThrowError(expect.objectContaining({ code: 'INVALID_PATH' }));
  });
  it('requires originated WSH keys with one two-choice normal multipath and an unhardened wildcard', () => {
    const source = splitDescriptorChecksum(legacyWshFixture.descriptor).body;
    const invalidBodies = [
      source.replaceAll('/<0;1>/*', '/*'),
      source.replaceAll('<0;1>', '<0;1;2>'),
      source.replaceAll('/<0;1>/*', '/<0;1>/<2;3>/*'),
      source.replace('/0/<0;1>/*', '/2147483648/<0;1>/*'),
    ];
    for (const body of invalidBodies) {
      expect(() => parseLianaDescriptor(descriptorWithBody(body), 'mainnet')).toThrowError(expect.objectContaining({ code: 'INVALID_DESCRIPTOR' }));
    }
  });
  it('reports every selected multipath child index in descriptor order', () => {
    const item = rustMultisigFixture.cases.find((entry) => entry.id === 'multisig-distinct-branch-values')!;
    const wallet = parseLianaDescriptor(item.descriptor, 'mainnet');
    const receive = deriveWalletAddress(wallet, 'receive', 0);
    const change = deriveWalletAddress(wallet, 'change', 0);
    expect(receive.branchIndexes).toEqual([0, 2, 2, 2, 0, 0, 0]);
    expect(change.branchIndexes).toEqual([1, 3, 3, 3, 1, 1, 1]);
  });
  it('builds a NUMS internal xpub from ordered input extended public keys', () => {
    const wallet = parseLianaDescriptor(fixture.receive.descriptor, 'signet');
    const result = constructUnspendableInternalXpub(wallet.signers.map((signer) => signer.xpub), 'signet');
    expect(Buffer.from(result.publicKey).toString('hex')).toBe('0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0');
    expect(Buffer.from(result.chainCode).toString('hex')).toBe('cbbedbf9f2a95f56939a8607ea0242b3ca29370ac03b8831b4c976a4d812ca54');
    expect(result.xpub).toBe('tpubD6NzVbkrYhZ4YNGrVH69p4DDGAAdXQZzQ4oYnZH64K1ct62aX21QWWEvLE566i3VXFtURY8cdVFU1rypo4KDjVfmoEiUqDkSrPaxVab1UA2');
    expect(result.descriptorKey).toBe(`${result.xpub}/<0;1>/*`);
  });
  it('includes repeated public keys in the NUMS chain-code hash', () => {
    const wallet = parseLianaDescriptor(fixture.receive.descriptor, 'signet');
    const pub = Buffer.from('03f8178a5ccdfb39ed0c3d8088970b0d7e1f0c27a24dad0e2d2865c43dae2b9a09', 'hex');
    const expected = createHash('sha256').update(Buffer.concat([pub, pub])).digest('hex');
    const result = constructUnspendableInternalXpub([wallet.signers[0]!.xpub, wallet.signers[0]!.xpub], 'signet');
    expect(Buffer.from(result.chainCode).toString('hex')).toBe(expected);
  });
  it('imports and derives a synthetic multisig descriptor using the NUMS internal key', () => {
    const template = parseLianaDescriptor(rustMultisigFixture.cases[1]!.descriptor, 'mainnet');
    const uniqueSigners = [...new Map(template.signers.map((signer) => [signer.masterFingerprint, signer])).values()];
    const [primary, second, recovery] = uniqueSigners;
    const key = (signer: typeof primary, purpose: number) => {
      const origin = signer!.originPath === 'm' ? signer!.masterFingerprint : `${signer!.masterFingerprint}/${signer!.originPath.slice(2)}`;
      return `[${origin}]${signer!.xpub}/${purpose}/<0;1>/*`;
    };
    const ordered = [primary!, second!, recovery!];
    const tree = `{multi_a(2,${key(ordered[0]!, 0)},${key(ordered[1]!, 0)}),and_v(v:pk(${key(ordered[2]!, 1)}),older(36))}`;
    const nums = constructUnspendableInternalXpub(ordered.map((signer) => signer.xpub), 'mainnet');
    const body = `tr(${nums.descriptorKey},${tree})`;
    const descriptor = `${body}#${descriptorChecksum(body)}`;
    const wallet = parseLianaDescriptor(descriptor, 'mainnet');
    const derived = deriveWalletAddress(wallet, 'receive', 0);
    expect(derived.address.startsWith('bc1p')).toBe(true);
    expect(derived.scriptPubKey).toHaveLength(34);
  });
  it('rejects a Taproot recovery tree with no always-available primary path', () => {
    const wallet = parseLianaDescriptor(rustMultisigFixture.cases[0]!.descriptor, 'mainnet');
    const recovery = wallet.signers[1]!;
    const origin = recovery.originPath === 'm' ? recovery.masterFingerprint : `${recovery.masterFingerprint}/${recovery.originPath.slice(2)}`;
    const key = `[${origin}]${recovery.xpub}/1/<0;1>/*`;
    const internal = constructUnspendableInternalXpub([recovery.xpub], 'mainnet');
    const body = `tr(${internal.descriptorKey},and_v(v:pk(${key}),older(36)))`;
    const descriptor = `${body}#${descriptorChecksum(body)}`;
    try { parseLianaDescriptor(descriptor, 'mainnet'); throw new Error('expected invalid Liana policy error'); }
    catch (error) {
      expect(error).toBeInstanceOf(WalletDerivationError);
      expect((error as WalletDerivationError).code).toBe('INVALID_DESCRIPTOR');
    }
  });
  it('rejects duplicate signer origins within one primary spending path', () => {
    const template = parseLianaDescriptor(fixture.receive.descriptor, 'signet');
    const [primary, recovery] = template.signers;
    const key = (signer: typeof primary, branch: number) => `[${signer!.masterFingerprint}/${signer!.originPath.slice(2)}]${signer!.xpub}/${branch}/<0;1>/*`;
    const recoveryKey = key(recovery, 1);
    const primaryKey = key(primary, 0);
    const tree = `{and_v(v:pk(${recoveryKey}),older(36)),multi_a(2,${primaryKey},${primaryKey})}`;
    const internal = constructUnspendableInternalXpub([recovery!.xpub, primary!.xpub, primary!.xpub], 'signet');
    const body = `tr(${internal.descriptorKey},${tree})`;
    const descriptor = `${body}#${descriptorChecksum(body)}`;
    expect(() => parseLianaDescriptor(descriptor, 'signet')).toThrowError(expect.objectContaining({ code: 'INVALID_DESCRIPTOR' }));
  });
  it('rejects distinct recovery leaves with the same relative timelock', () => {
    const template = parseLianaDescriptor(fixture.receive.descriptor, 'signet');
    const [primary, recovery] = template.signers;
    const key = (signer: typeof primary, branch: number) => `[${signer!.masterFingerprint}/${signer!.originPath.slice(2)}]${signer!.xpub}/${branch}/<0;1>/*`;
    const recoveryA = key(primary, 1);
    const recoveryB = key(recovery, 1);
    const primaryA = key(primary, 0);
    const primaryB = key(recovery, 0);
    const tree = `{and_v(v:pk(${recoveryA}),older(36)),{and_v(v:pk(${recoveryB}),older(36)),multi_a(2,${primaryA},${primaryB})}}`;
    const internal = constructUnspendableInternalXpub([primary!.xpub, recovery!.xpub, primary!.xpub, recovery!.xpub], 'signet');
    const body = `tr(${internal.descriptorKey},${tree})`;
    const descriptor = `${body}#${descriptorChecksum(body)}`;
    expect(() => parseLianaDescriptor(descriptor, 'signet')).toThrowError(expect.objectContaining({ code: 'INVALID_DESCRIPTOR' }));
  });
  it('rejects a Taproot key-only descriptor with no Liana recovery path', () => {
    const signer = parseLianaDescriptor(fixture.receive.descriptor, 'signet').signers[0]!;
    const key = `[${signer.masterFingerprint}/${signer.originPath.slice(2)}]${signer.xpub}/<0;1>/*`;
    const body = `tr(${key})`;
    const descriptor = `${body}#${descriptorChecksum(body)}`;
    try { parseLianaDescriptor(descriptor, 'signet'); throw new Error('expected error'); }
    catch (error) {
      expect(error).toBeInstanceOf(WalletDerivationError);
      expect((error as WalletDerivationError).code).toBe('INVALID_DESCRIPTOR');
    }
  });
  it('rejects a NUMS internal xpub inconsistent with ordered TapTree keys', () => {
    const wallet = parseLianaDescriptor(fixture.receive.descriptor, 'signet');
    const [primary, recovery] = wallet.signers;
    const key = (signer: typeof primary) => `[${signer.masterFingerprint}/${signer.originPath.slice(2)}]${signer.xpub}/<0;1>/*`;
    const treeKeys = [primary!, recovery!, primary!];
    const tree = `{multi_a(2,${key(treeKeys[0]!)},${key(treeKeys[1]!)}),and_v(v:pk(${key(treeKeys[2]!)}),older(36))}`;
    const correct = constructUnspendableInternalXpub(treeKeys.map((signer) => signer!.xpub), 'signet');
    const wrong = constructUnspendableInternalXpub([recovery!.xpub, primary!.xpub, primary!.xpub], 'signet');
    const body = `tr(${wrong.descriptorKey},${tree})`;
    const descriptor = `${body}#${descriptorChecksum(body)}`;
    try { parseLianaDescriptor(descriptor, 'signet'); throw new Error('expected error'); }
    catch (error) {
      expect(error).toBeInstanceOf(WalletDerivationError);
      expect((error as WalletDerivationError).code).toBe('INVALID_INTERNAL_KEY');
    }
    expect(correct.xpub).not.toBe(wrong.xpub);
  });
  it('reports a typed missing-checksum error', () => {
    const body = fixture.receive.descriptor.slice(0, fixture.receive.descriptor.lastIndexOf('#'));
    try { parseLianaDescriptor(body, 'signet'); throw new Error('expected error'); }
    catch (error) {
      expect(error).toBeInstanceOf(WalletDerivationError);
      expect((error as WalletDerivationError).code).toBe('CHECKSUM_REQUIRED');
    }
  });
  it('reports an invalid address index as a typed error', () => {
    try { deriveDescriptorAddress(fixture.receive.descriptor, 0x80000000, 'signet'); throw new Error('expected error'); }
    catch (error) {
      expect(error).toBeInstanceOf(WalletDerivationError);
      expect((error as WalletDerivationError).code).toBe('INVALID_INDEX');
    }
  });
  it('imports a descriptor without rewriting it and extracts signer origins', () => {
    const wallet = parseLianaDescriptor(fixture.receive.descriptor, 'signet');
    expect(wallet.original).toBe(fixture.receive.descriptor);
    expect(wallet.checksum).toBe('22y0dhdd');
    expect(wallet.network).toBe('signet');
    expect(wallet.signers).toHaveLength(2);
    expect(wallet.signers[0]).toMatchObject({ masterFingerprint: '07fd816d', originPath: "m/48'/1'/0'/2'", network: 'signet' });
  });
  it('rejects a Liana signer key missing its master-fingerprint origin', () => {
    const { body } = splitDescriptorChecksum(rustMultisigFixture.cases[0]!.descriptor);
    const originStart = body.indexOf('[');
    const originEnd = body.indexOf(']', originStart);
    const missingOrigin = `${body.slice(0, originStart)}${body.slice(originEnd + 1)}`;
    expect(originEnd).toBeGreaterThan(originStart);
    const descriptor = `${missingOrigin}#${descriptorChecksum(missingOrigin)}`;
    try { parseLianaDescriptor(descriptor, 'mainnet'); throw new Error('expected missing-origin error'); }
    catch (error) {
      expect(error).toBeInstanceOf(WalletDerivationError);
      expect((error as WalletDerivationError).code).toBe('INVALID_ORIGIN');
    }
  });
  it('rejects private-key material in watch-only descriptors before parsing output scripts', () => {
    const { body } = splitDescriptorChecksum(fixture.receive.descriptor);
    const fakeWif = `K${'1'.repeat(51)}`;
    const bodyWithPrivateKey = body.replace(/tpub[1-9A-HJ-NP-Za-km-z]+/, fakeWif);
    const descriptor = `${bodyWithPrivateKey}#${descriptorChecksum(bodyWithPrivateKey)}`;
    expect(() => parseLianaDescriptor(descriptor, 'signet')).toThrowError(expect.objectContaining({ code: 'INVALID_EXTENDED_KEY' }));
  });
  it('rejects a Signet descriptor when the caller selects mainnet', () => {
    expect(() => parseLianaDescriptor(fixture.receive.descriptor, 'mainnet')).toThrowError(expect.objectContaining({ code: 'NETWORK_MISMATCH' }));
  });
  it('rejects a descriptor with a modified checksum as a typed checksum error', () => {
    expect(() => parseLianaDescriptor(fixture.receive.descriptor.replace('#22y0dhdd', '#00000000'), 'signet')).toThrowError(expect.objectContaining({ code: 'INVALID_CHECKSUM' }));
  });
  it('splits a descriptor and verifies its checksum without changing its body', () => {
    expect(splitDescriptorChecksum('raw(deadbeef)#89f8spxm')).toEqual({ body: 'raw(deadbeef)', checksum: '89f8spxm' });
    expect(() => splitDescriptorChecksum('raw(deadbeef)#00000000')).toThrow(/checksum/i);
  });
  it('preserves the ordered two multipath choices', () => {
    expect(parseMultipath('[deadbeef/48h/1h]xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/<7;3>/*')).toMatchObject({ fingerprint: 'deadbeef', originPath: '48h/1h', branches: [7, 3], wildcard: true });
  });
});
