import { describe, expect, it } from 'vitest';
import { descriptorChecksum, splitDescriptorChecksum, parseMultipath, deriveDescriptorAddress, parseLianaDescriptor, deriveWalletAddress, WalletDerivationError, constructUnspendableInternalXpub } from '../src/index.js';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
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

function descriptorWithBody(body: string): string {
  return `${body}#${descriptorChecksum(body)}`;
}

describe('descriptor primitives', () => {
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
    expect(rustMultisigFixture.cases.map((item) => item.id)).toEqual(['single-primary-recovery', 'multisig-one-recovery', 'multisig-distinct-branch-values', 'multisig-multiple-recovery']);
    let checked = 0;
    for (const item of rustMultisigFixture.cases) {
      const wallet = parseLianaDescriptor(item.descriptor, 'mainnet');
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
    expect(checked).toBe(16);
  });
  it('imports Liana P2WSH policies and matches pinned Rust outputs', () => {
    let checked = 0;
    for (const item of [legacyWshFixture, legacyWshMultisigFixture]) {
      expect(item.provenance).toMatchObject({ lianaCommit: '398e622596e7530a328de3027cb2c09905f708c6', miniscriptVersion: '11.2.0', network: 'mainnet' });
      const wallet = parseLianaDescriptor(item.descriptor, 'mainnet');
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
    expect(checked).toBe(8);
  });
  it('rejects P2WSH descriptors without recovery and duplicate recovery timelocks', () => {
    const source = splitDescriptorChecksum(legacyWshFixture.descriptor).body;
    const policy = source.slice('wsh('.length, -1);
    const recoveryAt = policy.indexOf(',and_v(');
    const primary = policy.slice('or_d('.length, recoveryAt);
    const recovery = policy.slice(recoveryAt + 1, -1);
    const withoutRecovery = descriptorWithBody(`wsh(${primary})`);
    const duplicateTimelock = descriptorWithBody(`wsh(or_d(or_d(${primary},${recovery}),${recovery}))`);
    expect(() => parseLianaDescriptor(withoutRecovery, 'mainnet')).toThrowError(expect.objectContaining({ code: 'INVALID_DESCRIPTOR' }));
    expect(() => parseLianaDescriptor(duplicateTimelock, 'mainnet')).toThrowError(expect.objectContaining({ code: 'INVALID_DESCRIPTOR' }));
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
  it('rejects a descriptor with a modified checksum', () => {
    expect(() => parseLianaDescriptor(fixture.receive.descriptor.replace('#22y0dhdd', '#00000000'), 'signet')).toThrow(/checksum/i);
  });
  it('splits a descriptor and verifies its checksum without changing its body', () => {
    expect(splitDescriptorChecksum('raw(deadbeef)#89f8spxm')).toEqual({ body: 'raw(deadbeef)', checksum: '89f8spxm' });
    expect(() => splitDescriptorChecksum('raw(deadbeef)#00000000')).toThrow(/checksum/i);
  });
  it('preserves the ordered two multipath choices', () => {
    expect(parseMultipath('[deadbeef/48h/1h]xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/<7;3>/*')).toMatchObject({ fingerprint: 'deadbeef', originPath: '48h/1h', branches: [7, 3], wildcard: true });
  });
});
