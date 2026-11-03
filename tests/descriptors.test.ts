import { describe, expect, it } from 'vitest';
import { descriptorChecksum, splitDescriptorChecksum, parseMultipath, deriveDescriptorAddress, parseLianaDescriptor, deriveWalletAddress, WalletDerivationError, constructUnspendableInternalXpub } from '../src/index.js';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';

const fixture = JSON.parse(readFileSync(resolve('tests/fixtures/liana-v9-signet-single-primary-recovery.json'), 'utf8')) as {
  receive: { descriptor: string; addressIndex0: string; scriptPubKeyIndex0: string; addresses0to9: string[] };
  change: { descriptor: string; addressIndex0: string; addresses0to9: string[] };
};

describe('descriptor primitives', () => {
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
    const template = parseLianaDescriptor(fixture.receive.descriptor, 'signet');
    const [primary, recovery] = template.signers;
    const key = (signer: typeof primary) => `[${signer.masterFingerprint}/${signer.originPath.slice(2)}]${signer.xpub}/<0;1>/*`;
    const ordered = [primary!, recovery!, primary!];
    const tree = `{multi_a(2,${key(ordered[0]! )},${key(ordered[1]! )}),and_v(v:pk(${key(ordered[2]!)}),older(36))}`;
    const nums = constructUnspendableInternalXpub(ordered.map((signer) => signer.xpub), 'signet');
    const body = `tr(${nums.descriptorKey},${tree})`;
    const descriptor = `${body}#${descriptorChecksum(body)}`;
    const wallet = parseLianaDescriptor(descriptor, 'signet');
    const derived = deriveWalletAddress(wallet, 'receive', 0);
    expect(derived.address.startsWith('tb1p')).toBe(true);
    expect(derived.scriptPubKey).toHaveLength(34);
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
