import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { descriptorChecksum, deriveWalletAddress, parseLianaDescriptor } from '../src/index.js';

const fixture = JSON.parse(readFileSync(resolve('tests/fixtures/liana-v9-rust-signet-single-primary-recovery.json'), 'utf8')) as {
  provenance: { lianaCommit: string; miniscriptVersion: string; network: string };
  multipathDescriptorBody: string;
  expected: Record<'receive' | 'change', Record<string, { address: string; scriptPubKey: string }>>;
};

const nonstandardMultipathFixture = JSON.parse(readFileSync(resolve('tests/fixtures/liana-v9-rust-signet-nonstandard-multipath.json'), 'utf8')) as {
  id: string;
  provenance: { lianaCommit: string; miniscriptVersion: string; network: string; multipathChoices: [number, number] };
  multipathDescriptorBody: string;
  expected: Record<'receive' | 'change', Record<string, { address: string; scriptPubKey: string }>>;
};

describe('pinned Liana Rust Signet single-primary vectors', () => {
  it('matches address and scriptPubKey for receive/change indices 0 through 9', () => {
    expect(fixture.provenance).toMatchObject({
      lianaCommit: '398e622596e7530a328de3027cb2c09905f708c6',
      miniscriptVersion: '11.2.0',
      network: 'signet',
    });
    const descriptor = `${fixture.multipathDescriptorBody}#${descriptorChecksum(fixture.multipathDescriptorBody)}`;
    const wallet = parseLianaDescriptor(descriptor, 'signet');
    let compared = 0;
    for (const branch of ['receive', 'change'] as const) {
      expect(Object.keys(fixture.expected[branch]).map(Number)).toEqual(Array.from({ length: 10 }, (_, index) => index));
      for (let index = 0; index < 10; index++) {
        const derived = deriveWalletAddress(wallet, branch, index);
        expect({
          address: derived.address,
          scriptPubKey: Buffer.from(derived.scriptPubKey).toString('hex'),
        }, `${branch}/${index}`).toEqual(fixture.expected[branch][String(index)]);
        compared++;
      }
    }
    expect(compared).toBe(20);
  });

  it('maps receive/change to nonstandard multipath indexes exactly as pinned Rust does', () => {
    expect(nonstandardMultipathFixture.provenance).toMatchObject({
      lianaCommit: '398e622596e7530a328de3027cb2c09905f708c6',
      miniscriptVersion: '11.2.0',
      network: 'signet',
      multipathChoices: [7, 19],
    });
    const body = nonstandardMultipathFixture.multipathDescriptorBody;
    const wallet = parseLianaDescriptor(`${body}#${descriptorChecksum(body)}`, 'signet');
    let compared = 0;
    for (const branch of ['receive', 'change'] as const) {
      for (let index = 0; index < 10; index++) {
        const derived = deriveWalletAddress(wallet, branch, index);
        expect({
          address: derived.address,
          scriptPubKey: Buffer.from(derived.scriptPubKey).toString('hex'),
        }, `${branch}/${index} (${nonstandardMultipathFixture.id})`).toEqual(nonstandardMultipathFixture.expected[branch][String(index)]);
        compared++;
      }
    }
    expect(compared).toBe(20);
  });
});
