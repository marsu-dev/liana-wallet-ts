import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { Output, networks } from '@bitcoinerlab/descriptors';

type Expected = { address: string; scriptPubKey: string };
type Vector = { id?: string; descriptor: string; expected: Record<'receive' | 'change', Record<string, Expected>> };
type Fixture = {
  id?: string;
  provenance?: { network: string };
  descriptor?: string;
  multipathDescriptorBody?: string;
  expected?: Vector['expected'];
  cases?: Vector[];
};

const files = [
  'liana-v9-rust-taproot-multisig.json',
  'liana-v9-rust-legacy-wsh.json',
  'liana-v9-rust-legacy-wsh-multisig.json',
  'liana-v9-rust-legacy-wsh-multiple-recovery.json',
  'liana-v9-rust-legacy-wsh-andor.json',
  'liana-v9-rust-legacy-wsh-v2-thresholds.json',
  'liana-v9-rust-signet-v2-bip32-derivs.json',
  'liana-v9-rust-signet-single-primary-recovery.json',
];

function fixtureVectors(filename: string): { filename: string; network: 'mainnet' | 'signet'; vector: Vector }[] {
  const fixture = JSON.parse(readFileSync(resolve('tests/fixtures', filename), 'utf8')) as Fixture;
  const network = fixture.provenance?.network === 'signet' ? 'signet' : 'mainnet';
  const descriptor = fixture.multipathDescriptorBody ?? fixture.descriptor ?? '';
  const vectors = fixture.cases ?? [{
    id: fixture.id ?? filename,
    descriptor,
    expected: fixture.expected ?? { receive: {}, change: {} },
  }];
  return vectors.map((vector) => ({ filename, network, vector }));
}

describe('independent descriptor-library parity against pinned Liana Rust vectors', () => {
  it('matches the exact Rust address and scriptPubKey after positional multipath selection', () => {
    let compared = 0;
    for (const filename of files) {
      for (const { network, vector } of fixtureVectors(filename)) {
        for (const branch of ['receive', 'change'] as const) {
          for (const [indexText, expected] of Object.entries(vector.expected[branch])) {
            const checksumIndex = vector.descriptor.lastIndexOf('#');
            const body = checksumIndex < 0 ? vector.descriptor : vector.descriptor.slice(0, checksumIndex);
            const source = body.replace(/<(\d+);(\d+)>/g, (_tuple, receive: string, change: string) => branch === 'receive' ? receive : change);
            const output = new Output({
              descriptor: source,
              checksumRequired: false,
              index: Number(indexText),
              network: network === 'signet' ? networks.testnet : networks.bitcoin,
            });
            expect({
              address: output.getAddress(),
              scriptPubKey: Buffer.from(output.getScriptPubKey()).toString('hex'),
            }, `${filename} ${vector.id ?? ''} ${branch}/${indexText}`).toEqual(expected);
            compared++;
          }
        }
      }
    }
    expect(compared).toBe(64);
  });
});
