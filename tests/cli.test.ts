import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';

const fixturePath = resolve('tests/fixtures/liana-v9-signet-single-primary-recovery.json');
describe('CLI', () => {
  it('lists a watch-only change address from a fixture file', () => {
    const output = execFileSync(resolve('node_modules/.bin/tsx'), ['src/cli.ts', '--network', 'signet', '--descriptor-file', fixturePath, '--branch', 'change', '--start', '0', '--count', '1'], { encoding: 'utf8' });
    const parsed = JSON.parse(output) as { addresses: Array<{ address: string; index: number; branch: string }> };
    expect(parsed.addresses[0]).toMatchObject({ address: 'tb1prn8cy7j5q8sc2g7ahgexmjfxauwvluvp7m80gvw9rzzrdnpculpsw6h524', index: 0, branch: 'change' });
  });
  it('lists a watch-only receive address range as JSON without printing the descriptor', () => {
    const output = execFileSync(resolve('node_modules/.bin/tsx'), ['src/cli.ts', '--network', 'signet', '--descriptor-file', fixturePath, '--branch', 'receive', '--start', '0', '--count', '1'], { encoding: 'utf8' });
    const parsed = JSON.parse(output) as { addresses: Array<{ address: string; scriptPubKey: string; index: number; branch: string }> };
    expect(parsed.addresses).toEqual([{ address: 'tb1pvpqeka564yfls5ma8ps56q2xd4sn8mstm7pe6nfxezw3wc963pysnda6x9', scriptPubKey: '512060419b769aa913f8537d38614d01466d6133ee0bdf839d4d26c89d1760ba8849', index: 0, branch: 'receive' }]);
    expect(output).not.toContain('tpubDDvFW');
  });
});
