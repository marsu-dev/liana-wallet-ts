import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const fixturePath = resolve('tests/fixtures/liana-v9-signet-single-primary-recovery.json');
const fixture = JSON.parse(readFileSync(fixturePath, 'utf8')) as {
  receive: { descriptor: string; scriptPubKeyIndex0: string; addresses0to9: string[] };
};
describe('CLI', () => {
  it('lists a watch-only change address from a fixture file', () => {
    const output = execFileSync(resolve('node_modules/.bin/tsx'), ['src/cli.ts', '--network', 'signet', '--descriptor-file', fixturePath, '--branch', 'change', '--start', '0', '--count', '1'], { encoding: 'utf8' });
    const parsed = JSON.parse(output) as { addresses: Array<{ address: string; index: number; branch: string }> };
    expect(parsed.addresses[0]).toMatchObject({ address: 'tb1prn8cy7j5q8sc2g7ahgexmjfxauwvluvp7m80gvw9rzzrdnpculpsw6h524', index: 0, branch: 'change' });
  });
  it('lists a two-address receive range with exact addresses and scripts from stdin', () => {
    const output = execFileSync(resolve('node_modules/.bin/tsx'), ['src/cli.ts', '--network', 'signet', '--descriptor-file', '-', '--branch', 'receive', '--start', '0', '--count', '2'], { encoding: 'utf8', input: fixture.receive.descriptor });
    const parsed = JSON.parse(output) as { network: string; addresses: Array<{ address: string; scriptPubKey: string; index: number; branch: string }> };
    expect(parsed.network).toBe('signet');
    expect(parsed.addresses.map(({ address, index, branch }) => ({ address, index, branch }))).toEqual([
      { address: fixture.receive.addresses0to9[0], index: 0, branch: 'receive' },
      { address: fixture.receive.addresses0to9[1], index: 1, branch: 'receive' },
    ]);
    expect(parsed.addresses[0]?.scriptPubKey).toBe(fixture.receive.scriptPubKeyIndex0);
    expect(parsed.addresses[1]?.scriptPubKey).toMatch(/^5120[0-9a-f]{64}$/);
  });
  it('lists a watch-only receive address range as JSON without printing the descriptor', () => {
    const output = execFileSync(resolve('node_modules/.bin/tsx'), ['src/cli.ts', '--network', 'signet', '--descriptor-file', fixturePath, '--branch', 'receive', '--start', '0', '--count', '1'], { encoding: 'utf8' });
    const parsed = JSON.parse(output) as { addresses: Array<{ address: string; scriptPubKey: string; index: number; branch: string }> };
    expect(parsed.addresses).toEqual([{ address: 'tb1pvpqeka564yfls5ma8ps56q2xd4sn8mstm7pe6nfxezw3wc963pysnda6x9', scriptPubKey: '512060419b769aa913f8537d38614d01466d6133ee0bdf839d4d26c89d1760ba8849', index: 0, branch: 'receive' }]);
    expect(output).not.toContain('tpubDDvFW');
  });
  it('runs when invoked through a package-style symlink', () => {
    const directory = mkdtempSync(join(tmpdir(), 'liana-cli-'));
    const symlink = join(directory, 'liana-wallet-ts.ts');
    symlinkSync(resolve('src/cli.ts'), symlink);
    try {
      const output = execFileSync(resolve('node_modules/.bin/tsx'), [symlink, '--network', 'signet', '--descriptor-file', fixturePath, '--branch', 'receive', '--start', '0', '--count', '1'], { encoding: 'utf8' });
      const parsed = JSON.parse(output) as { addresses: Array<{ address: string; branch: string }> };
      expect(parsed.addresses[0]).toMatchObject({ address: fixture.receive.addresses0to9[0], branch: 'receive' });
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
