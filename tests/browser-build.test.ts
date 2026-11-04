import { describe, expect, it } from 'vitest';
import { build } from 'esbuild';
import { resolve } from 'node:path';

describe('browser build', () => {
  it('bundles the public API without Node builtins or raw WASM imports', async () => {
    const result = await build({
      entryPoints: [resolve('src/index.ts')],
      bundle: true,
      platform: 'browser',
      format: 'esm',
      target: 'es2022',
      outfile: 'liana-wallet.browser.js',
      write: false,
    });
    const output = result.outputFiles.map((file) => file.text).join('\n');
    expect(output).not.toMatch(/from ["']node:|require\(["']node:/);
    expect(output).not.toMatch(/secp256k1\.wasm/);
    expect(output).not.toMatch(/\bBuffer\.(?:from|isBuffer)/);
    expect(output).toContain('deriveWalletAddress');
  });
});
