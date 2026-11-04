#!/usr/bin/env node
import { readFileSync, realpathSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { deriveDescriptorAddress, deriveWalletAddress } from './address.js';
import { parseLianaDescriptor } from './liana.js';
import { WalletDerivationError, type WalletDerivationErrorCode } from './errors.js';
import type { Network } from './bip32.js';
type Branch = 'receive' | 'change';
function usage(): string { return 'Usage: liana-wallet-ts --network <mainnet|testnet|signet|regtest> --descriptor-file <path|-> --branch <receive|change> [--start N] [--count N]'; }
function args(argv: string[]): Record<string, string> {
  const options: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    const key = argv[i]!;
    if (!key.startsWith('--') || i + 1 >= argv.length || argv[i + 1]!.startsWith('--')) throw new Error(usage());
    options[key.slice(2)] = argv[++i]!;
  }
  return options;
}
function descriptorFromFile(data: string, branch: Branch): string {
  const trimmed = data.trim();
  if (!trimmed.startsWith('{')) return trimmed;
  const parsed: unknown = JSON.parse(trimmed);
  if (!parsed || typeof parsed !== 'object') throw new Error('Descriptor file JSON must be an object');
  const record = parsed as Record<string, unknown>;
  const branchValue = record[branch];
  if (branchValue && typeof branchValue === 'object' && typeof (branchValue as Record<string, unknown>).descriptor === 'string') return (branchValue as Record<string, unknown>).descriptor as string;
  if (typeof record.descriptor === 'string') return record.descriptor;
  throw new Error(`JSON file must contain a ${branch}.descriptor or descriptor string`);
}
function networkValue(value: string | undefined): Network {
  if (value === 'mainnet' || value === 'testnet' || value === 'signet' || value === 'regtest') return value;
  throw new Error('Network must be mainnet, testnet, signet, or regtest');
}
function run(argv: string[]): void {
  const options = args(argv);
  const network = networkValue(options.network);
  const branch = options.branch;
  if (branch !== 'receive' && branch !== 'change') throw new Error('Branch must be receive or change');
  const file = options['descriptor-file'];
  if (!file) throw new Error('Descriptor file is required');
  const start = options.start === undefined ? 0 : Number(options.start);
  const count = options.count === undefined ? 10 : Number(options.count);
  if (!Number.isSafeInteger(start) || start < 0 || start >= 0x80000000 || !Number.isSafeInteger(count) || count < 1 || count > 1000 || start + count > 0x80000000) throw new WalletDerivationError('INVALID_INDEX', 'start/count must describe 1 to 1000 non-hardened addresses');
  const content = file === '-' ? readFileSync(0, 'utf8') : readFileSync(file, 'utf8');
  const descriptor = descriptorFromFile(content, branch);
  const wallet = parseLianaDescriptor(descriptor, network);
  const addresses = Array.from({ length: count }, (_, offset) => {
    const index = start + offset;
    const derived = /<\d+;\d+>/.test(descriptor) ? deriveWalletAddress(wallet, branch, index) : { ...deriveDescriptorAddress(descriptor, index, network), branch };
    return { address: derived.address, scriptPubKey: Buffer.from(derived.scriptPubKey).toString('hex'), index, branch };
  });
  process.stdout.write(`${JSON.stringify({ network, addresses }, null, 2)}\n`);
}
if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  try { run(process.argv.slice(2)); }
  catch (error) {
    const code: WalletDerivationErrorCode | 'INVALID_ARGUMENT' = error instanceof WalletDerivationError ? error.code : 'INVALID_ARGUMENT';
    process.stderr.write(`${code}: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 2;
  }
}
