import { Output } from '@bitcoinerlab/descriptors';
import { networks, type Network as BitcoinNetwork } from 'bitcoinjs-lib';
import { WalletDerivationError } from './errors.js';
import { assertNetwork, type Network } from './bip32.js';
import type { WalletDescriptor } from './liana.js';
import { splitDescriptorChecksum, selectMultipathBranch } from './descriptors.js';
export interface DerivedDescriptorOutput { address: string; scriptPubKey: Uint8Array; index: number; network: Network; }
export interface DerivedWalletAddress extends DerivedDescriptorOutput {
  branch: 'receive' | 'change';
  /** One selected BIP32 branch value per multipath key occurrence, in descriptor order. */
  branchIndexes: readonly number[];
}
function bitcoinNetwork(network: Network): BitcoinNetwork {
  assertNetwork(network);
  if (network === 'mainnet') return networks.bitcoin;
  if (network === 'regtest') return { ...networks.testnet, bech32: 'bcrt' };
  return networks.testnet;
}
function derive(body: string, index: number, network: Network, change?: number): DerivedDescriptorOutput {
  const output = new Output({ descriptor: body, index, ...(change === undefined ? {} : { change }), network: bitcoinNetwork(network), checksumRequired: false });
  return { address: output.getAddress(), scriptPubKey: Uint8Array.from(output.getScriptPubKey()), index, network };
}
function assertIndex(index: number): void {
  if (!Number.isInteger(index) || index < 0 || index >= 0x80000000) throw new WalletDerivationError('INVALID_INDEX', 'Address index must be a non-hardened BIP32 index');
}
export function deriveDescriptorAddress(descriptor: string, index: number, network: Network): DerivedDescriptorOutput {
  assertNetwork(network);
  assertIndex(index);
  const { body } = splitDescriptorChecksum(descriptor);
  try { return derive(body, index, network); }
  catch (error) { throw new WalletDerivationError('UNSUPPORTED_DESCRIPTOR', `Unable to derive descriptor output: ${error instanceof Error ? error.message : String(error)}`, { cause: error }); }
}
export function deriveWalletAddress(wallet: WalletDescriptor, branch: 'receive' | 'change', index: number): DerivedWalletAddress {
  assertNetwork(wallet.network);
  if (branch !== 'receive' && branch !== 'change') throw new WalletDerivationError('INVALID_PATH', `Unknown wallet branch: ${String(branch)}`);
  assertIndex(index);
  const { body } = splitDescriptorChecksum(wallet.original);
  const selection = branch === 'receive' ? 0 : 1;
  const selected = selectMultipathBranch(body, selection);
  try {
    const result = derive(selected.body, index, wallet.network);
    return { ...result, branch, branchIndexes: selected.branchIndexes };
  } catch (error) { throw new WalletDerivationError('UNSUPPORTED_DESCRIPTOR', `Unable to derive ${branch} wallet address: ${error instanceof Error ? error.message : String(error)}`, { cause: error }); }
}
