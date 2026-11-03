import { Output } from '@bitcoinerlab/descriptors';
import { networks, type Network as BitcoinNetwork } from 'bitcoinjs-lib';
import { WalletDerivationError } from './errors.js';
import type { Network } from './bip32.js';
import type { WalletDescriptor } from './liana.js';
import { splitDescriptorChecksum } from './descriptors.js';
export interface DerivedDescriptorOutput { address: string; scriptPubKey: Uint8Array; index: number; network: Network; }
export interface DerivedWalletAddress extends DerivedDescriptorOutput { branch: 'receive' | 'change'; branchIndex: number; }
function bitcoinNetwork(network: Network): BitcoinNetwork {
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
  assertIndex(index);
  const { body } = splitDescriptorChecksum(descriptor);
  try { return derive(body, index, network); }
  catch (error) { throw new Error(`Unable to derive descriptor output: ${error instanceof Error ? error.message : String(error)}`); }
}
export function deriveWalletAddress(wallet: WalletDescriptor, branch: 'receive' | 'change', index: number): DerivedWalletAddress {
  assertIndex(index);
  const { body } = splitDescriptorChecksum(wallet.original);
  const choices = [...body.matchAll(/<(\d+);(\d+)>/g)];
  if (choices.length === 0) throw new Error('Wallet descriptor has no two-choice multipath derivation');
  const values = choices.map((match) => [Number(match[1]), Number(match[2])] as const);
  if (values.some(([receive, change]) => !Number.isSafeInteger(receive) || !Number.isSafeInteger(change) || receive >= 0x80000000 || change >= 0x80000000 || receive === change)) throw new Error('Invalid multipath branch indexes');
  const [receiveIndex, changeIndex] = values[0]!;
  if (values.some(([receive, change]) => receive !== receiveIndex || change !== changeIndex)) throw new Error('Descriptor multipath choices are inconsistent across keys');
  const position = branch === 'receive' ? 0 : 1;
  try {
    const result = derive(body, index, wallet.network, position);
    return { ...result, branch, branchIndex: values[0]![position] };
  } catch (error) { throw new Error(`Unable to derive ${branch} wallet address: ${error instanceof Error ? error.message : String(error)}`); }
}
