import { Output } from '@bitcoinerlab/descriptors';
import { networks, type Network as BitcoinNetwork } from 'bitcoinjs-lib';
import type { Network } from './bip32.js';
import { splitDescriptorChecksum } from './descriptors.js';
export interface DerivedDescriptorOutput { address: string; scriptPubKey: Uint8Array; index: number; network: Network; }
function bitcoinNetwork(network: Network): BitcoinNetwork {
  if (network === 'mainnet') return networks.bitcoin;
  if (network === 'regtest') return { ...networks.testnet, bech32: 'bcrt' };
  return networks.testnet;
}
export function deriveDescriptorAddress(descriptor: string, index: number, network: Network): DerivedDescriptorOutput {
  if (!Number.isInteger(index) || index < 0 || index >= 0x80000000) throw new Error('Address index must be a non-hardened BIP32 index');
  const { body } = splitDescriptorChecksum(descriptor);
  try {
    const output = new Output({ descriptor: body, index, network: bitcoinNetwork(network) });
    return { address: output.getAddress(), scriptPubKey: Uint8Array.from(output.getScriptPubKey()), index, network };
  } catch (error) {
    throw new Error(`Unable to derive descriptor output: ${error instanceof Error ? error.message : String(error)}`);
  }
}
