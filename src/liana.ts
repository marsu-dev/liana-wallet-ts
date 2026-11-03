import { Output } from '@bitcoinerlab/descriptors';
import { networks, type Network as BitcoinNetwork } from 'bitcoinjs-lib';
import { importAccountXpub, type Network, type AccountKey } from './bip32.js';
import { WalletDerivationError } from './errors.js';
import { splitDescriptorChecksum } from './descriptors.js';
export interface WalletDescriptor { network: Network; original: string; checksum: string; signers: AccountKey[]; }
const KEY_WITH_ORIGIN = /\[([0-9a-fA-F]{8}(?:\/(?:0|[1-9]\d*)['hH]?)*?)\]((?:xpub|tpub)[1-9A-HJ-NP-Za-km-z]+)/g;
function bitcoinNetwork(network: Network): BitcoinNetwork {
  if (network === 'mainnet') return networks.bitcoin;
  if (network === 'regtest') return { ...networks.testnet, bech32: 'bcrt' };
  return networks.testnet;
}
export function parseLianaDescriptor(text: string, network: Network): WalletDescriptor {
  const { body, checksum } = splitDescriptorChecksum(text);
  const signers: AccountKey[] = [];
  for (const match of body.matchAll(KEY_WITH_ORIGIN)) {
    try { signers.push(importAccountXpub(match[2]!, match[1]!, network)); }
    catch (error) {
      if (error instanceof WalletDerivationError) throw error;
      throw new WalletDerivationError('INVALID_EXTENDED_KEY', `Invalid descriptor signer origin/key: ${error instanceof Error ? error.message : String(error)}`, { cause: error });
    }
  }
  if (signers.length === 0) throw new WalletDerivationError('NO_SIGNER_KEYS', 'Descriptor contains no originated xpub/tpub signer keys');
  try { new Output({ descriptor: body, network: bitcoinNetwork(network), index: 0, change: 0, checksumRequired: false }); }
  catch (error) { throw new WalletDerivationError('UNSUPPORTED_DESCRIPTOR', `Invalid or unsupported Liana output descriptor: ${error instanceof Error ? error.message : String(error)}`, { cause: error }); }
  return { network, original: text, checksum, signers };
}
