import { Output } from '@bitcoinerlab/descriptors';
import { networks, type Network as BitcoinNetwork } from 'bitcoinjs-lib';
import { importAccountXpub, assertNetwork, type Network, type AccountKey } from './bip32.js';
import { WalletDerivationError } from './errors.js';
import { constructUnspendableInternalXpub } from './taproot.js';
import { splitDescriptorChecksum } from './descriptors.js';
export interface WalletDescriptor { network: Network; original: string; checksum: string; signers: AccountKey[]; }
const KEY_WITH_ORIGIN = /\[([0-9a-fA-F]{8}(?:\/(?:0|[1-9]\d*)['hH]?)*?)\]((?:xpub|tpub)[1-9A-HJ-NP-Za-km-z]+)/g;
function bitcoinNetwork(network: Network): BitcoinNetwork {
  if (network === 'mainnet') return networks.bitcoin;
  if (network === 'regtest') return { ...networks.testnet, bech32: 'bcrt' };
  return networks.testnet;
}
function validateLianaTaprootPolicy(body: string): void {
  const tr = /^tr\(([^,]+)(?:,([\s\S]*))?\)$/.exec(body);
  if (!tr) return;
  if (!tr[2] || !/\bolder\s*\(/.test(tr[2])) {
    throw new WalletDerivationError('INVALID_DESCRIPTOR', 'Liana Taproot descriptors require a recovery TapTree with at least one relative timelock');
  }
}
function validateNumsInternalKey(body: string, network: Network): void {
  const tr = /^tr\(([^,]+),([\s\S]*)\)$/.exec(body);
  if (!tr) return;
  const internal = /^((?:xpub|tpub)[1-9A-HJ-NP-Za-km-z]+)\/<0;1>\/\*$/.exec(tr[1]!);
  if (!internal) return;
  const leafXpubs = [...tr[2]!.matchAll(KEY_WITH_ORIGIN)].map((match) => match[2]!);
  if (leafXpubs.length === 0) throw new WalletDerivationError('INVALID_INTERNAL_KEY', 'NUMS internal key requires originated extended public keys in the TapTree');
  const expected = constructUnspendableInternalXpub(leafXpubs, network);
  if (internal[1] !== expected.xpub) throw new WalletDerivationError('INVALID_INTERNAL_KEY', 'NUMS internal xpub does not match the ordered TapTree leaf keys');
}
export function parseLianaDescriptor(text: string, network: Network): WalletDescriptor {
  assertNetwork(network);
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
  validateLianaTaprootPolicy(body);
  validateNumsInternalKey(body, network);
  try { new Output({ descriptor: body, network: bitcoinNetwork(network), index: 0, change: 0, checksumRequired: false }); }
  catch (error) { throw new WalletDerivationError('UNSUPPORTED_DESCRIPTOR', `Invalid or unsupported Liana output descriptor: ${error instanceof Error ? error.message : String(error)}`, { cause: error }); }
  return { network, original: text, checksum, signers };
}
