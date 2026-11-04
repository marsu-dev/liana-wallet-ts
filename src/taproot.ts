import { sha256 } from '@noble/hashes/sha2.js';
import { bip32 } from './bip32-engine.js';
import { assertNetwork, type Network } from './bip32.js';
import { WalletDerivationError } from './errors.js';
const NUMS_COMPRESSED_HEX = '0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0';
const NUMS_COMPRESSED = Uint8Array.from(NUMS_COMPRESSED_HEX.match(/.{2}/g)!, (byte) => Number.parseInt(byte, 16));
function networkParams(network: Network) {
  assertNetwork(network);
  return network === 'mainnet' ? undefined : { wif: 0xef, bip32: { public: 0x043587cf, private: 0x04358394 } };
}
export interface UnspendableInternalXpub { publicKey: Uint8Array; chainCode: Uint8Array; xpub: string; descriptorKey: string; }
export function constructUnspendableInternalXpub(leafExtendedPublicKeys: readonly string[], network: Network): UnspendableInternalXpub {
  if (leafExtendedPublicKeys.length === 0) throw new WalletDerivationError('INVALID_DESCRIPTOR', 'At least one leaf extended public key is required');
  const publicKeys: Uint8Array[] = [];
  for (const xpub of leafExtendedPublicKeys) {
    try { publicKeys.push(Uint8Array.from(bip32.fromBase58(xpub, networkParams(network)).publicKey)); }
    catch (error) { throw new WalletDerivationError('INVALID_EXTENDED_KEY', `Invalid leaf extended public key: ${error instanceof Error ? error.message : String(error)}`, { cause: error }); }
  }
  const concatenatedKeys = new Uint8Array(publicKeys.reduce((total, key) => total + key.length, 0));
  let offset = 0;
  for (const key of publicKeys) {
    concatenatedKeys.set(key, offset);
    offset += key.length;
  }
  const chainCode = sha256(concatenatedKeys);
  const node = bip32.fromPublicKey(NUMS_COMPRESSED, chainCode, networkParams(network));
  const xpub = node.toBase58();
  return { publicKey: Uint8Array.from(NUMS_COMPRESSED), chainCode: Uint8Array.from(chainCode), xpub, descriptorKey: `${xpub}/<0;1>/*` };
}
