import { BIP32Factory } from 'bip32';
import * as ecc from 'tiny-secp256k1';
import { createHash } from 'node:crypto';
import type { Network } from './bip32.js';
import { WalletDerivationError } from './errors.js';
const bip32 = BIP32Factory(ecc);
const NUMS_COMPRESSED = Uint8Array.from(Buffer.from('0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0', 'hex'));
function networkParams(network: Network) { return network === 'mainnet' ? undefined : { wif: 0xef, bip32: { public: 0x043587cf, private: 0x04358394 } }; }
export interface UnspendableInternalXpub { publicKey: Uint8Array; chainCode: Uint8Array; xpub: string; descriptorKey: string; }
export function constructUnspendableInternalXpub(leafExtendedPublicKeys: readonly string[], network: Network): UnspendableInternalXpub {
  if (leafExtendedPublicKeys.length === 0) throw new WalletDerivationError('INVALID_DESCRIPTOR', 'At least one leaf extended public key is required');
  const publicKeys: Uint8Array[] = [];
  for (const xpub of leafExtendedPublicKeys) {
    try { publicKeys.push(Uint8Array.from(bip32.fromBase58(xpub, networkParams(network)).publicKey)); }
    catch (error) { throw new WalletDerivationError('INVALID_EXTENDED_KEY', `Invalid leaf extended public key: ${error instanceof Error ? error.message : String(error)}`, { cause: error }); }
  }
  const chainCode = createHash('sha256').update(Buffer.concat(publicKeys.map((key) => Buffer.from(key)))).digest();
  const node = bip32.fromPublicKey(NUMS_COMPRESSED, chainCode, networkParams(network));
  const xpub = node.toBase58();
  return { publicKey: Uint8Array.from(NUMS_COMPRESSED), chainCode: Uint8Array.from(chainCode), xpub, descriptorKey: `${xpub}/<0;1>/*` };
}
