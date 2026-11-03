export type Network = 'mainnet' | 'testnet' | 'signet' | 'regtest';
export interface AccountKey { network: Network; xpub: string; masterFingerprint: string; originPath: string; }
export interface DerivedKey { branchIndex: number; addressIndex: number; compressedPublicKey: Uint8Array; xOnlyPublicKey: Uint8Array; }
export type { WalletDescriptor } from './liana.js';
export interface DerivedAddress { address: string; scriptPubKey: Uint8Array; branch: 'receive' | 'change'; index: number; }
export { WalletDerivationError, type WalletDerivationErrorCode } from './errors.js';
export { deriveAccountXpub, deriveChildKey, importAccountXpub, mnemonicToSeed } from './bip32.js';
export { descriptorChecksum, parseMultipath, splitDescriptorChecksum } from './descriptors.js';
export type { DescriptorAst, DescriptorAstNode, DescriptorKeyExpression } from './descriptors.js';
export { deriveDescriptorAddress, deriveWalletAddress } from './address.js';
export { parseLianaDescriptor } from './liana.js';
export { constructUnspendableInternalXpub } from './taproot.js';
