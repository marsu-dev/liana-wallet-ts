export type Network = 'mainnet' | 'testnet' | 'signet' | 'regtest';
export interface AccountKey { network: Network; xpub: string; masterFingerprint: string; originPath: string; }
export interface DerivedKey { branchIndex: number; addressIndex: number; compressedPublicKey: Uint8Array; xOnlyPublicKey: Uint8Array; }
export interface WalletDescriptor { network: Network; original: string; checksum?: string; signers: AccountKey[]; }
export interface DerivedAddress { address: string; scriptPubKey: Uint8Array; branch: 'receive' | 'change'; index: number; }
export { deriveAccountXpub, deriveChildKey, importAccountXpub, mnemonicToSeed } from './bip32.js';
export { descriptorChecksum, parseMultipath, splitDescriptorChecksum } from './descriptors.js';
export { deriveDescriptorAddress } from './address.js';
