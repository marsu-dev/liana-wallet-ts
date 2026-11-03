export type WalletDerivationErrorCode =
  | 'INVALID_SEED'
  | 'INVALID_PATH'
  | 'INVALID_INDEX'
  | 'INVALID_ORIGIN'
  | 'INVALID_EXTENDED_KEY'
  | 'NETWORK_MISMATCH'
  | 'CHECKSUM_REQUIRED'
  | 'INVALID_CHECKSUM'
  | 'INVALID_DESCRIPTOR'
  | 'UNSUPPORTED_DESCRIPTOR'
  | 'INVALID_INTERNAL_KEY'
  | 'NO_SIGNER_KEYS';
export class WalletDerivationError extends Error {
  readonly code: WalletDerivationErrorCode;
  constructor(code: WalletDerivationErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'WalletDerivationError';
    this.code = code;
  }
}
