# liana-wallet-ts

Watch-only TypeScript toolkit for deriving keys and, in later milestones, exact addresses from imported Liana Bitcoin wallet descriptors.

> **Status: early implementation.** This package currently implements basic BIP32 seed-to-extended-public-key derivation and non-hardened public child derivation. Liana descriptor parsing and Taproot address derivation are not implemented; no Liana compatibility claim is made.

## Requirements

- Node.js 20 or newer
- npm

## Development

```sh
npm ci
npm test
npm run typecheck
npm run build
```

The API is exported from `src/index.ts`. For public-only use, import an account xpub with its master fingerprint and origin path, then derive non-hardened branch/index keys. Do not provide or store a mnemonic in applications that only need to watch an existing wallet.

## Security

Extended public keys and descriptors are privacy-sensitive. Do not log them unnecessarily. Mnemonics, passphrases and seeds are secrets; this library does not persist them. Review cryptographic dependency changes before upgrading.

## Compatibility

Address derivation must be tested against a pinned Liana Rust/miniscript implementation and full independent fixtures before it can be considered compatible. See [PLAN.md](PLAN.md).
