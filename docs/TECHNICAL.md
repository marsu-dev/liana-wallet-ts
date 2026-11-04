# Technical documentation

This document describes the package API, descriptor-processing flow, CLI contract and security boundaries. The root [README](../README.md) is the user-facing quickstart. Exact supported descriptor forms, oracle versions, vector counts and provenance have one canonical home in [COMPATIBILITY.md](COMPATIBILITY.md); do not infer broader compatibility from the API descriptions below.

## Runtime and package

- Node.js: `>=20.19.0` for building the package and running the CLI.
- Package: `liana-wallet-ts`, ESM (`type: module`), TypeScript declarations shipped from `dist/index.d.ts`.
- Browser: the root export selects `dist/browser/index.js` through the `browser` export condition/field. It is a self-contained ESM bundle targeting ES2022; the watch-only API path has no Node core imports, global `Buffer` requirement, or WASM asset. BIP39 uses `@scure/bip39` and imports only the English wordlist by default. The CLI remains Node-only.
- `npm run build` emits both Node ESM/CLI files and the browser bundle.
- Network values: `mainnet`, `testnet`, `signet`, `regtest`.
- The package is not yet published to the npm registry. Build the checkout before installing it by local path.

## Public API

All exports below are available from the package root unless identified as a type.

### BIP32 and BIP39

- `mnemonicToSeed(mnemonic, passphrase?, wordlist?)` validates BIP39 using the English wordlist by default, or the supplied `string[]`, and applies Unicode NFKD normalization to the mnemonic and passphrase.
- `deriveAccountXpub(seed, path, network)` derives an account node from a seed and returns an `AccountKey` containing its network, xpub, master fingerprint and origin path.
- `importAccountXpub(xpub, origin, network)` validates a public extended key against its network and the supplied fingerprint/path metadata.
- `deriveChildKey(account, branch, index)` derives a non-hardened public child and returns its compressed and x-only public keys.

`AccountKey` contains `{ network, xpub, masterFingerprint, originPath }`. Hardened derivation is possible only while deriving from a seed; child derivation below an xpub accepts non-hardened indexes.

### Descriptors and addresses

- `parseLianaDescriptor(text, network)` requires a valid descriptor checksum, rejects private-key material, imports signer origins, validates the supported Liana policy subset, and returns a `WalletDescriptor` containing the original text, checksum, signers and syntax AST.
- `deriveWalletAddress(wallet, branch, index)` derives one `receive` or `change` output from a parsed wallet descriptor. For multipath descriptors, branch `receive` selects the first choice and `change` selects the second, preserving the original descriptor text. The result includes `branchIndexes`, in descriptor key-occurrence order.
- `deriveDescriptorAddress(descriptor, index, network)` derives one output from a checksummed descriptor without the Liana-specific wallet branch selection helper.
- `descriptorChecksum(text)` computes a descriptor checksum; `splitDescriptorChecksum(text)` validates and separates the body/checksum.
- `parseMultipath(expression)` parses the supported originated `xpub`/`tpub` multipath key expression.
- `constructUnspendableInternalXpub(leafExtendedPublicKeys, network)` constructs the NUMS internal extended key used by the supported Taproot descriptor construction.

`WalletDescriptor.ast` is a syntax tree. Nodes preserve raw source slices, offsets, argument and prefix ordering, and binary Taproot tree shape. This AST is not a complete Miniscript semantic model and is not evidence that unsupported descriptor forms are accepted.

`DerivedWalletAddress` contains the Bech32/Bech32m address, `scriptPubKey` as `Uint8Array`, network, index, branch and selected multipath values. Convert scripts to display hex in either runtime with `Array.from(scriptPubKey, byte => byte.toString(16).padStart(2, '0')).join('')`.

### Errors

Validation and derivation failures are reported as `WalletDerivationError`, with a stable `code` from `WalletDerivationErrorCode`. Codes include invalid seed/path/index/origin, invalid extended key, network mismatch, checksum required/invalid, invalid/unsupported descriptor, invalid internal key and missing signer keys. The CLI prints the code and message to stderr and exits with status 2.

## Processing flow

1. Parse and validate the supplied descriptor checksum.
2. Reject private-key encodings and hardened derivation below public extended keys.
3. Import signer xpubs/tpubs and check key origin metadata against extended-key depth and child-number metadata.
4. Validate the bounded Liana policy and selected network.
5. For wallet derivation, select receive/change values from every ordered multipath occurrence, derive the output, and return both address and script.

A descriptor or xpub is public-key data, not a spending key, but it can still reveal wallet ownership and address history. Watch-only callers should import descriptors directly and avoid mnemonic/seed APIs.

## CLI contract

The executable is `liana-wallet-ts` after installation; from the checkout it can be run as `node dist/cli.js` after `npm run build`.

```text
liana-wallet-ts --network <mainnet|testnet|signet|regtest> \
  --descriptor-file <path|-> --branch <receive|change> \
  [--start N] [--count N]
```

- A file may contain a descriptor string or JSON with a top-level `descriptor` string, or a `receive.descriptor` / `change.descriptor` string selected by `--branch`.
- `--descriptor-file -` reads UTF-8 descriptor text from stdin. Descriptor text is intentionally not accepted as a command-line argument, reducing exposure in shell history and process listings.
- Defaults: `start=0`, `count=10`. `count` must be from 1 to 1,000, and the range must fit non-hardened BIP32 indexes.
- Standard output is JSON `{ network, addresses }`; each address entry has `address`, hex `scriptPubKey`, `index` and `branch`. Descriptor content is not echoed.

## Compatibility boundary

The importer deliberately supports only the Liana descriptor shapes and networks documented in [COMPATIBILITY.md](COMPATIBILITY.md). That document records the pinned Rust Liana/Miniscript versions, exact fixture provenance, supported policy forms, negative cases and the boundary of the third-party library parity tests. Tests built from synthetic TypeScript values are not oracle vectors.

Do not broaden policy acceptance from a syntactically plausible descriptor alone. For compatibility-sensitive changes, probe the exact descriptor with the pinned Rust implementation, assert inferred primary/recovery structure, and compare both address and `scriptPubKey` for receive/change branches and indexes.

## Security notes

- Do not put mnemonic phrases, passphrases, seeds, private keys or xprvs in descriptors, fixtures, examples, logs or issue reports.
- Treat xpubs, fingerprints and descriptors as privacy-sensitive. Do not log descriptor input in the CLI or services.
- The mnemonic helper is optional; its presence does not make this package a signer or key-custody library.
- Review cryptographic dependency changes and regenerate/compare oracle fixtures before accepting them.

## Local verification

```sh
npm ci
npm test
npm run typecheck
npm run build
npm pack --dry-run
npm audit --omit=dev
```

See [PLAN.md](../PLAN.md) for current implementation gates and [tests/oracle/README.md](../tests/oracle/README.md) for the oracle fixture generation procedure.
