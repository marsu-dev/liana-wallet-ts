# liana-wallet-ts

Watch-only TypeScript toolkit for deriving keys and addresses from imported Bitcoin descriptors, with Liana compatibility under active validation.

> **Status: early implementation.** This package implements BIP32/BIP39 watch-only derivation, Bitcoin Core descriptor checksums, originated xpub/tpub extraction, a bounded CLI, and descriptor-based addresses/scripts for tested shapes. Authoritative Liana Rust parity is now verified for four generated Taproot policies: single-key primary/recovery, 3-of-3 primary with one 2-of-3 recovery, a case with different primary/recovery multipath values (`<0;1>` and `<2;3>`), and 2-of-3 primary with three recovery paths, at receive/change indices 0–1. Broader policy, parser, and network compatibility remain unverified; no general Liana compatibility claim is made.

## Requirements

- Node.js 20.19 or newer
- npm

## Development

```sh
npm ci
npm test
npm run typecheck
npm run build
```

The API is exported from `src/index.ts`. For public-only use, import an account xpub with its master fingerprint and origin path, then derive non-hardened branch/index keys. `parseLianaDescriptor(text, network)` preserves the exact input and validates the checksum and supported descriptor shape; `deriveWalletAddress(wallet, 'receive' | 'change', index)` selects the first or second ordered multipath choice without rewriting the source descriptor. Its `branchIndexes` result lists the selected BIP32 path value for each multipath key occurrence in original descriptor order. Do not provide or store a mnemonic in applications that only need to watch an existing wallet.

For a checked-out project, the CLI reads either a plain descriptor text file or a JSON file with a `receive.descriptor` / `change.descriptor` field. It accepts `-` as the file path to read from standard input; descriptor text is not accepted as a command-line argument, avoiding shell-history exposure.

```sh
node dist/cli.js --network signet --descriptor-file wallet-descriptors.json --branch receive --start 0 --count 10
```

Output is JSON containing addresses, `scriptPubKey`s, indexes and branch labels. Descriptor content is never echoed. The CLI caps each range at 1,000 addresses.

## Security

Extended public keys and descriptors are privacy-sensitive. Do not log them unnecessarily. Mnemonics, passphrases and seeds are secrets; this library does not persist them. Review cryptographic dependency changes before upgrading.

## Compatibility

Address derivation must be tested against a pinned Liana Rust/miniscript implementation and full independent fixtures before it can be considered compatible. See [PLAN.md](PLAN.md).
