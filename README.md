# liana-wallet-ts

A watch-only TypeScript library for importing supported Liana Bitcoin descriptors and deriving wallet addresses and `scriptPubKey`s. It also provides BIP32/BIP39 public-key utilities and a small command-line interface.

> **Compatibility is deliberately bounded.** This library does not claim general Liana or Miniscript compatibility. See [Compatibility](docs/COMPATIBILITY.md) for the exact tested forms and vectors.

## Features

- Import checksummed Liana descriptors with originated `xpub`/`tpub` keys.
- Derive receive/change addresses and `scriptPubKey`s from supported descriptors.
- Select ordered multipath branches without rewriting the original descriptor.
- Use BIP32 account-key and public-child derivation helpers; optionally convert a BIP39 mnemonic to a seed.
- Inspect a lossless syntax AST attached to an imported descriptor.
- Batch address derivation through the CLI, including reading descriptors from standard input.

## Use cases

- Build a watch-only Liana wallet viewer or address monitor.
- Derive receive and change addresses for supported Liana wallet exports.
- Check address and script outputs before integrating a descriptor into a wallet service.
- Batch-generate addresses for a wallet-import or recovery workflow.

## Installation

This package is not published to npm yet. To use a local checkout, build it first and install the directory from your application:

```sh
# In the liana-wallet-ts checkout
npm ci
npm run build

# In your application
npm install /absolute/path/to/liana-wallet-ts
```

Requires Node.js 20.19 or newer.

## Usage

### Derive a receive and change address

Save a *checksummed multipath* Liana descriptor (with `<0;1>` branch choices) in `wallet.descriptor`:

```ts
import { readFile } from 'node:fs/promises'
import { deriveWalletAddress, parseLianaDescriptor } from 'liana-wallet-ts'

const descriptor = (await readFile('./wallet.descriptor', 'utf8')).trim()
const wallet = parseLianaDescriptor(descriptor, 'signet')

for (const branch of ['receive', 'change'] as const) {
  const output = deriveWalletAddress(wallet, branch, 0)
  console.log(`${branch}: ${output.address}`)
  console.log(`scriptPubKey: ${Buffer.from(output.scriptPubKey).toString('hex')}`)
}
```

`deriveWalletAddress` returns the address, script, requested branch and index, plus the selected multipath value for each key occurrence. If you have separate receive/change descriptors rather than one multipath descriptor, use `deriveDescriptorAddress(descriptor, index, network)` for each descriptor.

### Derive a range

```ts
const firstIndex = 0
const count = 5
const receive = Array.from({ length: count }, (_, offset) =>
  deriveWalletAddress(wallet, 'receive', firstIndex + offset),
)

console.log(receive.map(({ index, address }) => ({ index, address })))
```

### Use the CLI

The CLI accepts a descriptor text file or JSON containing a `receive.descriptor`, `change.descriptor`, or top-level `descriptor` field. Use `-` to read descriptor text from standard input.

```sh
npm run build
node dist/cli.js \
  --network signet \
  --descriptor-file wallet-descriptors.json \
  --branch receive \
  --start 0 \
  --count 5
```

It prints JSON with addresses and `scriptPubKey`s; it does not echo the descriptor. Each request is limited to 1,000 addresses.

## Security

- This is a watch-only library; an existing wallet descriptor is sufficient for address derivation.
- Extended public keys and descriptors can reveal wallet activity and are privacy-sensitive. Avoid logging or sharing them unnecessarily.
- Mnemonics, passphrases and seeds are secrets. The optional `mnemonicToSeed` helper does not persist them, but applications that call it must protect them and keep them out of logs.
- Verify derived addresses against a trusted wallet or hardware device before relying on them for funds.

## Technical documentation

- [Technical guide and API details](docs/TECHNICAL.md)
- [Compatibility scope, pinned Rust oracle and fixture provenance](docs/COMPATIBILITY.md)
- [Implementation plan](PLAN.md)

## Standards

- [BIP32 — Hierarchical Deterministic Wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP39 — Mnemonic code for generating deterministic keys](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP380 — Output script descriptors](https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki)
- [BIP341 — Taproot](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)

This project implements only the documented and tested subset of these standards; see the compatibility document before assuming broader support.

## Development

```sh
npm ci
npm test
npm run typecheck
npm run build
```
