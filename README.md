# liana-wallet-ts

A watch-only TypeScript library for importing supported Liana Bitcoin descriptors and deriving wallet addresses and `scriptPubKey`s. It also provides BIP32/BIP39 public-key utilities and a small command-line interface.

**Live demo:** https://marsu-dev.github.io/liana-wallet-ts/

> **Compatibility is deliberately bounded.** This library does not claim general Liana or Miniscript compatibility. See [Compatibility](docs/COMPATIBILITY.md) for the exact tested forms and vectors.

## Features

- Import checksummed Liana descriptors with originated `xpub`/`tpub` keys.
- Derive receive/change addresses and `scriptPubKey`s from supported descriptors.
- Select ordered multipath branches without rewriting the original descriptor.
- Use BIP32 account-key and public-child derivation helpers; optionally convert a BIP39 mnemonic to a seed.
- Inspect a lossless syntax AST attached to an imported descriptor.
- Batch address derivation through the CLI, including reading descriptors from standard input.
- Import the public API from modern browser applications through a prebuilt ES2022 browser export; no Node runtime is required in the browser.

## Use cases

- Build a watch-only Liana wallet viewer or address monitor.
- Derive receive and change addresses for supported Liana wallet exports.
- Check address and script outputs before integrating a descriptor into a wallet service.
- Batch-generate addresses for a wallet-import or recovery workflow.

## Demo

Try the live browser demo: [Liana Wallet TS on GitHub Pages](https://marsu-dev.github.io/liana-wallet-ts/). Address links open the corresponding transaction history on [mempool.space](https://mempool.space/) (mainnet, testnet and signet).

## Installation

This package is not published to npm yet. To use a local checkout, build it first and install the directory from your application:

```sh
# In the liana-wallet-ts checkout
npm ci
npm run build

# In your application
npm install /absolute/path/to/liana-wallet-ts
```

Requires Node.js 20.19 or newer to build the package or run its CLI. Browser applications use the package's browser ESM export and do not need Node.js at runtime; use a bundler that honors the `browser` export condition/field. `npm run build` creates `dist/browser/index.js`.

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

### Derive a Liana address from extended public keys

An `xpub` alone does not define a Liana wallet address: the descriptor also specifies the network, derivation paths, primary/recovery policy and checksum. Use the complete descriptor exported by Liana. This reproducible Signet example uses public test-vector `tpub`s and a single-key recovery path; replace the descriptor with your wallet’s own export:

```ts
import { descriptorChecksum, deriveWalletAddress, parseLianaDescriptor } from 'liana-wallet-ts'

const primaryXpub = "[07fd816d/48'/1'/0'/2']tpubDDvFWduSiwhW7hUbL1oMyUfcNgeSyZgHbooe1WjHyRaXYH3uUjm1xdxWXAGbQFn8QGScDg4b4a6WMGNiEAq2uQdmPDhDKPE5Dr8DX24mwd5"
const recoveryXpub = "[da855a1f/48'/1'/0'/2']tpubDEHRt73d4guqR5BLGQud4XMW8vDCGHUj54qDTFtsdFstF6PAYx1oAy3jfKg1PffqLUWuSsXmnetKeTJFKfKLXeJR97yUuqvvojnoBcUDHg5"
const body = `tr(${primaryXpub}/<0;1>/*,and_v(v:multi_a(1,${recoveryXpub}/<0;1>/*),older(36)))`
const descriptor = `${body}#${descriptorChecksum(body)}`

const wallet = parseLianaDescriptor(descriptor, 'signet')
const receive = deriveWalletAddress(wallet, 'receive', 0)
console.log(receive.address)
// tb1pe6f66tkglw6m3gp4apwcgww0et086wh5vnrnk6csx4s5dxp9fqjq3s2x2p
```

The expected address and `scriptPubKey` for this vector are checked against the pinned Liana Rust oracle. A real wallet must use its own complete descriptor; do not substitute only one xpub or reuse these test keys.

### Use from a browser application

The package root selects its prebuilt browser export when resolved by a bundler. No Node `crypto`, `Buffer` global, or WebAssembly loader/polyfill is required on this path:

```ts
import { deriveWalletAddress, parseLianaDescriptor } from 'liana-wallet-ts'

const wallet = parseLianaDescriptor(descriptorFromUser, 'mainnet')
const output = deriveWalletAddress(wallet, 'receive', 0)
const scriptPubKeyHex = Array.from(output.scriptPubKey, byte =>
  byte.toString(16).padStart(2, '0'),
).join('')

renderAddress(output.address, scriptPubKeyHex)
```

The browser export targets ES2022 and uses BigInt-capable browsers. The current minified entry is about 754 kB uncompressed (205 kB gzip); its size can change with dependency updates. It is smoke-tested against a pinned Liana address/script vector in Chromium; see [Compatibility](docs/COMPATIBILITY.md). The CLI remains Node-only.

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
