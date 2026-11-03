# Security policy

## Scope

This project is an early-stage, watch-only Bitcoin descriptor derivation library. It is not a signing tool, wallet, or substitute for validating addresses with the pinned Liana implementation. Treat extended public keys and descriptors as sensitive financial-privacy metadata.

## Reporting

Please do not publish exploitable security issues before maintainers can assess them. Use GitHub's private vulnerability reporting for this repository when enabled. If private reporting is unavailable, contact the repository owner privately before opening a public issue.

## Secret handling

Never include real mnemonic phrases, passphrases, seeds, private keys, wallet backups, or identifiable production descriptors in issues, tests, CI logs, or fixtures. Test fixtures must be public test data and record their provenance. This package does not intentionally persist key material.

Dependency updates touching cryptographic behavior require reproducible vectors and renewed compatibility checks.
