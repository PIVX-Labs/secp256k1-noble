# secp256k1-noble (Name is a placeholder)

[secp256k1-node](https://github.com/cryptocoinjs/secp256k1-node) compatible library based on @noble/secp256k1 instead of elliptic.js

The unit tests are taken from https://github.com/cryptocoinjs/secp256k1-node and modified slightly.

## Differences with secp256k1-node

- `signatureImport` and `signatureExport` have not been implemented
- `ecdsaVerify` doesn't throw if signature can't be parsed, but returns `false`
- `ecdsaRecover` throws `Signature could not be parsed` instead of `Public key could not be recover` when given an invalid signature
- `privateKeyNegate` throws when given an out of bounds private key instead of carrying on
Any other discrepancy is considered a bug, and should be reported.
