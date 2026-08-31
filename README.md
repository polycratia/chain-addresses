# chain-addresses

One interface for deriving deposit addresses across chains, with HD derivation
instead of trusting a node's keystore.

## Why

Asking a node to hand out a fresh deposit address means the node owns the keys,
the address gap, and the recovery story. Deriving addresses yourself from an
extended public key keeps that control in your application: the node becomes a
read-only view of the chain, and every address is reproducible from a seed.

## Usage

Start from an account-level extended public key exported by an offline signer.
Nothing in this package accepts or stores a private key, so the process that
hands out deposit addresses never holds spending authority.

```python
from chain_addresses import ExtendedPublicKey

account = ExtendedPublicKey.parse(account_xpub)
deposit = account.derive("0/17")

deposit.public_key.hex()      # compressed point for the address encoder
deposit.fingerprint.hex()     # HASH160 prefix, useful for audit records
deposit.serialize()           # the child as its own extended public key
```

Only non-hardened children can be derived from a public key. Passing `"0'/17"`
or an `xprv` raises instead of silently doing something else.

## Status

Pre-alpha. BIP32 public derivation is implemented; the per-chain address
encoders are not written yet.

## Installation

```bash
pip install chain-addresses
```

## Development

```bash
pip install -e .
```

## License

MIT

Maintained by [polycratia](https://polycratia.com).
