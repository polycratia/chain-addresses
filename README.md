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
from chain_addresses import ExtendedPublicKey, get_encoder

account = ExtendedPublicKey.parse(account_xpub)
deposit = account.derive("0/17")

encoder = get_encoder("bitcoin-p2wpkh")
encoder.encode(deposit.public_key)   # bc1q...
```

Only non-hardened children can be derived from a public key. Passing `"0'/17"`
or an `xprv` raises instead of silently doing something else.

## Address formats

Every encoder takes a 33-byte compressed public key and returns a string, so
code that holds an encoder never has to know which chain it is serving.

| Name | Encoding |
| --- | --- |
| `bitcoin-p2pkh` | Base58Check, version `0x00` |
| `bitcoin-p2sh` | Base58Check, version `0x05`, P2WPKH nested in P2SH |
| `bitcoin-p2wpkh` | bech32, witness version 0 |
| `bitcoin-p2tr` | bech32m, witness version 1, BIP86 key-path tweak |
| `bitcoin-testnet-*` | the four above with testnet versions and the `tb` prefix |
| `evm` | EIP-55 checksummed hex, for any EVM chain |

`ENCODERS` maps each name to its encoder, for offering the list to a user.

## Validating an address

An address you did not derive yourself — a withdrawal destination, a value from
a form — should be checked before anything is sent to it. The failures are not
interchangeable, so they come back as a typed reason rather than a message:

```python
from chain_addresses import Reason, validate_address

result = validate_address(destination, network="testnet")
if not result:
    if result.reason is Reason.WRONG_NETWORK:
        ...          # well-formed, but result.network says which chain it is for
    elif result.reason is Reason.BAD_CHECKSUM:
        ...          # a typo or a truncated copy, worth asking the user again
```

A valid result carries the format it recognised (`result.format`, a name from
the table above) and the network the address belongs to. Encoding is checked
first, so a corrupted testnet address is a `BAD_CHECKSUM`, not a
`WRONG_NETWORK`. EIP-55 hex belongs to `Network.ANY` and passes any network
check, and `formats=` narrows the accepted formats when a flow only serves one.

Validation reaches slightly further than derivation: a version 0, 32-byte
witness program (P2WSH) is a fine destination and validates as
`bitcoin-p2wsh`, even though no encoder here produces one.

## Status

Pre-alpha. BIP32 public derivation, the address formats above and address
validation are implemented; chain metadata and gap-limit scanning are not
written yet.

## Installation

```bash
pip install chain-addresses
```

## Development

```bash
pip install -e ".[dev]"
python -m pytest
```

The test suite carries its own private-key derivation (CKDpriv) and checks that
public derivation reaches the same children, so the public-only path is verified
against the private one it is meant to replace. Keccak-256 is checked against
`hashlib.sha3_256` through the one domain byte that separates them.

## License

MIT

Maintained by [polycratia](https://polycratia.com).
