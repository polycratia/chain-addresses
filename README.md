# chain-addresses

One interface for deriving deposit addresses across chains, with HD derivation
instead of trusting a node's keystore.

## Deposit addresses without hot keys

A service that takes deposits needs a fresh address per customer, and it needs
them forever. The shortcut is to ask a node for one, which quietly makes the
node the wallet: it holds the keys, it owns the address gap, and the recovery
story becomes "restore that machine's keystore from a backup". Everything that
can hand out an address can also spend.

BIP32 removes the need for that trade. An extended public key is a curve point
with the chain code that belongs beside it, and from those two values every
non-hardened child public key can be computed without the private key ever
being present. The process that shows an address to a customer needs nothing
more than that, so it never holds spending authority at all.

| Stays offline | Goes online |
| --- | --- |
| seed and mnemonic | the account extended public key |
| master private key | child public keys derived from it |
| the hardened prefix, `m/84'/0'/0'` | the relative path below it, `0/17` |
| signing a withdrawal | deriving, encoding and issuing addresses |

The hardened prefix is what makes the split safe. Non-hardened derivation is
reversible in one direction nobody wants: a chain code and any child *private*
key together recover the parent private key. Hardening every step down to the
account means a leak below that point stops there — it cannot climb back to the
master key and the other accounts under it. That is also why only the last two
levels are left unhardened: they are the ones a public key can walk.

An xpub is not a spending key, but it is not public either. Anyone holding one
can compute every address the account will ever produce and link them into a
single wallet. Treat it as a privacy secret: it belongs in the service that
issues addresses, not in a customer-facing response or a client bundle.

Which prefix a signer exports — `xpub`, `ypub`, `zpub`, `tpub` — is a
serialisation detail. The version bytes describe the address format the signer
expects, not the derivation, so this package parses all of them and leaves the
choice of address format to the encoder you ask for.

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
or an `xprv` raises instead of silently doing something else: the first cannot
be reached without the seed, and the second is a key that should never have
reached this process.

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

## The gap-limit trap

Deriving addresses yourself moves one problem from the node onto you. A
watching wallet does not know how many addresses exist; it derives forward and
stops after a run of unused ones — twenty of them, by the convention BIP44
fixed. Hand out index 500 while the scanner is looking twenty past the last
used index and the key is not lost, since derivation is deterministic, but the
deposit is: nothing following that rule will ever look there. The customer
pays, the chain confirms, and no credit appears.

The recovery is a rescan with a raised limit, which means noticing first. The
cheap fix is to never issue past the frontier, which is what `AddressLedger`
exists for: it hands out addresses in order and refuses to issue one a
conforming scanner would never reach.

```python
from chain_addresses import AddressLedger, GapLimitError

ledger = AddressLedger(account, "bitcoin-p2wpkh")   # gap limit 20 by default

try:
    deposit = ledger.issue()       # .index, .path, .address, .public_key
except GapLimitError:
    ...          # twenty addresses are already out unused; none may follow
```

`issue()` is the only call that moves the cursor, so an address shown twice on
a reloaded page should come from `peek()`, and a support tool that inspects an
index should use `address_at(index)`. `remaining` counts how many addresses may
still go out and `frontier` is the first index a conforming scanner would miss.

The window only moves when a deposit is seen:

```python
ledger.mark_used(deposit.index)    # a scanner saw a payment: the window moves
```

The ways into the trap are all bookkeeping, not cryptography. Issuing an
address per page view rather than per intent burns indexes twenty at a time.
Two processes issuing from the same branch without shared state hand the same
address to two customers, or race past the frontier together. And the limit
that decides the outcome is the scanner's, not this ledger's: if the watching
wallet is configured lower than the value here, the lower one wins. Set
`gap_limit=` to match the tool that actually scans.

The state is two integers beside the key they belong to, so a process can stop
and resume without losing its place:

```python
store.save(ledger.state())         # JSON-safe: account, format, branch, indexes
ledger = AddressLedger.restore(store.load())
```

`mark_used` also accepts an index that was never issued — a restore from
another system, or an address a customer kept — and moves the cursor past it
rather than handing it out a second time.

## Status

Pre-alpha. BIP32 public derivation, the address formats above, address
validation and the gap-limit index policy are implemented; chain metadata is
not written yet.

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
`hashlib.sha3_256` through the one domain byte that separates them. Published
vectors from BIP32, BIP84 and EIP-55 live in `tests/test_vectors.py`, so drift
from the standards fails there before anything else.

## License

MIT

Maintained by [polycratia](https://polycratia.com).
