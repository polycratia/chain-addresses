# chain-addresses

One interface for deriving deposit addresses across chains, with HD derivation
instead of trusting a node's keystore.

## Why

Asking a node to hand out a fresh deposit address means the node owns the keys,
the address gap, and the recovery story. Deriving addresses yourself from an
extended public key keeps that control in your application: the node becomes a
read-only view of the chain, and every address is reproducible from a seed.

## Status

Pre-alpha. The package installs, but the derivation backends are not implemented
yet.

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
