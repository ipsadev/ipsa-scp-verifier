# ipsa-scp-verifier (archived)

this repository is archived and no longer developed. the work that lived here has moved into dedicated crates, each published on crates.io. the published `ipsa-scp-verifier` crate stays on crates.io so existing builds keep working, but it will not get new releases.

## where it went

the verifier was split along its two responsibilities: the audited consensus checker, and the tooling that feeds it evidence and reports on it.

- **[stellar-consensus-verifier](https://github.com/ipsadev/stellar-consensus-verifier)** (`stellar-consensus-verifier` on crates.io) is the audited core: a `no_std` library that verifies stellar scp consensus for a single ledger, with a typed front door (`verify_update`, `verify_header`, `verify_consensus`). this is the part on the critical path, and the one to depend on for verification.
- **[scp-exporter](https://github.com/ipsadev/ipsa-tooling)** (`scp-exporter` on crates.io, in the ipsa-tooling workspace) reads evidence from the public history archives: the `archive`, `history`, and `network` modules that used to live behind this crate's `io` feature.
- **[scp-verify](https://github.com/ipsadev/ipsa-tooling)** (`scp-verify` on crates.io, in ipsa-tooling) is the command line tool and http server, together with the step-by-step report (`evaluate`) and the checkpoint cache (`api`). it builds on stellar-consensus-verifier for the verification and on scp-exporter for the evidence, and installing it gives you the `scp-verify` binary that replaces `ipsa-scp-verify`.
- **chain-check** (in the ipsa-tooling workspace) is the independent cross-check: a second implementation with its own xdr reader and its own cryptography, used to catch mistakes in the core verifier.

## migrating

replace the dependency:

```toml
# before
ipsa-scp-verifier = { version = "3", default-features = false }

# after: the verifier itself
stellar-consensus-verifier = "2"

# and, if you read evidence from the archives, add
scp-exporter = "0.1"
```

replace the command line tool:

```sh
# before
cargo install ipsa-scp-verifier   # installs ipsa-scp-verify

# after
cargo install scp-verify          # installs scp-verify
```

the `--ledger` and `--trust-root` interface, and the trust-root rules the verifier enforces, are unchanged. see the scp-verify readme for current usage.
