# ipsa-scp-verifier

independently verify stellar scp consensus for a single ledger, step by step, from the public history archives.

it answers one question: did a quorum of the validators *you* trust externalize this ledger, and is this `LedgerHeader` the one they agreed on? every check runs locally against signed scp envelopes. no horizon or rpc provider is trusted for evidence, and neither is the archive.

## install

```sh
cargo install ipsa-scp-verifier
```

that installs the `ipsa-scp-verify` binary. as a library, depend on it without the cli:

```toml
ipsa-scp-verifier = { version = "3", default-features = false }
```

the `io` feature adds archive access, `serve` adds the http server, and `cli` (the default) adds both plus the binary.

## the trust root

a quorum only means something relative to a set of validators you already trust. that set is the trust root: an `SCPQuorumSet`, hex-encoded xdr, passed with `--trust-root`.

the verifier refuses to run without one. the archive carries quorum sets too, but those are pledged by the same validators whose signatures are being checked, so taking the trust root from there would let whoever writes the archive decide who counts as a quorum.

build one from the validators you trust with the stellar cli:

```sh
echo '{"threshold":2,"validators":["G...","G...","G..."],"inner_sets":[]}' \
  | stellar xdr encode --type ScpQuorumSet --output single \
  | xxd -p | tr -d '\n'
```

`trust-roots/mainnet.hex` is the set sdf's mainnet validators pledged at ledger 63907880: five of seven organisations, two of three validators each. it is what `just live` uses. read it before you rely on it:

```sh
xxd -r -p trust-roots/mainnet.hex | stellar xdr decode --type ScpQuorumSet --input single --output json
```

## usage

verify one mainnet ledger:

```sh
ipsa-scp-verify --ledger 63907880 --trust-root "$(cat trust-roots/mainnet.hex)"
```

add `--trusted-previous <hex>` with the hash of a ledger you already trust at N-1, and the header must name it as its predecessor. without it the ledger is verified as externalized, not as connected to a chain you trust. the verifier never takes N-1 from the archive for this.

other modes:

- `--negative` - after verifying, flip one field at a time and require each step to fail with the right error
- `--network testnet` - read the testnet archive and use the testnet passphrase
- `--archive <url or directory>` - read a different archive, or a local mirror
- `--fixture <path>` / `--export <path>` - verify a frozen test vector offline, or write one out. an exported vector records the ledger's transaction results, so step 8 runs offline too; older vectors without them skip it
- `--range FROM..TO` - verify every ledger in a range and classify each one instead of stopping at the first failure; `--jsonl <path>` writes one json row per ledger, and repeating `--archive` merges several archives. only `disagreement` is a finding: `invalid-evidence`, `incomplete-evidence`, `sub-quorum-evidence` and the rest describe the archive
- `--range FROM..TO --scan` - only look for a validator externalizing two values for one slot. verifies nothing, so needs no trust root
- `--range FROM..TO --audit` - check that every archived transaction set hashes to the `txSetHash` its header names, and exit non-zero if one does not. needs no trust root
- `--raw off|sample|all` and `--list-signers false` - control how much of the evidence is printed

`ipsa-scp-verify --help` lists everything.

## the http server

```sh
ipsa-scp-verify --serve 8110 --trust-root "$(cat trust-roots/mainnet.hex)" --cors-origin https://example.org
```

- `GET /health`
- `GET /mutations` - the names `mutation` accepts
- `POST /verify` with `{"ledger": 63907880}` - returns a per-step report and a verdict

a request may also carry `network`, `mutation`, `trust_root` (hex `SCPQuorumSet`) and `trusted_previous` (hex ledger hash). a request without `trust_root` uses the server's `--trust-root`, and only for the network the server was started on. with neither, the request is refused. `SCP_VERIFY_CORS_ORIGINS` (comma-separated) stands in for `--cors-origin`.

the verdict is one of:

- `verified` - every step passed and the header names the `trusted_previous` you supplied
- `verified_unanchored` - every step passed, but no `trusted_previous` was given
- `insufficient` - the evidence is well-formed but not enough: too few signers for your trust root, or a missing quorum-set preimage
- `invalid_evidence` - an envelope or quorum set is malformed or badly signed. that is a problem with the archive's data, not a claim about the ledger
- `contradicted` - well-formed, quorum-signed evidence disagrees with the header

the server runs at most 4 verifications at once and answers 503 beyond that, gives each one 90 seconds before answering 504, and keeps the last 4 checkpoints it fetched in memory. it has no per-client rate limit, so put it behind something that has one before exposing it.

## the steps

- **fetch the evidence** - scp messages, ledger header and quorum sets for ledger N, from the public history archives
- **check the signatures** - each envelope's ed25519 signature over `networkID ‖ xdr(ENVELOPE_TYPE_SCP) ‖ raw SCPStatement`
- **check the statements** - all `EXTERNALIZE`, right slot, no node appearing twice
- **check the quorum sets** - every signer's quorum set preimage hashes to the `commitQuorumSetHash` it signed
- **find the quorum** - group signers by the value they pledged, then run stellar-core's `isQuorum` against your trust root
- **check it's one value** - byte-for-byte across the group, ballot counters ignored
- **tie it to the ledger** - that value is the header's `scpValue`, and `sha256(header)` is the ledger hash
- **tie it to the next slot** - slot N+1's tx set hashes to what N+1 externalized, and names ledger N as its predecessor
- **check the results** - the archived result pairs hash to `header.txSetResultHash`. a ledger with no archived results is checked as a ledger with no transactions, against the hash of the empty set

the archive is untrusted input throughout: downloads are capped at 256 MiB, gunzipped files at 1 GiB, xdr nesting at 500 levels, and no count read from a file is used to reserve memory.

## testing

```sh
just ci     # fmt, clippy, tests, cargo audit
just live   # verify a real mainnet ledger over the network
```

`tests/quorum_oracle.rs` throws 20,000 random federations at it, up to 8 nodes with nested quorum sets,
and checks `is_quorum` against an exhaustive search over every closed subset, and `is_quorum_slice`
against a dumb counting version written separately in the same file. if the fixed point and brute force
ever disagree, one of them is wrong. runs every time, takes a fraction of a second.

then `tests/core_differential.rs`, which is the one that actually matters. 2,000 generated cases run
through stellar-core's own code - compiled out of a real stellar-core tree.

getting stellar-core to build in isolation is the annoying part, and that's what `core-oracle/` is for.
`oracle.cpp` pulls the quorum code out and puts a line protocol in front of it; `stubs.cpp` fills in
everything else stellar-core wants to link but the predicate never touches. the test spawns it, pipes
cases in on stdin, reads verdicts back off stdout. point `CORE_ORACLE` at the built binary to run it.

`tools/src/crosscheck.rs` does the same trick at the other end - verifies a whole ledger a second time
through a completely separate implementation, different xdr reader, `ring` instead of `sha2` +
`ed25519-dalek`:

```sh
cargo run -p tools -- chain-check --network mainnet --ledger 63907880 --trust-root "$(cat trust-roots/mainnet.hex)"
```

`tests/differential.rs` covers the decoder: decode the fixtures with our hand-rolled reader and with
`stellar-xdr`, assert they match. that includes the byte spans, which matters more than it sounds -
signatures cover exact bytes, so an off-by-one in a span breaks every signature check without the
output ever looking wrong.

and `--negative` flips one field at a time to confirm each step actually fails when it should.

## code map

### `src/` - the verifier

| file | what it does |
|---|---|
| `main.rs` | the `ipsa-scp-verify` binary: cli parsing, input assembly, and the whole printed report |
| `steps.rs` | the verification steps, one function per check. `verify_ledger` runs them all; `verify_header` is the light client's subset, without the signers' own quorum sets |
| `evaluate.rs` | the same steps as a structured per-step report with a verdict, for the http api |
| `api.rs` | one http request to one report: resolve the trust root, load the checkpoint, evaluate |
| `serve.rs` | the axum server behind `--serve` |
| `sweep.rs` | range mode: fetch per checkpoint, merge envelopes across archives by node, classify every ledger instead of stopping at the first failure |
| `audit.rs` | `--audit`: archived transaction sets against the headers that name them |
| `negative.rs` | the single-mutation negative suite |
| `error.rs` | `VerifyError` - one deterministic variant per way verification can fail |
| `archive.rs` | history-archive access: checkpoint arithmetic, url construction, capped http get and gunzip, frame splitting |
| `history.rs` | decoders for the archive wrappers the light client never sees, preserving raw byte spans |
| `network.rs` | passphrases, `network_id = sha256(passphrase)`, and archive base urls, pinned per network |
| `fixture.rs` | frozen test vectors: load, save, decode |
| `report.rs` | terminal output, deliberately dependency-free |
| `rawdump.rs` | field-by-field walk of each raw item for `--raw`. presentation only |
| `strkey.rs` | `G…` account-id encoding so validators are named the way operators name them. presentation only |
| `lib.rs` | module declarations, so the crate is usable as a library too |

### `tools/` - separate workspace member, not a dependency of the binary

| file | what it does |
|---|---|
| `crosscheck.rs` | the independent implementation behind `chain-check`, sharing no code and using `ring` |
| `sync.rs` | `verify-sync`: diff or regenerate a vendored copy of the verifier's sources at `--target` |
| `main.rs` | the task runner's cli |

### `core-oracle/` - stellar-core, wrapped

| file | what it does |
|---|---|
| `oracle.cpp` | stellar-core's quorum predicates behind a line protocol on stdin/stdout |
| `stubs.cpp` | stands in for everything stellar-core links that the predicate does not need |
| `Dockerfile`, `build-oracle.sh` | build it against a real stellar-core tree |
| `oracle-docker` | wrapper so `CORE_ORACLE` can point at the container |

## what it does not tell you

a passing run says a quorum of your trust root signed this ledger. safety also assumes quorum intersection
among well-behaved nodes, which no light client can check for itself, and that you are intertwined with
the network under the trust root you chose. that is an assumption, not a result.

## license

Copyright 2026 Amanda Gonsalves. Licensed under the [Apache License 2.0](LICENSE).
