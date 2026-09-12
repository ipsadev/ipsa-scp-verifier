# scp-verifier

independently verify stellar scp consensus for a single ledger, step by step, from the public history archives.

## the steps

- **fetch the evidence** - scp messages, ledger header and quorum sets for ledger N, from the public history archives
- **check the signatures** - each envelope's ed25519 signature over `networkID ‖ xdr(ENVELOPE_TYPE_SCP) ‖ raw SCPStatement`
- **check the statements** - all `EXTERNALIZE`, right slot, no node appearing twice
- **check the quorum sets** - every signer's quorum set preimage hashes to the `commitQuorumSetHash` it signed
- **find the quorum** - group signers by the value they pledged, then run stellar-core's `isQuorum` against the trust root
- **check it's one value** - byte-for-byte across the group, ballot counters ignored
- **tie it to the ledger** - that value is the header's `scpValue`, and `sha256(header)` is the ledger hash
- **tie it to the next slot** - slot N+1's tx set hashes to what N+1 externalized, and names ledger N as its predecessor
- **check the results** - the archived result pairs hash to `header.txSetResultHash`


## testing

`tests/quorum_oracle.rs` throws 20,000 random federations at it, up to 8 nodes with nested quorum sets,
and checks `is_quorum` against an exhaustive search over every closed subset, and `is_quorum_slice`
against a dumb counting version written separately in the same file. if the fixed point and brute force
ever disagree, one of them is wrong. runs every time, takes a fraction of a second.

then `tests/core_differential.rs`, which is the one that actually matters. 2,000 generated cases run
through stellar-core's own code - compiled out of a real stellar-core tree.

getting stellar-core to build in isolation is the annoying part, and that's what `core-oracle/` is for.
`oracle.cpp` pulls the quorum code out and puts a line protocol in front of it; `stubs.cpp` fills in
everything else stellar-core wants to link but the predicate never touches. the test spawns it, pipes
cases in on stdin, reads verdicts back off stdout.

`tools/src/crosscheck.rs` does the same trick at the other end - verifies a whole ledger a second time
through a completely separate implementation, different xdr reader, `ring` instead of `sha2` +
`ed25519-dalek`.

`tests/differential.rs` covers the decoder: decode the fixtures with our hand-rolled reader and with
`stellar-xdr`, assert they match. that includes the byte spans, which matters more than it sounds -
signatures cover exact bytes, so an off-by-one in a span breaks every signature check without the
output ever looking wrong.

and `--negative` flips one field at a time to confirm each step actually fails when it should.

## code map

### `src/` - the verifier

| file | what it does |
|---|---|
| `main.rs` | the `scp-verify` binary: cli parsing, input assembly, and the whole printed report |
| `steps.rs` | the verification steps, one function per check, plus `verify_header` |
| `sweep.rs` | range mode: fetch per checkpoint, merge envelopes across archives by node, classify every ledger instead of stopping at the first failure |
| `negative.rs` | the single-mutation negative suite |
| `error.rs` | `VerifyError` - one deterministic variant per way verification can fail |
| `archive.rs` | history-archive access: checkpoint arithmetic, url construction, http get, gunzip, frame splitting |
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
| `sync.rs` | the two vendoring checks: `vendor-sync` against the contract, `verify-sync` against the ipsa copy |
| `main.rs` | the task runner's cli |

### `core-oracle/` - stellar-core, wrapped

| file | what it does |
|---|---|
| `oracle.cpp` | stellar-core's quorum predicates behind a line protocol on stdin/stdout |
| `stubs.cpp` | stands in for everything stellar-core links that the predicate does not need |
| `Dockerfile`, `build-oracle.sh` | build it against a real stellar-core tree |
| `oracle-docker` | wrapper so `CORE_ORACLE` can point at the container |
