# core-oracle

a differential oracle: stellar-core's own quorum predicates, wrapped in a line protocol so
`tests/core_differential.rs` can check our port against them case for case.

## what it exposes

three functions, straight out of a real stellar-core tree, no reimplementation:

- `LocalNode::isQuorum`
- `LocalNode::isQuorumSlice`
- `isQuorumSetSane`

the test writes cases on stdin and reads verdicts off stdout. if our fixed point and stellar-core
ever disagree on the same input, the test fails.

## build and run

```sh
docker build -t scp-core-oracle core-oracle/
CORE_ORACLE=core-oracle/oracle-docker cargo test --release --test core_differential
```

`oracle-docker` is a one-line wrapper around `docker run --rm -i scp-core-oracle`. point `CORE_ORACLE`
at any executable that speaks the protocol if you'd rather build it another way.

the differential test **skips with a message** when `CORE_ORACLE` is unset, so ci pays nothing for it.

## what's in the build

`Dockerfile` clones stellar-core at `CORE_TAG` (currently `v27.1.0`), runs `./autogen.sh` and
`./configure --disable-tests`, then hands off to `build-oracle.sh`.

`build-oracle.sh` compiles `oracle.cpp` and `stubs.cpp` and links them against stellar-core's own
object files: `src/scp/*.o`, `src/crypto/*.o`, `src/util/*.o`, plus asio, jsoncpp, crc16, siphash and
spdlog. the quorum code is the real thing, compiled from the tree.

## what's stubbed, and why it aborts

`stubs.cpp` stands in for the rust bridge and the bits of stellar-core the quorum predicates never
touch. it does not fake them. `verify_ed25519_signature_dalek` prints a message and calls `abort()`:

> core-oracle: verify_ed25519_signature_dalek was called. This oracle links only the quorum
> predicates and stubs the rust bridge, so any answer would be meaningless.

that's deliberate. an oracle that quietly returned `true` for a stubbed signature check would turn a
missing dependency into a passing test, which is the worst possible failure for a tool whose whole job
is telling you when two implementations disagree.

## what agreement proves, and what it doesn't

**proves:** our port of the quorum predicates and stellar-core's originals reach the same answer on the
same input, over 2,000 generated cases of up to 8 nodes with nested quorum sets.

**does not prove:** anything about signature verification, which is stubbed out here. and it does not
prove either implementation matches the whitepaper. `tests/whitepaper.rs` covers that separately, on
small federations built by hand.
