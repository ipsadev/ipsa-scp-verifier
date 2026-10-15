# independent verification of Stellar SCP consensus, one ledger at a time

lints := "-D warnings -A clippy::manual_is_multiple_of -A clippy::too_many_arguments -A clippy::result_large_err"
ledger := "63907880"
mainnet_trust_root := `cat trust-roots/mainnet.hex`

default:
    @just --list

# everything CI runs, in CI's order
ci: fmt-check lint test audit

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

lint:
    cargo clippy --locked --workspace --all-targets -- {{lints}}

test:
    cargo test --locked --workspace

# hits the live network, so it is not part of ci
live ledger=ledger:
    cargo run --locked --release -- --ledger {{ledger}} --trust-root {{mainnet_trust_root}} --negative
    cargo run --locked -p tools -- chain-check --network mainnet --ledger {{ledger}} --trust-root {{mainnet_trust_root}}

# regenerate a consumer's vendored copy of this verifier
sync target:
    cargo run --locked -p tools -- verify-sync --write --target {{target}}

audit:
    cargo audit --file Cargo.lock

# what crates.io would receive, without sending it
package:
    cargo package --locked

clean:
    cargo clean
