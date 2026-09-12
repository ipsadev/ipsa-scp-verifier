use std::path::PathBuf;

use ipsa_scp_verifier::error::VerifyError;
use ipsa_scp_verifier::fixture::Fixture;
use ipsa_scp_verifier::negative::{self, Outcome};
use ipsa_scp_verifier::steps::{self, QuorumConfig};

fn fixture(name: &str) -> Fixture {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "fixtures", name]
        .iter()
        .collect();
    Fixture::load(&path).expect("fixture loads")
}

fn trust_root(f: &Fixture) -> QuorumConfig {
    let raw = ipsa_scp_verifier::fixture::unhex(&f.quorum_sets_xdr[0]).expect("hex");
    QuorumConfig::from_xdr(&raw).expect("trust root is sane")
}

#[test]
fn verifies_mainnet_63907880() {
    let f = fixture("mainnet-63907880.json");
    let (input, _) = f.to_input().expect("decodes");
    let config = trust_root(&f);

    assert_eq!(input.envelopes_xdr.len(), 21, "21 externalize envelopes");
    assert_eq!(input.quorum_sets_xdr.len(), 1, "one quorum-set preimage");

    let v = steps::verify_header(&input, &config).expect("verifies");
    assert_eq!(v.slot, 63907880);
    assert_eq!(hex::encode(v.ledger_hash), f.ledger_hash);
    assert_eq!(v.close_time, f.close_time);
    assert_eq!(hex::encode(v.tx_set_result_hash), f.tx_set_result_hash);
}

#[test]
fn mainnet_trust_root_is_five_of_seven_nested() {
    let f = fixture("mainnet-63907880.json");
    let config = trust_root(&f);
    assert_eq!(config.local.threshold, 5);
    assert!(config.local.validators.is_empty());
    assert_eq!(config.local.inner_sets.len(), 7);
    for inner in &config.local.inner_sets {
        assert_eq!(inner.threshold, 2);
        assert_eq!(inner.validators.len(), 3);
    }
}

#[test]
fn the_agreed_value_appears_verbatim_in_the_header() {
    let f = fixture("mainnet-63907880.json");
    let (input, _) = f.to_input().expect("decodes");
    let envelopes: Vec<_> = input
        .envelopes_xdr
        .iter()
        .map(|raw| steps::validate_externalize(raw, input.slot).expect("externalize"))
        .collect();
    let value = steps::verify_externalized_value(&envelopes).expect("one value");
    assert!(
        input
            .ledger_header_xdr
            .windows(value.len())
            .any(|w| w == value.as_slice()),
        "the externalized StellarValue must appear inside the LedgerHeader"
    );
}

#[test]
fn verifies_testnet_4160279_including_the_next_slot_binding() {
    let f = fixture("testnet-4160279.json");
    let (input, next) = f.to_input().expect("decodes");
    let config = trust_root(&f);

    let v = steps::verify_header(&input, &config).expect("verifies");
    assert_eq!(hex::encode(v.ledger_hash), f.ledger_hash);

    let next = next.expect("this vector carries slot N+1");
    let next_envelopes: Vec<_> = next
        .envelopes_xdr
        .iter()
        .map(|raw| steps::validate_externalize(raw, input.slot + 1).expect("externalize"))
        .collect();
    let preimages = steps::index_quorum_sets(&next.quorum_sets_xdr).expect("preimages");
    let signers = steps::verify_quorum_set_hashes(&next_envelopes, &preimages).expect("bound");
    steps::verify_quorum(&config, &signers).expect("next slot is a quorum");
    let next_value = steps::verify_externalized_value(&next_envelopes).expect("one value");

    steps::verify_next_slot_binding(&next_value, &next.tx_set_xdr, &v.ledger_hash)
        .expect("the next slot's tx set follows this ledger");
}

#[test]
fn a_tampered_tx_set_breaks_the_next_slot_binding() {
    let f = fixture("testnet-4160279.json");
    let (input, next) = f.to_input().expect("decodes");
    let config = trust_root(&f);
    let v = steps::verify_header(&input, &config).expect("verifies");

    let mut next = next.expect("carries slot N+1");
    *next.tx_set_xdr.last_mut().unwrap() ^= 0x01;

    let next_envelopes: Vec<_> = next
        .envelopes_xdr
        .iter()
        .map(|raw| steps::validate_externalize(raw, input.slot + 1).expect("externalize"))
        .collect();
    let next_value = steps::verify_externalized_value(&next_envelopes).expect("one value");

    assert!(matches!(
        steps::verify_next_slot_binding(&next_value, &next.tx_set_xdr, &v.ledger_hash),
        Err(VerifyError::TxSetHashMismatch { .. })
    ));
}

#[test]
fn the_negative_suite_fails_closed_on_mainnet() {
    let f = fixture("mainnet-63907880.json");
    let (input, _) = f.to_input().expect("decodes");
    let config = trust_root(&f);

    let cases = negative::run_suite(&input, &config, None);
    assert!(!cases.is_empty());
    for case in &cases {
        match &case.outcome {
            Outcome::Rejected(_) => {}
            Outcome::WrongError(msg) => panic!(
                "[{}] {}: expected {}, got {msg}",
                case.step, case.name, case.expected
            ),
            Outcome::Accepted => panic!(
                "[{}] {}: ACCEPTED, expected {}",
                case.step, case.name, case.expected
            ),
        }
    }
}

#[test]
fn the_negative_suite_fails_closed_on_testnet() {
    let f = fixture("testnet-4160279.json");
    let (input, next) = f.to_input().expect("decodes");
    let config = trust_root(&f);
    let next = next.expect("carries slot N+1");

    let cases = negative::run_suite(
        &input,
        &config,
        Some(negative::NextSlotEvidence {
            envelopes_xdr: &next.envelopes_xdr,
            tx_set_xdr: &next.tx_set_xdr,
        }),
    );

    for case in &cases {
        assert!(
            matches!(case.outcome, Outcome::Rejected(_)),
            "[{}] {} did not fail closed",
            case.step,
            case.name
        );
    }

    for expected in ["TxSetHashMismatch", "LedgerNotPrevious"] {
        assert!(
            cases.iter().any(|c| c.expected == expected),
            "the suite lost its {expected} case"
        );
    }
}

#[test]
fn fixtures_round_trip_through_json() {
    for name in ["mainnet-63907880.json", "testnet-4160279.json"] {
        let f = fixture(name);
        let json = serde_json::to_string(&f).expect("serialises");
        let back: Fixture = serde_json::from_str(&json).expect("deserialises");
        let (a, _) = f.to_input().expect("decodes");
        let (b, _) = back.to_input().expect("decodes");
        assert_eq!(a.ledger_header_xdr, b.ledger_header_xdr, "{name}");
        assert_eq!(a.envelopes_xdr, b.envelopes_xdr, "{name}");
        assert_eq!(a.quorum_sets_xdr, b.quorum_sets_xdr, "{name}");
    }
}
