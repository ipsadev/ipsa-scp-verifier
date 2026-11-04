use std::path::PathBuf;

use ipsa_scp_verifier::fixture::{unhex, Fixture};
use ipsa_scp_verifier::steps::{self, QuorumConfig};

fn fixture() -> Fixture {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "tests",
        "fixtures",
        "testnet-5541000-protocol-30.json",
    ]
    .iter()
    .collect();

    Fixture::load(&path).expect("fixture loads")
}

#[test]
fn verifies_a_protocol_30_ledger_with_a_millisecond_close_time() {
    let f = fixture();
    let (input, _) = f.to_input().expect("decodes");
    let config =
        QuorumConfig::from_xdr(&unhex(&f.quorum_sets_xdr[0]).unwrap()).expect("trust root is sane");

    let verified = steps::verify_header(&input, &config).expect("verifies");

    assert_eq!(verified.slot, 5_541_000);
    assert_eq!(verified.close_time, f.close_time);
    assert_eq!(
        verified.ledger_hash.to_vec(),
        unhex(&f.ledger_hash).unwrap()
    );
    assert_eq!(
        verified.tx_set_result_hash.to_vec(),
        unhex(&f.tx_set_result_hash).unwrap()
    );
}
