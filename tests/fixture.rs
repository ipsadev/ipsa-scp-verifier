use ipsa_scp_verifier::fixture::Fixture;

fn mainnet() -> Fixture {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/mainnet-63907880.json");

    Fixture::load(&path).expect("fixture loads")
}

#[test]
fn a_fixture_without_results_records_none() {
    let fixture = mainnet();
    let (input, _) = fixture.to_input().expect("decodes");

    assert!(fixture.result_pairs_xdr.is_none());
    assert!(input.result_pairs_xdr.is_empty());
}

#[test]
fn result_pairs_survive_a_round_trip() {
    let mut fixture = mainnet();

    fixture.result_pairs_xdr = Some(vec!["00010203".to_string(), "0a0b".to_string()]);

    let json = serde_json::to_string(&fixture).expect("serialises");
    let reloaded: Fixture = serde_json::from_str(&json).expect("parses");
    let (input, _) = reloaded.to_input().expect("decodes");

    assert_eq!(input.result_pairs_xdr, vec![vec![0, 1, 2, 3], vec![10, 11]]);
}

#[test]
fn an_empty_result_set_is_recorded_rather_than_dropped() {
    let mut fixture = mainnet();

    fixture.result_pairs_xdr = Some(Vec::new());

    let json = serde_json::to_string(&fixture).expect("serialises");

    assert!(json.contains("\"result_pairs_xdr\":[]"));
}
