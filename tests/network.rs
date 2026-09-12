use ipsa_scp_verifier::network::*;

#[test]
fn network_ids_are_the_published_constants() {
    assert_eq!(
        hex::encode(Network::Mainnet.id()),
        "7ac33997544e3175d266bd022439b22cdb16508c01163f26e5cb2a3e1045a979"
    );
    assert_eq!(
        hex::encode(Network::Testnet.id()),
        "cee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd472"
    );
}

#[test]
fn parse_accepts_the_usual_aliases() {
    assert_eq!(Network::parse("public").unwrap(), Network::Mainnet);
    assert_eq!(Network::parse("TESTNET").unwrap(), Network::Testnet);
    assert!(Network::parse("futurenet").is_err());
}
