use ipsa_scp_verifier::api::{self, Options, Request};
use ipsa_scp_verifier::error::Error;
use ipsa_scp_verifier::network::Network;

fn request(network: Option<&str>) -> Request {
    Request {
        ledger: 63907880,
        network: network.map(str::to_string),
        mutation: None,
        trust_root: None,
        trusted_previous: None,
    }
}

#[tokio::test]
async fn a_request_with_no_trust_root_anywhere_is_refused() {
    let outcome = api::verify(
        &request(None),
        &Options::for_network(Network::Mainnet, None),
    )
    .await;

    assert!(matches!(outcome, Err(Error::NoTrustRoot)));
}

#[tokio::test]
async fn a_configured_trust_root_is_not_lent_to_another_network() {
    let options = Options::for_network(Network::Mainnet, Some(vec![0u8; 16]));
    let outcome = api::verify(&request(Some("testnet")), &options).await;

    assert!(matches!(outcome, Err(Error::NoTrustRoot)));
}

#[tokio::test]
async fn a_trust_root_that_is_not_hex_is_refused_before_any_fetch() {
    let mut asked = request(None);

    asked.trust_root = Some("not hex".to_string());

    let outcome = api::verify(&asked, &Options::for_network(Network::Mainnet, None)).await;

    assert!(matches!(outcome, Err(Error::HexDecode { .. })));
}
