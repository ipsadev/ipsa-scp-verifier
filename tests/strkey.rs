use ipsa_scp_verifier::strkey::*;

#[test]
fn encodes_the_sep23_reference_vector() {
    let raw =
        hex::decode("3f0c34bf93ad0d9971d04ccc90f705511c838aad9734a4a2fb0d7a03fc7fe89a").unwrap();
    let key: [u8; 32] = raw.try_into().unwrap();
    assert_eq!(
        account_id(&key),
        "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"
    );
}

#[test]
fn an_account_id_is_56_chars_starting_with_g() {
    let s = account_id(&[0u8; 32]);
    assert_eq!(s.len(), 56);
    assert!(s.starts_with('G'));
}

#[test]
fn the_encoding_round_trips_through_the_parser() {
    let key = [0x2au8; 32];
    let encoded = account_id(&key);
    let parsed: stellar_strkey::ed25519::PublicKey = encoded.parse().expect("parses back");
    assert_eq!(parsed.0, key);
}
