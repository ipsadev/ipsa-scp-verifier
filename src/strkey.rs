pub fn account_id(key: &[u8; 32]) -> String {
    stellar_strkey::ed25519::PublicKey(*key).to_string()
}
