use std::io::Cursor;

use ipsa_scp_verifier::fixture::Fixture;
use ipsa_scp_verifier::scp::envelope::Envelope;
use ipsa_scp_verifier::scp::ledger::LedgerHeader;
use ipsa_scp_verifier::scp::quorum::QuorumSet;

use stellar_xdr::{Limited, Limits, ReadXdr};

fn fixture(name: &str) -> Fixture {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    Fixture::load(&path).expect("fixture loads")
}

fn reader(bytes: &[u8]) -> Limited<Cursor<&[u8]>> {
    Limited::new(Cursor::new(bytes), Limits::none())
}

fn both_fixtures() -> Vec<Fixture> {
    vec![
        fixture("mainnet-63907880.json"),
        fixture("testnet-4160279.json"),
    ]
}

#[test]
fn envelopes_agree_with_stellar_xdr() {
    for f in both_fixtures() {
        let (input, _) = f.to_input().expect("decodes");
        assert!(!input.envelopes_xdr.is_empty());

        for raw in &input.envelopes_xdr {
            let ours = Envelope::decode(raw).expect("our decoder accepts");

            let mut r = reader(raw);
            let theirs = stellar_xdr::ScpEnvelope::read_xdr(&mut r).expect("stellar-xdr accepts");

            let stellar_xdr::PublicKey::PublicKeyTypeEd25519(key) = theirs.statement.node_id.0;
            assert_eq!(ours.node_id, key.0, "node id");
            assert_eq!(ours.slot_index, theirs.statement.slot_index, "slot index");

            let stellar_xdr::ScpStatementPledges::Externalize(ext) = &theirs.statement.pledges
            else {
                panic!("fixture envelope is not EXTERNALIZE");
            };
            assert_eq!(
                ours.externalize().unwrap().commit.counter,
                ext.commit.counter,
                "counter"
            );
            assert_eq!(
                ours.externalize().unwrap().highest_confirmed_ballot_counter,
                ext.n_h,
                "highest confirmed ballot counter"
            );
            assert_eq!(
                ours.externalize().unwrap().commit.value,
                ext.commit.value.0.to_vec(),
                "commit value"
            );
            assert_eq!(
                ours.externalize().unwrap().commit_quorum_set_hash,
                ext.commit_quorum_set_hash.0,
                "quorum set hash"
            );
            assert_eq!(
                ours.signature.to_vec(),
                theirs.signature.0.to_vec(),
                "signature"
            );
        }
    }
}

#[test]
fn the_signed_statement_span_agrees_with_stellar_xdr() {
    for f in both_fixtures() {
        let (input, _) = f.to_input().expect("decodes");

        for raw in &input.envelopes_xdr {
            let ours = Envelope::decode(raw).expect("our decoder accepts");

            let mut r = reader(raw);
            let start = r.inner.position() as usize;
            let _ = stellar_xdr::ScpStatement::read_xdr(&mut r).expect("statement decodes");
            let end = r.inner.position() as usize;

            assert_eq!(
                ours.statement_bytes,
                raw[start..end].to_vec(),
                "signed statement span disagrees"
            );
        }
    }
}

#[test]
fn ledger_headers_agree_with_stellar_xdr() {
    for f in both_fixtures() {
        let (input, _) = f.to_input().expect("decodes");
        let ours = LedgerHeader::decode(&input.ledger_header_xdr).expect("our decoder accepts");

        let mut r = reader(&input.ledger_header_xdr);
        let theirs = stellar_xdr::LedgerHeader::read_xdr(&mut r).expect("stellar-xdr accepts");

        assert_eq!(ours.ledger_seq, theirs.ledger_seq, "ledger seq");
        assert_eq!(ours.ledger_version, theirs.ledger_version, "ledger version");
        assert_eq!(
            ours.previous_ledger_hash, theirs.previous_ledger_hash.0,
            "previous ledger hash"
        );
        assert_eq!(
            ours.tx_set_hash, theirs.scp_value.tx_set_hash.0,
            "tx set hash"
        );
        assert_eq!(ours.close_time, theirs.scp_value.close_time.0, "close time");
        assert_eq!(
            ours.tx_set_result_hash, theirs.tx_set_result_hash.0,
            "tx set result hash"
        );
        assert_eq!(
            ours.bucket_list_hash, theirs.bucket_list_hash.0,
            "bucket list hash"
        );
    }
}

#[test]
fn the_scp_value_span_agrees_with_stellar_xdr() {
    for f in both_fixtures() {
        let (input, _) = f.to_input().expect("decodes");
        let ours = LedgerHeader::decode(&input.ledger_header_xdr).expect("decodes");

        let mut r = reader(&input.ledger_header_xdr);
        let _version = u32::read_xdr(&mut r).expect("version");
        let _prev = stellar_xdr::Hash::read_xdr(&mut r).expect("prev hash");
        let start = r.inner.position() as usize;
        let _value = stellar_xdr::StellarValue::read_xdr(&mut r).expect("stellar value");
        let end = r.inner.position() as usize;

        assert_eq!(
            ours.scp_value_bytes,
            input.ledger_header_xdr[start..end].to_vec(),
            "scp value span disagrees"
        );
    }
}

#[test]
fn quorum_sets_agree_with_stellar_xdr() {
    for f in both_fixtures() {
        let (input, _) = f.to_input().expect("decodes");
        assert!(!input.quorum_sets_xdr.is_empty());

        for raw in &input.quorum_sets_xdr {
            let ours = QuorumSet::decode(raw).expect("our decoder accepts");

            let mut r = reader(raw);
            let theirs = stellar_xdr::ScpQuorumSet::read_xdr(&mut r).expect("stellar-xdr accepts");

            assert_eq!(ours.threshold, theirs.threshold, "threshold");
            assert_eq!(ours.validators.len(), theirs.validators.len(), "validators");
            assert_eq!(ours.inner_sets.len(), theirs.inner_sets.len(), "inner sets");

            for (mine, theirs) in ours.validators.iter().zip(theirs.validators.iter()) {
                let stellar_xdr::PublicKey::PublicKeyTypeEd25519(key) = &theirs.0;
                assert_eq!(mine, &key.0, "validator key");
            }
        }
    }
}
