use ipsa_scp_verifier::fixture::Fixture;
use ipsa_scp_verifier::history::*;
use ipsa_scp_verifier::scp::envelope::Envelope;

fn fixture(name: &str) -> Fixture {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    Fixture::load(&path).expect("fixture loads")
}

#[test]
fn statement_type_names_cover_the_union() {
    assert_eq!(statement_type_name(SCP_ST_PREPARE), "PREPARE");
    assert_eq!(statement_type_name(SCP_ST_CONFIRM), "CONFIRM");
    assert_eq!(statement_type_name(SCP_ST_EXTERNALIZE), "EXTERNALIZE");
    assert_eq!(statement_type_name(SCP_ST_NOMINATE), "NOMINATE");
    assert_eq!(statement_type_name(42), "UNKNOWN");
}

#[test]
fn a_truncated_record_is_refused() {
    assert!(read_scp_history_entry(&[0, 0, 0, 0]).is_err());
    assert!(read_header_history_entry(&[0u8; 8]).is_err());
    assert!(read_tx_history_entry(&[0u8; 4]).is_err());
}

#[test]
fn an_unsupported_scp_history_version_is_refused() {
    let mut raw = 1i32.to_be_bytes().to_vec();
    raw.extend_from_slice(&[0u8; 8]);
    assert!(read_scp_history_entry(&raw).is_err());
}

#[test]
fn envelope_spans_round_trip_through_a_synthesised_entry() {
    let f = fixture("testnet-4160279.json");
    let (input, _) = f.to_input().expect("decodes");

    let mut record = 0i32.to_be_bytes().to_vec();
    record.extend_from_slice(&(input.quorum_sets_xdr.len() as u32).to_be_bytes());
    for q in &input.quorum_sets_xdr {
        record.extend_from_slice(q);
    }
    record.extend_from_slice(&(input.slot as u32).to_be_bytes());
    record.extend_from_slice(&(input.envelopes_xdr.len() as u32).to_be_bytes());
    for e in &input.envelopes_xdr {
        record.extend_from_slice(e);
    }

    let entry = read_scp_history_entry(&record).expect("the synthesised entry parses");

    assert_eq!(entry.ledger_seq as u64, input.slot);
    assert_eq!(entry.quorum_sets_xdr, input.quorum_sets_xdr);
    assert_eq!(entry.envelopes.len(), input.envelopes_xdr.len());

    for (archived, raw) in entry.envelopes.iter().zip(input.envelopes_xdr.iter()) {
        let strict = Envelope::decode(raw).expect("strict decoder accepts");

        assert!(archived.is_externalize());
        assert_eq!(archived.envelope_xdr, *raw, "envelope span");
        assert_eq!(
            archived.statement_xdr, strict.statement_bytes,
            "signed statement span disagrees with the strict decoder"
        );
        assert_eq!(archived.node_id, strict.node_id);
        assert_eq!(archived.slot_index, strict.slot_index);
        assert_eq!(archived.signature, strict.signature.to_vec());
    }
}
