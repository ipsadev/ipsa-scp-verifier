use ipsa_scp_verifier::archive::*;

#[test]
fn checkpoints_end_at_the_boundary() {
    assert_eq!(checkpoint_for(0), 63);
    assert_eq!(checkpoint_for(63), 63);
    assert_eq!(checkpoint_for(64), 127);

    assert_eq!(checkpoint_for(63907880), 63907903);
}

#[test]
fn archive_paths_are_nibble_sharded() {
    assert_eq!(
        url("https://x", "scp", 63907903),
        "https://x/scp/03/cf/28/scp-03cf283f.xdr.gz"
    );
}

#[test]
fn frames_split_on_the_length_prefix() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(0x8000_0003u32).to_be_bytes());
    buf.extend_from_slice(b"abc");
    buf.extend_from_slice(&(0x8000_0001u32).to_be_bytes());
    buf.extend_from_slice(b"z");
    assert_eq!(frames(&buf).unwrap(), vec![&b"abc"[..], &b"z"[..]]);
}

#[test]
fn a_frame_running_past_the_end_is_an_error() {
    let mut buf = (0x8000_0010u32).to_be_bytes().to_vec();
    buf.extend_from_slice(b"short");
    assert!(frames(&buf).is_err());
}

#[test]
fn the_last_ledger_sequence_has_a_checkpoint_and_no_successor() {
    assert_eq!(checkpoint_for(u32::MAX), u32::MAX);
    assert_eq!(checkpoint_for(u32::MAX - 64), u32::MAX - 64);
    assert_eq!(next_checkpoint(u32::MAX), None);
    assert_eq!(next_checkpoint(63), Some(127));
}

#[test]
fn gunzip_refuses_output_past_its_limit() {
    use std::io::Write;

    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());

    encoder.write_all(&[0u8; 4096]).unwrap();
    let gzipped = encoder.finish().unwrap();

    assert_eq!(gunzip(&gzipped, 4096).unwrap().len(), 4096);
    assert!(gunzip(&gzipped, 4095).is_err());
}
