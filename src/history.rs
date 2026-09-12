use std::io::Cursor;

use crate::error::{Error, Result};
use stellar_xdr::{
    GeneralizedTransactionSet, Hash, LedgerHeader, Limited, Limits, PublicKey, ReadXdr,
    ScpQuorumSet, ScpStatement, ScpStatementType, Signature, TransactionResultPair, TransactionSet,
};

pub const SCP_ST_PREPARE: i32 = 0;
pub const SCP_ST_CONFIRM: i32 = 1;
pub const SCP_ST_EXTERNALIZE: i32 = 2;
pub const SCP_ST_NOMINATE: i32 = 3;

pub fn statement_type_name(kind: i32) -> &'static str {
    match kind {
        SCP_ST_PREPARE => "PREPARE",
        SCP_ST_CONFIRM => "CONFIRM",
        SCP_ST_EXTERNALIZE => "EXTERNALIZE",
        SCP_ST_NOMINATE => "NOMINATE",
        _ => "UNKNOWN",
    }
}

fn statement_type_code(kind: ScpStatementType) -> i32 {
    match kind {
        ScpStatementType::Prepare => SCP_ST_PREPARE,
        ScpStatementType::Confirm => SCP_ST_CONFIRM,
        ScpStatementType::Externalize => SCP_ST_EXTERNALIZE,
        ScpStatementType::Nominate => SCP_ST_NOMINATE,
    }
}

type Reader<'a> = Limited<Cursor<&'a [u8]>>;

fn reader(bytes: &[u8]) -> Reader<'_> {
    Limited::new(Cursor::new(bytes), Limits::none())
}

fn position(reader: &Reader<'_>) -> usize {
    reader.inner.position() as usize
}

fn span(record: &[u8], start: usize, end: usize) -> Result<Vec<u8>> {
    record
        .get(start..end)
        .map(<[u8]>::to_vec)
        .ok_or(Error::ByteSpanOutsideRecord { start, end })
}

fn node_id_bytes(key: &PublicKey) -> [u8; 32] {
    let PublicKey::PublicKeyTypeEd25519(bytes) = key;

    bytes.0
}

#[derive(Clone, Debug)]
pub struct ArchivedEnvelope {
    pub node_id: [u8; 32],
    pub slot_index: u64,
    pub statement_type: i32,
    pub statement_xdr: Vec<u8>,
    pub signature: Vec<u8>,
    pub envelope_xdr: Vec<u8>,
}

impl ArchivedEnvelope {
    pub fn is_externalize(&self) -> bool {
        self.statement_type == SCP_ST_EXTERNALIZE
    }
}

#[derive(Clone, Debug)]
pub struct ScpHistoryEntry {
    pub ledger_seq: u32,
    pub quorum_sets_xdr: Vec<Vec<u8>>,
    pub envelopes: Vec<ArchivedEnvelope>,
}

pub fn read_scp_history_entry(record: &[u8]) -> Result<ScpHistoryEntry> {
    let mut entry = reader(record);

    match i32::read_xdr(&mut entry)
        .map_err(|error| Error::decoding("SCPHistoryEntry discriminant", error))?
    {
        0 => {}

        other => return Err(Error::UnsupportedHistoryVersion { version: other }),
    }

    let quorum_set_count =
        u32::read_xdr(&mut entry).map_err(|error| Error::decoding("quorum set count", error))?;
    let mut quorum_sets_xdr = Vec::with_capacity(quorum_set_count as usize);

    for index in 0..quorum_set_count {
        let start = position(&entry);

        ScpQuorumSet::read_xdr(&mut entry)
            .map_err(|error| Error::decoding(format!("quorum set {index}"), error))?;
        quorum_sets_xdr.push(span(record, start, position(&entry))?);
    }

    let ledger_seq =
        u32::read_xdr(&mut entry).map_err(|error| Error::decoding("ledgerSeq", error))?;
    let n_envelopes =
        u32::read_xdr(&mut entry).map_err(|error| Error::decoding("envelope count", error))?;
    let mut envelopes = Vec::with_capacity(n_envelopes as usize);

    for index in 0..n_envelopes {
        let envelope_start = position(&entry);
        let statement = ScpStatement::read_xdr(&mut entry)
            .map_err(|error| Error::decoding(format!("statement of envelope {index}"), error))?;
        let statement_end = position(&entry);
        let signature = Signature::read_xdr(&mut entry)
            .map_err(|error| Error::decoding(format!("signature of envelope {index}"), error))?;

        envelopes.push(ArchivedEnvelope {
            node_id: node_id_bytes(&statement.node_id.0),
            slot_index: statement.slot_index,
            statement_type: statement_type_code(statement.pledges.discriminant()),
            statement_xdr: span(record, envelope_start, statement_end)?,
            signature: signature.0.into(),
            envelope_xdr: span(record, envelope_start, position(&entry))?,
        });
    }

    Ok(ScpHistoryEntry {
        ledger_seq,
        quorum_sets_xdr,
        envelopes,
    })
}

#[derive(Clone, Debug)]
pub struct HeaderHistoryEntry {
    pub recorded_hash: [u8; 32],
    pub ledger_seq: u32,
    pub header_xdr: Vec<u8>,
}

pub fn read_header_history_entry(record: &[u8]) -> Result<HeaderHistoryEntry> {
    let mut entry = reader(record);
    let recorded_hash = Hash::read_xdr(&mut entry)
        .map_err(|error| Error::decoding("recorded ledger hash", error))?;
    let start = position(&entry);
    let header = LedgerHeader::read_xdr(&mut entry)
        .map_err(|error| Error::decoding("ledger header", error))?;

    Ok(HeaderHistoryEntry {
        recorded_hash: recorded_hash.0,
        ledger_seq: header.ledger_seq,
        header_xdr: span(record, start, position(&entry))?,
    })
}

#[derive(Clone, Debug)]
pub struct TxSetRecord {
    pub ledger_seq: u32,
    pub generalized_xdr: Option<Vec<u8>>,
}

pub fn read_tx_history_entry(record: &[u8]) -> Result<TxSetRecord> {
    let mut entry = reader(record);
    let ledger_seq =
        u32::read_xdr(&mut entry).map_err(|error| Error::decoding("ledgerSeq", error))?;
    let legacy = TransactionSet::read_xdr(&mut entry)
        .map_err(|error| Error::decoding("legacy transaction set", error))?;

    if !legacy.txs.is_empty() {
        return Ok(TxSetRecord {
            ledger_seq,
            generalized_xdr: None,
        });
    }

    let generalized_xdr = match i32::read_xdr(&mut entry)
        .map_err(|error| Error::decoding("TransactionHistoryEntry ext", error))?
    {
        0 => None,
        1 => {
            let start = position(&entry);

            GeneralizedTransactionSet::read_xdr(&mut entry)
                .map_err(|error| Error::decoding("generalized transaction set", error))?;

            Some(span(record, start, position(&entry))?)
        }

        other => return Err(Error::UnsupportedTransactionHistoryExt { ext: other }),
    };

    Ok(TxSetRecord {
        ledger_seq,
        generalized_xdr,
    })
}

#[derive(Clone, Debug)]
pub struct ResultRecord {
    pub ledger_seq: u32,
    pub result_pairs: Vec<Vec<u8>>,
}

pub fn read_result_record(record: &[u8]) -> Result<ResultRecord> {
    let mut result = reader(record);
    let ledger_seq =
        u32::read_xdr(&mut result).map_err(|error| Error::decoding("ledgerSeq", error))?;
    let n =
        u32::read_xdr(&mut result).map_err(|error| Error::decoding("result pair count", error))?;
    let mut result_pairs = Vec::with_capacity(n as usize);

    for index in 0..n {
        let start = position(&result);

        TransactionResultPair::read_xdr(&mut result)
            .map_err(|error| Error::decoding(format!("result pair {index}"), error))?;
        result_pairs.push(span(record, start, position(&result))?);
    }

    Ok(ResultRecord {
        ledger_seq,
        result_pairs,
    })
}
