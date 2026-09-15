use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VerifyError {
    #[error("no SCP envelopes supplied")]
    NoEnvelopes,
    #[error("malformed {what} XDR: {detail}")]
    MalformedXdr { what: String, detail: String },
    #[error("statement is not EXTERNALIZE: {detail}")]
    NotExternalize { detail: String },
    #[error("statement fails the sanity rules: {detail}")]
    InsaneStatement { detail: String },
    #[error("envelope is for slot {found}, expected {expected}")]
    SlotMismatch { expected: u64, found: u64 },
    #[error("node {node_id} pledged an empty commit value")]
    EmptyCommitValue { node_id: String },
    #[error("node {node_id} signed twice (envelopes {first} and {second})")]
    DuplicateSigner {
        node_id: String,
        first: usize,
        second: usize,
    },
    #[error("node {node_id} is not a valid Ed25519 public key")]
    InvalidPublicKey { node_id: String },
    #[error("invalid Ed25519 signature from {node_id}")]
    InvalidSignature { node_id: String },
    #[error("no quorum-set preimage for {node_id} (commitQuorumSetHash {hash})")]
    QuorumSetPreimageMissing { node_id: String, hash: String },
    #[error("quorum set fails the sanity rules: {detail}")]
    InsaneQuorumSet { detail: String },
    #[error("the signature verifier failed: {detail}")]
    SignatureVerifierFailed { detail: String },
    #[error("the {signers} signers do not form a quorum for the configured trust root")]
    InsufficientQuorum { signers: usize },
    #[error("node {node_id} pledged a different commit value")]
    ConflictingValues { node_id: String },
    #[error("two different values are each backed by a quorum ({values} distinct values seen) - this is fork evidence, not a disagreement")]
    ForkedQuorums { values: usize },
    #[error(
        "the externalized value ({value_len} bytes) is not this header's scpValue \
         ({header_value_len} bytes)"
    )]
    ValueNotInHeader {
        value_len: usize,
        header_value_len: usize,
    },
    #[error("header is for ledger {found}, expected {expected}")]
    LedgerSeqMismatch { expected: u64, found: u64 },
    #[error("ledger hash mismatch: archive recorded {expected}, header hashes to {computed}")]
    LedgerHashMismatch { expected: String, computed: String },
    #[error("next slot's tx set hashes to {computed}, but its value names {expected}")]
    TxSetHashMismatch { expected: String, computed: String },
    #[error("next slot's tx set follows ledger {found}, not {expected}")]
    LedgerNotPrevious { expected: String, found: String },
    #[error(
        "header names predecessor {found}, but the trusted ledger before it hashes to {expected}"
    )]
    PreviousLedgerMismatch { expected: String, found: String },
    #[error(
        "the {pairs} archived result pair(s) hash to {computed}, but the header committed to \
         txSetResultHash {expected}"
    )]
    ResultSetMismatch {
        pairs: usize,
        expected: String,
        computed: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Verified,
    VerifiedUnanchored,
    Contradicted,
    Insufficient,
}

impl Error {
    pub fn decoding(field: impl Into<String>, detail: impl ToString) -> Self {
        Self::Decode {
            field: field.into(),
            detail: detail.to_string(),
        }
    }
}

impl VerifyError {
    pub fn verdict(&self) -> Verdict {
        match self {
            Self::NoEnvelopes
            | Self::QuorumSetPreimageMissing { .. }
            | Self::InsufficientQuorum { .. } => Verdict::Insufficient,
            _ => Verdict::Contradicted,
        }
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Verify(#[from] VerifyError),
    #[error(transparent)]
    Scp(#[from] stellar_consensus_verifier::error::ScpError),
    #[error("GET {url} returned HTTP {status}")]
    ArchiveStatus { url: String, status: u32 },
    #[error("GET {url}: {detail}")]
    ArchiveRequest { url: String, detail: String },
    #[error("reading the body of {url}: {detail}")]
    ArchiveBody { url: String, detail: String },
    #[error("gunzipping {url}: {detail}")]
    ArchiveGunzip { url: String, detail: String },
    #[error("parsing {url}: {detail}")]
    ArchiveJson { url: String, detail: String },
    #[error("{url} carries no currentLedger")]
    ArchiveNoCurrentLedger { url: String },
    #[error("no archive served SCP messages for checkpoint {checkpoint}")]
    NoArchiveForCheckpoint { checkpoint: u32 },
    #[error("truncated frame header at byte {offset}")]
    FrameTruncated { offset: usize },
    #[error("the frame at byte {offset} claims {len} bytes, past the end of the file")]
    FrameOverruns { offset: usize, len: usize },
    #[error("decoding {field}: {detail}")]
    Decode { field: String, detail: String },
    #[error("byte span {start}..{end} is outside the record")]
    ByteSpanOutsideRecord { start: usize, end: usize },
    #[error("unsupported SCPHistoryEntry version {version}")]
    UnsupportedHistoryVersion { version: i32 },
    #[error("unsupported TransactionHistoryEntry ext {ext}")]
    UnsupportedTransactionHistoryExt { ext: i32 },
    #[error("no SCP messages archived for ledger {ledger}")]
    NoScpMessages { ledger: u32 },
    #[error("no ledger header archived for ledger {ledger}")]
    NoLedgerHeader { ledger: u32 },
    #[error("no tx set archived for ledger {ledger}")]
    NoTxSet { ledger: u32 },
    #[error("the ledger carries no quorum sets")]
    NoQuorumSets,
    #[error("no quorum-set preimages to derive a trust root from")]
    NoTrustRoot,
    #[error("reading fixture {path}: {detail}")]
    FixtureRead { path: String, detail: String },
    #[error("parsing fixture {path}: {detail}")]
    FixtureParse { path: String, detail: String },
    #[error("creating {path}: {detail}")]
    FileCreate { path: String, detail: String },
    #[error("writing {path}: {detail}")]
    FileWrite { path: String, detail: String },
    #[error("decoding {len} hex characters: {detail}")]
    HexDecode { len: usize, detail: String },
    #[error("expected 32 bytes, got {got}")]
    HexLength { got: usize },
    #[error("unknown network {name:?}, expected mainnet or testnet")]
    UnknownNetwork { name: String },
    #[error("pass --ledger <sequence_number> or --fixture <path>")]
    NoLedgerSelected,
    #[error("--range wants FROM..TO, got {specification:?}")]
    RangeMalformed { specification: String },
    #[error("--range {end} is not a ledger sequence: {detail}")]
    RangeBound { end: String, detail: String },
    #[error("--range needs from <= to, got {from}..{to}")]
    RangeInverted { from: u32, to: u32 },
    #[error("--trusted-previous is not a ledger hash: {detail}")]
    TrustedPrevious { detail: String },
    #[error("the decoder rejected an archived envelope from {node}: {detail}")]
    DecoderRejectedEnvelope { node: String, detail: String },
    #[error("decoder disagreement on {field} for {node}")]
    DecoderDisagreement { field: String, node: String },
    #[error("binding {address}: {detail}")]
    ServeBind { address: String, detail: String },
    #[error("reading the request body: {detail}")]
    ServeReadBody { detail: String },
    #[error("the request body is not UTF-8")]
    ServeBodyNotUtf8,
    #[error("parsing the request body: {detail}")]
    ServeParseBody { detail: String },
    #[error("writing the response: {detail}")]
    ServeWriteResponse { detail: String },
    #[error("serialising the response: {detail}")]
    ServeSerialize { detail: String },
    #[error("writing a jsonl row: {detail}")]
    JsonlWrite { detail: String },
    #[error(
        "this server is pinned to {pinned} archives, so it cannot serve {asked}. \
         Start it without --archive, or point --network at {asked}"
    )]
    ArchivesPinned { pinned: String, asked: String },
    #[error("{detail}")]
    Mutation { detail: String },
    #[error("an archived EXTERNALIZE from {node} does not decode: {detail}")]
    ArchivedEnvelopeUndecodable { node: String, detail: String },
    #[error("no archive served SCP for checkpoint {checkpoint} ({detail})")]
    NoArchiveServedCheckpoint { checkpoint: u32, detail: String },
    #[error("{count} disagreement(s); every other outcome is an archive property")]
    Disagreements { count: usize },
    #[error(
        "ledger {ledger} is not archived yet: it needs checkpoint {checkpoint}, and this archive \
         is only published through ledger {latest}. Checkpoints close every {frequency} ledgers \
         and are uploaded a few minutes later, so try again in a few minutes or pick a ledger at \
         or below {latest}."
    )]
    LedgerNotArchivedYet {
        ledger: u32,
        checkpoint: u32,
        latest: u32,
        frequency: u32,
    },
    #[error("ledger {ledger} has a legacy tx set; the binding needs a generalized one")]
    LegacyTxSet { ledger: u32 },
    #[error(
        "decoder disagreement on the signed statement range for {node}: \
         archive says {archive} bytes, decoder says {decoder}"
    )]
    DecoderStatementRange {
        node: String,
        archive: usize,
        decoder: usize,
    },
    #[error("{failed}/{total} negative cases did not fail closed")]
    NegativeCasesPassed { failed: usize, total: usize },
}
