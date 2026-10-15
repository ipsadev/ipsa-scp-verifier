use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Result},
    steps::HeaderInput,
};

#[derive(Debug, Clone)]
pub struct NextSlot {
    pub envelopes_xdr: Vec<Vec<u8>>,
    pub quorum_sets_xdr: Vec<Vec<u8>>,
    pub tx_set_xdr: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fixture {
    #[serde(default)]
    pub network: String,
    pub ledger_seq: u64,
    pub network_id: String,
    pub ledger_hash: String,
    pub close_time: u64,
    pub tx_set_result_hash: String,
    #[serde(default)]
    pub bucket_list_hash: String,
    pub ledger_header_xdr: String,
    pub quorum_sets_xdr: Vec<String>,
    pub envelopes_xdr: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub next_envelopes_xdr: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub next_tx_set_xdr: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub next_quorum_sets_xdr: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_pairs_xdr: Option<Vec<String>>,
}

impl Fixture {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).map_err(|error| Error::FixtureRead {
            path: path.display().to_string(),
            detail: error.to_string(),
        })?;

        serde_json::from_str(&raw).map_err(|error| Error::FixtureParse {
            path: path.display().to_string(),
            detail: error.to_string(),
        })
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|error| Error::FileCreate {
                path: dir.display().to_string(),
                detail: error.to_string(),
            })?;
        }

        let json = serde_json::to_string_pretty(self).map_err(|error| Error::FileWrite {
            path: path.display().to_string(),
            detail: error.to_string(),
        })?;

        std::fs::write(path, json).map_err(|error| Error::FileWrite {
            path: path.display().to_string(),
            detail: error.to_string(),
        })
    }

    pub fn to_input(&self) -> Result<(HeaderInput, Option<NextSlot>)> {
        let input = HeaderInput {
            slot: self.ledger_seq,
            network_id: unhex32(&self.network_id)?,
            ledger_header_xdr: unhex(&self.ledger_header_xdr)?,
            envelopes_xdr: self
                .envelopes_xdr
                .iter()
                .map(|hexed| unhex(hexed))
                .collect::<Result<_>>()?,
            quorum_sets_xdr: self
                .quorum_sets_xdr
                .iter()
                .map(|hexed| unhex(hexed))
                .collect::<Result<_>>()?,
            result_pairs_xdr: self
                .result_pairs_xdr
                .iter()
                .flatten()
                .map(|hexed| unhex(hexed))
                .collect::<Result<_>>()?,
            recorded_ledger_hash: Some(unhex32(&self.ledger_hash)?),
            trusted_previous_hash: None,
        };

        let next = if self.next_envelopes_xdr.is_empty() || self.next_tx_set_xdr.is_empty() {
            None
        } else {
            Some(NextSlot {
                envelopes_xdr: self
                    .next_envelopes_xdr
                    .iter()
                    .map(|hexed| unhex(hexed))
                    .collect::<Result<_>>()?,
                quorum_sets_xdr: if self.next_quorum_sets_xdr.is_empty() {
                    input.quorum_sets_xdr.clone()
                } else {
                    self.next_quorum_sets_xdr
                        .iter()
                        .map(|hexed| unhex(hexed))
                        .collect::<Result<_>>()?
                },
                tx_set_xdr: unhex(&self.next_tx_set_xdr)?,
            })
        };

        Ok((input, next))
    }
}

pub fn unhex(hexed: &str) -> Result<Vec<u8>> {
    hex::decode(hexed).map_err(|error| Error::HexDecode {
        len: hexed.len(),
        detail: error.to_string(),
    })
}

pub fn unhex32(hexed: &str) -> Result<[u8; 32]> {
    let bytes = unhex(hexed)?;

    bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::HexLength { got: bytes.len() })
}
