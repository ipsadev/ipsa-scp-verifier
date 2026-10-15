use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

use crate::archive;
use crate::evaluate::{self, NextSlot};
use crate::fixture;
use crate::network::Network;
use crate::steps::{HeaderInput, QuorumConfig};
use crate::sweep::{self, Checkpoint};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Request {
    pub ledger: u32,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub mutation: Option<String>,
    #[serde(default)]
    pub trust_root: Option<String>,
    #[serde(default)]
    pub trusted_previous: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Options {
    pub network: Network,
    pub archives: Vec<String>,
    pub archives_pinned: bool,
    pub trust_root_xdr: Option<Vec<u8>>,
}

impl Options {
    pub fn for_network(network: Network, trust_root_xdr: Option<Vec<u8>>) -> Self {
        Self {
            network,
            archives: vec![network.archive_base().to_string()],
            archives_pinned: false,
            trust_root_xdr,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Mutation {
    pub name: &'static str,
    pub step: &'static str,
}

pub fn mutations() -> Vec<Mutation> {
    evaluate::MUTATIONS
        .iter()
        .map(|(name, step)| Mutation { name, step })
        .collect()
}

type CacheKey = (Vec<String>, u32);

pub struct CheckpointCache {
    capacity: usize,
    entries: Mutex<VecDeque<(CacheKey, Arc<Checkpoint>)>>,
}

impl CheckpointCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(VecDeque::new()),
        }
    }

    fn get(&self, key: &CacheKey) -> Option<Arc<Checkpoint>> {
        let mut entries = self.entries.lock().ok()?;
        let position = entries.iter().position(|(cached, _)| cached == key)?;
        let entry = entries.remove(position)?;
        let checkpoint = Arc::clone(&entry.1);

        entries.push_back(entry);

        Some(checkpoint)
    }

    fn put(&self, key: CacheKey, checkpoint: Arc<Checkpoint>) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };

        entries.retain(|(cached, _)| *cached != key);
        entries.push_back((key, checkpoint));

        while entries.len() > self.capacity {
            entries.pop_front();
        }
    }
}

pub async fn verify(request: &Request, options: &Options) -> Result<evaluate::Report> {
    verify_with_cache(request, options, None).await
}

pub async fn verify_with_cache(
    request: &Request,
    options: &Options,
    cache: Option<&CheckpointCache>,
) -> Result<evaluate::Report> {
    let network = match request.network.as_deref() {
        Some(name) => Network::parse(name)?,
        None => options.network,
    };

    let archives = if network == options.network {
        options.archives.clone()
    } else if options.archives_pinned {
        return Err(Error::ArchivesPinned {
            pinned: options.network.label().to_string(),
            asked: network.label().to_string(),
        });
    } else {
        vec![network.archive_base().to_string()]
    };

    let trust_root_xdr = match (&request.trust_root, &options.trust_root_xdr) {
        (Some(hexed), _) => fixture::unhex(hexed)?,
        (None, Some(configured)) if network == options.network => configured.clone(),
        (None, _) => return Err(Error::NoTrustRoot),
    };
    let trusted_previous_hash = match &request.trusted_previous {
        Some(hexed) => Some(
            fixture::unhex32(hexed).map_err(|error| Error::TrustedPrevious {
                detail: error.to_string(),
            })?,
        ),
        None => None,
    };
    let mut config = QuorumConfig::from_xdr(&trust_root_xdr)?;
    let ledger = request.ledger;
    let sweep_opts = sweep::Options {
        network,
        archives,
        from: ledger,
        to: ledger,
        next_slot: true,
        results: false,
        trust_root_xdr: None,
        jsonl: None,
    };

    let checkpoint = archive::checkpoint_for(ledger);
    let key = (sweep_opts.archives.clone(), checkpoint);
    let loaded = match cache.and_then(|cache| cache.get(&key)) {
        Some(hit) => hit,
        None => {
            let fresh = Arc::new(sweep::load_checkpoint(checkpoint, &sweep_opts, true).await?);

            if let Some(cache) = cache {
                cache.put(key, Arc::clone(&fresh));
            }

            fresh
        }
    };
    let slot = loaded
        .slots
        .get(&ledger)
        .ok_or(Error::NoScpMessages { ledger })?;
    let header = loaded
        .headers
        .get(&ledger)
        .ok_or(Error::NoLedgerHeader { ledger })?;
    let mut input = HeaderInput {
        slot: ledger as u64,
        network_id: network.id(),
        ledger_header_xdr: header.header_xdr.clone(),
        envelopes_xdr: slot.externalize_xdr.clone(),
        quorum_sets_xdr: slot.quorum_sets_xdr.clone(),
        recorded_ledger_hash: Some(header.recorded_hash),
        result_pairs_xdr: Vec::new(),
        trusted_previous_hash,
    };

    let mutation = request.mutation.clone();

    if let Some(name) = mutation.as_deref() {
        let mutated =
            evaluate::apply_mutation(name, &input).map_err(|detail| Error::Mutation { detail })?;

        input = mutated.input;

        if let Some(replacement) = mutated.config {
            config = replacement;
        }
    }

    let following = ledger.checked_add(1);
    let next_source = following
        .filter(|following| archive::checkpoint_for(*following) == checkpoint)
        .map(|following| (following, &loaded));

    let next_evidence = next_source.and_then(|(following, source)| {
        let slot = source.slots.get(&following)?;
        let tx_set = source.tx_sets.get(&following)?.clone()?;

        Some((
            slot.externalize_xdr.clone(),
            slot.quorum_sets_xdr.clone(),
            tx_set,
        ))
    });
    let next = next_evidence
        .as_ref()
        .map(|(envelopes, quorum_sets, tx_set)| NextSlot {
            envelopes_xdr: envelopes,
            quorum_sets_xdr: quorum_sets,
            tx_set_xdr: tx_set,
        });

    Ok(evaluate::evaluate(&input, &config, next, mutation))
}
