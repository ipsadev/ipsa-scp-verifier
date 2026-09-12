use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

use crate::archive;
use crate::evaluate::{self, NextSlot};
use crate::network::Network;
use crate::steps::{HeaderInput, QuorumConfig};
use crate::sweep;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Request {
    pub ledger: u32,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub mutation: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Options {
    pub network: Network,
    pub archives: Vec<String>,
    pub archives_pinned: bool,
}

impl Options {
    pub fn for_network(network: Network) -> Self {
        Self {
            network,
            archives: vec![network.archive_base().to_string()],
            archives_pinned: false,
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

pub async fn verify(request: &Request, options: &Options) -> Result<evaluate::Report> {
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
    let loaded = sweep::load_checkpoint(checkpoint, &sweep_opts, true).await?;
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
        trusted_previous_hash: loaded.parent_hash(ledger),
    };

    let config = QuorumConfig::from_xdr(input.quorum_sets_xdr.first().ok_or(Error::NoQuorumSets)?)?;
    let mut config = config;
    let mutation = request.mutation.clone();

    if let Some(name) = mutation.as_deref() {
        let mutated =
            evaluate::apply_mutation(name, &input).map_err(|detail| Error::Mutation { detail })?;

        input = mutated.input;

        if let Some(replacement) = mutated.config {
            config = replacement;
        }
    }

    let following = ledger + 1;
    let next_source = if archive::checkpoint_for(following) == checkpoint {
        Some(&loaded)
    } else {
        None
    };

    let next_evidence = next_source.and_then(|source| {
        let envelopes = source.slots.get(&following)?;
        let tx_set = source.tx_sets.get(&following)?.clone()?;

        Some((envelopes.externalize_xdr.clone(), tx_set))
    });
    let next = next_evidence.as_ref().map(|(envelopes, tx_set)| NextSlot {
        envelopes_xdr: envelopes,
        tx_set_xdr: tx_set,
    });

    Ok(evaluate::evaluate(&input, &config, next, mutation))
}
