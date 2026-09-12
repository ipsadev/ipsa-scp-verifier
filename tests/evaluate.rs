use std::path::Path;

use ipsa_scp_verifier::evaluate::{apply_mutation, evaluate, NextSlot, MUTATIONS};
use ipsa_scp_verifier::fixture::Fixture;
use ipsa_scp_verifier::steps::{HeaderInput, QuorumConfig};

fn load() -> (HeaderInput, QuorumConfig, Vec<Vec<u8>>, Vec<u8>) {
    let fixture = Fixture::load(Path::new("tests/fixtures/mainnet-63907880.json")).unwrap();
    let (input, next) = fixture.to_input().unwrap();

    let config = QuorumConfig::from_xdr(&input.quorum_sets_xdr[0]).unwrap();
    let next = next.unwrap_or(ipsa_scp_verifier::fixture::NextSlot {
        envelopes_xdr: Vec::new(),
        quorum_sets_xdr: Vec::new(),
        tx_set_xdr: Vec::new(),
    });

    (input, config, next.envelopes_xdr, next.tx_set_xdr)
}

fn run(
    input: &HeaderInput,
    config: &QuorumConfig,
    mutation: Option<&str>,
) -> ipsa_scp_verifier::evaluate::Report {
    evaluate(input, config, None, mutation.map(str::to_string))
}

#[test]
fn a_clean_ledger_passes_every_archive_verifiable_step() {
    let (input, config, _, _) = load();
    let report = run(&input, &config, None);

    assert!(
        report.verified,
        "expected a clean verify, got {:?}",
        report.steps
    );
    assert_eq!(report.ledger, 63_907_880);
    assert_eq!(report.signers, 21);

    for step in report.steps.iter().filter(|s| s.step <= 6) {
        assert!(
            step.passed,
            "step {} did not pass: {:?}",
            step.step, step.error
        );
    }
}

#[test]
fn the_report_names_every_step_in_order() {
    let (input, config, _, _) = load();
    let report = run(&input, &config, None);

    let numbers: Vec<usize> = report.steps.iter().map(|s| s.step).collect();
    assert_eq!(numbers, vec![1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn a_clean_ledger_reports_its_hash() {
    let (input, config, _, _) = load();
    let report = run(&input, &config, None);

    assert_eq!(
        report.ledger_hash.as_deref(),
        Some("57f1147d7b800c956df0ed72425bf0fa474ddc22cff06ba901dbc76e82f29fd6")
    );
}

#[test]
fn every_mutation_fails_the_step_it_targets() {
    let (input, config, _, _) = load();

    for (name, expected_step) in MUTATIONS {
        if name == "tampered-result-pairs" && input.result_pairs_xdr.is_empty() {
            assert!(
                apply_mutation(name, &input).is_err(),
                "{name} must refuse when the ledger carries no results"
            );
            continue;
        }

        let mutated = apply_mutation(name, &input).unwrap();
        let config = mutated.config.clone().unwrap_or_else(|| config.clone());
        let report = run(&mutated.input, &config, Some(name));

        assert!(!report.verified, "{name} was accepted");

        let failing: Vec<&ipsa_scp_verifier::evaluate::StepResult> = report
            .steps
            .iter()
            .filter(|s| !s.passed && !s.skipped)
            .collect();

        assert_eq!(failing.len(), 1, "{name} failed {} steps", failing.len());
        assert_eq!(
            failing[0].name, expected_step,
            "{name} failed the wrong step"
        );
        assert!(failing[0].error.is_some(), "{name} reported no error");
    }
}

#[test]
fn a_mutation_stops_the_run_at_the_failing_step() {
    let (input, config, _, _) = load();
    let mutated = apply_mutation("tampered-signature", &input).unwrap();
    let report = run(&mutated.input, &config, Some("tampered-signature"));

    assert_eq!(report.steps.len(), 1);
    assert_eq!(report.steps[0].step, 1);
}

#[test]
fn an_unknown_mutation_is_rejected() {
    let (input, _, _, _) = load();
    assert!(apply_mutation("not-a-mutation", &input).is_err());
}

#[test]
fn the_next_slot_step_is_skipped_without_evidence() {
    let (input, config, _, _) = load();
    let report = run(&input, &config, None);

    let seven = report.steps.iter().find(|s| s.step == 7).unwrap();
    assert!(seven.skipped);
    assert!(seven.error.is_none());
}

#[test]
fn the_next_slot_step_passes_with_real_evidence() {
    let (input, config, next_envelopes, next_tx_set) = load();
    if next_tx_set.is_empty() {
        return;
    }

    let report = evaluate(
        &input,
        &config,
        Some(NextSlot {
            envelopes_xdr: &next_envelopes,
            tx_set_xdr: &next_tx_set,
        }),
        None,
    );

    let seven = report.steps.iter().find(|s| s.step == 7).unwrap();
    assert!(seven.passed, "step 7 failed: {:?}", seven.error);
}
