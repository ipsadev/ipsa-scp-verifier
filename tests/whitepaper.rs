use ipsa_scp_verifier::error::VerifyError;
use ipsa_scp_verifier::scp::quorum::{is_quorum_slice, NodeId, QuorumSet};
use ipsa_scp_verifier::steps::{verify_externalized_value, verify_quorum, QuorumConfig};

use ipsa_scp_verifier::scp::envelope::{Ballot, Envelope, Externalize, Statement};

fn node(seed: u8) -> NodeId {
    [seed; 32]
}

fn qset(threshold: u32, validators: &[NodeId], inner_sets: Vec<QuorumSet>) -> QuorumSet {
    QuorumSet {
        threshold,
        validators: validators.to_vec(),
        inner_sets,
    }
}

fn encode(qset: &QuorumSet) -> Vec<u8> {
    let mut out = qset.threshold.to_be_bytes().to_vec();
    out.extend_from_slice(&(qset.validators.len() as u32).to_be_bytes());
    for v in &qset.validators {
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(v);
    }
    out.extend_from_slice(&(qset.inner_sets.len() as u32).to_be_bytes());
    for inner in &qset.inner_sets {
        out.extend_from_slice(&encode(inner));
    }
    out
}

fn trust_root(qset: &QuorumSet) -> QuorumConfig {
    QuorumConfig::from_xdr(&encode(qset)).expect("the trust root is sane")
}

fn unchecked_trust_root(qset: &QuorumSet) -> QuorumConfig {
    QuorumConfig {
        local: qset.clone(),
        raw: encode(qset),
    }
}

fn slices(pairs: &[(NodeId, QuorumSet)], id: &NodeId) -> Option<QuorumSet> {
    pairs
        .iter()
        .find(|(other, _)| other == id)
        .map(|(_, q)| q.clone())
}

fn survivors(signers: &[(NodeId, QuorumSet)]) -> Vec<NodeId> {
    let mut current: Vec<NodeId> = signers.iter().map(|(id, _)| *id).collect();
    loop {
        let snapshot = current.clone();
        let next: Vec<NodeId> = snapshot
            .iter()
            .copied()
            .filter(|id| slices(signers, id).is_some_and(|q| is_quorum_slice(&q, &snapshot)))
            .collect();
        if next.len() == current.len() {
            return next;
        }
        current = next;
    }
}

fn externalize(node_id: NodeId, counter: u32, value: &[u8]) -> Envelope {
    Envelope {
        node_id,
        slot_index: 1,
        statement: Statement::Externalize(Externalize {
            commit: Ballot {
                counter,
                value: value.to_vec(),
            },
            highest_confirmed_ballot_counter: counter,
            commit_quorum_set_hash: [0u8; 32],
        }),
        signature: [0u8; 64],
        statement_bytes: Vec::new(),
    }
}

#[test]
fn a_quorum_contains_a_slice_for_each_of_its_members() {
    let (a, b, c) = (node(1), node(2), node(3));
    let all = [a, b, c];
    let among = qset(2, &all, Vec::new());
    let signers = vec![(a, among.clone()), (b, among.clone()), (c, among.clone())];
    let root = trust_root(&among);

    assert!(verify_quorum(&root, &signers).is_ok());

    let survived = survivors(&signers);
    assert!(!survived.is_empty(), "a quorum must be non-empty");

    for id in &survived {
        let own = slices(&signers, id).expect("a survivor has a quorum set");
        assert!(
            is_quorum_slice(&own, &survived),
            "member {} has no slice inside the quorum",
            hex::encode(id)
        );
    }

    assert!(
        is_quorum_slice(&root.local, &survived),
        "the trust root has no slice inside the quorum"
    );
}

#[test]
fn the_empty_set_is_not_a_quorum() {
    let root = trust_root(&qset(1, &[node(1)], Vec::new()));

    assert!(matches!(
        verify_quorum(&root, &[]),
        Err(VerifyError::NoEnvelopes)
    ));
}

#[test]
fn a_signer_whose_own_slices_are_unsatisfied_does_not_count() {
    let a = node(1);
    let stranger = node(9);
    let signers = vec![(a, qset(1, &[stranger], Vec::new()))];
    let root = trust_root(&qset(1, &[a], Vec::new()));

    assert!(survivors(&signers).is_empty());
    assert!(matches!(
        verify_quorum(&root, &signers),
        Err(VerifyError::InsufficientQuorum { .. })
    ));
}

#[test]
fn the_fixed_point_finds_a_quorum_hiding_among_unclosed_signers() {
    let (a, b, loner) = (node(1), node(2), node(3));
    let pair = qset(2, &[a, b], Vec::new());
    let signers = vec![
        (a, pair.clone()),
        (b, pair.clone()),
        (loner, qset(1, &[node(9)], Vec::new())),
    ];
    let root = trust_root(&pair);

    assert_eq!(survivors(&signers), vec![a, b]);
    assert!(
        verify_quorum(&root, &signers).is_ok(),
        "the quorum {{a, b}} survives even though the whole signer set is not closed"
    );
}

#[test]
fn losing_one_node_cascades_through_the_fixed_point() {
    let (a, b, c) = (node(1), node(2), node(3));
    let signers = vec![
        (a, qset(1, &[b], Vec::new())),
        (b, qset(1, &[c], Vec::new())),
        (c, qset(1, &[node(9)], Vec::new())),
    ];
    let root = trust_root(&qset(1, &[a], Vec::new()));

    assert!(survivors(&signers).is_empty());
    assert!(matches!(
        verify_quorum(&root, &signers),
        Err(VerifyError::InsufficientQuorum { .. })
    ));
}

#[test]
fn many_signatures_from_untrusted_nodes_are_not_a_quorum() {
    let strangers: Vec<NodeId> = (10u8..31).map(node).collect();
    let among = qset(21, &strangers, Vec::new());
    let signers: Vec<(NodeId, QuorumSet)> =
        strangers.iter().map(|id| (*id, among.clone())).collect();

    let mine = [node(1), node(2), node(3)];
    let root = trust_root(&qset(2, &mine, Vec::new()));

    assert_eq!(signers.len(), 21);
    assert!(
        matches!(
            verify_quorum(&root, &signers),
            Err(VerifyError::InsufficientQuorum { .. })
        ),
        "21 signatures from nodes the trust root never names is not a quorum"
    );
}

#[test]
fn one_signature_is_a_quorum_when_the_trust_root_says_so() {
    let a = node(1);
    let solo = qset(1, &[a], Vec::new());
    let signers = vec![(a, solo.clone())];

    assert!(
        verify_quorum(&unchecked_trust_root(&solo), &signers).is_ok(),
        "quorums are defined by slices, not by counting signatures"
    );
}

#[test]
fn a_slice_counts_validators_before_inner_sets() {
    let (a, b) = (node(1), node(2));
    let inner = qset(1, &[node(3)], Vec::new());
    let set = qset(2, &[a, b], vec![inner]);

    assert!(is_quorum_slice(&set, &[a, b]));
    assert!(is_quorum_slice(&set, &[a, node(3)]));
    assert!(!is_quorum_slice(&set, &[a]));
    assert!(!is_quorum_slice(&set, &[node(3)]));
}

#[test]
fn an_inner_set_satisfies_exactly_one_unit_of_the_outer_threshold() {
    let inner_a = qset(2, &[node(1), node(2)], Vec::new());
    let inner_b = qset(2, &[node(3), node(4)], Vec::new());
    let outer = qset(2, &[], vec![inner_a, inner_b]);

    assert!(is_quorum_slice(
        &outer,
        &[node(1), node(2), node(3), node(4)]
    ));
    assert!(
        !is_quorum_slice(&outer, &[node(1), node(2)]),
        "one satisfied inner set counts once, not twice"
    );
}

#[test]
fn slices_are_upward_closed() {
    let set = qset(2, &[node(1), node(2)], Vec::new());
    let satisfying = [node(1), node(2)];
    assert!(is_quorum_slice(&set, &satisfying));

    let mut larger = satisfying.to_vec();
    for extra in 3u8..40 {
        larger.push(node(extra));
        assert!(
            is_quorum_slice(&set, &larger),
            "adding a node must never unsatisfy a slice"
        );
    }
}

#[test]
fn adding_signers_never_destroys_a_quorum() {
    let (a, b) = (node(1), node(2));
    let pair = qset(2, &[a, b], Vec::new());
    let root = trust_root(&pair);

    let mut signers = vec![(a, pair.clone()), (b, pair.clone())];
    assert!(verify_quorum(&root, &signers).is_ok());

    for extra in 3u8..12 {
        signers.push((node(extra), pair.clone()));
        assert!(
            verify_quorum(&root, &signers).is_ok(),
            "a quorum stays a quorum when unrelated signers are added"
        );
    }
}

#[test]
fn the_quorum_check_is_relative_to_the_configured_trust_root() {
    let (a, b) = (node(1), node(2));
    let pair = qset(2, &[a, b], Vec::new());
    let signers = vec![(a, pair.clone()), (b, pair.clone())];

    assert!(verify_quorum(&trust_root(&pair), &signers).is_ok());

    let elsewhere = qset(2, &[node(7), node(8)], Vec::new());
    assert!(
        matches!(
            verify_quorum(&trust_root(&elsewhere), &signers),
            Err(VerifyError::InsufficientQuorum { .. })
        ),
        "the same signers are a quorum for one trust root and not for another"
    );
}

#[test]
fn a_trust_root_must_meet_the_v_blocking_rule() {
    let four = [node(1), node(2), node(3), node(4)];

    assert!(qset(1, &four, Vec::new()).check_sane(false).is_ok());
    assert!(
        qset(1, &four, Vec::new()).check_sane(true).is_err(),
        "a threshold below the v-blocking size is refused as a trust root"
    );
    assert!(qset(3, &four, Vec::new()).check_sane(true).is_ok());
}

#[test]
fn one_agreed_value_across_different_ballot_counters() {
    let value = b"the-externalized-stellar-value";
    let envelopes = [
        externalize(node(1), 1, value),
        externalize(node(2), 7, value),
        externalize(node(3), 4123, value),
    ];

    assert_eq!(
        verify_externalized_value(&envelopes).expect("counters are not consensus-relevant"),
        value.to_vec()
    );
}

#[test]
fn one_ballot_counter_cannot_carry_two_values() {
    let envelopes = [
        externalize(node(1), 1, b"value-a"),
        externalize(node(2), 1, b"value-b"),
    ];

    assert!(matches!(
        verify_externalized_value(&envelopes),
        Err(VerifyError::ConflictingValues { .. })
    ));
}

#[test]
fn a_quorum_set_names_between_one_and_a_thousand_validators() {
    assert!(qset(1, &[], Vec::new()).check_sane(false).is_err());

    let many: Vec<NodeId> = (0u16..1001)
        .map(|i| {
            let mut id = [0u8; 32];
            id[0..2].copy_from_slice(&i.to_be_bytes());
            id
        })
        .collect();
    assert!(qset(1, &many, Vec::new()).check_sane(false).is_err());
}

#[test]
fn a_repeated_validator_is_refused() {
    let a = node(1);
    assert!(qset(1, &[a, a], Vec::new()).check_sane(false).is_err());

    let inner = qset(1, &[a], Vec::new());
    assert!(
        qset(1, &[a], vec![inner]).check_sane(false).is_err(),
        "a validator repeated across an inner set is still a repeat"
    );
}
