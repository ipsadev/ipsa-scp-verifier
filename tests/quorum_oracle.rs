use ipsa_scp_verifier::scp::quorum::{is_quorum, is_quorum_slice, NodeId, QuorumSet};

const MAX_NODES: usize = 8;
const CASES: usize = 20_000;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + self.below(hi - lo + 1)
    }

    fn chance(&mut self, one_in: usize) -> bool {
        self.below(one_in) == 0
    }
}

fn node(i: usize) -> NodeId {
    [i as u8; 32]
}

fn subset(rng: &mut Rng, nodes: &[NodeId], min: usize) -> Vec<NodeId> {
    loop {
        let picked: Vec<NodeId> = nodes.iter().copied().filter(|_| rng.chance(2)).collect();
        if picked.len() >= min {
            return picked;
        }
    }
}

fn random_qset(rng: &mut Rng, nodes: &[NodeId], depth: u32) -> QuorumSet {
    let validators = subset(rng, nodes, 1);
    let inner_count = if depth == 0 { rng.below(3) } else { 0 };
    let inner_sets: Vec<QuorumSet> = (0..inner_count)
        .map(|_| random_qset(rng, nodes, depth + 1))
        .collect();
    let entries = validators.len() + inner_sets.len();
    QuorumSet {
        threshold: rng.range(1, entries) as u32,
        validators,
        inner_sets,
    }
}

fn slice_by_counting(qset: &QuorumSet, nodes: &[NodeId]) -> bool {
    let from_validators = qset.validators.iter().filter(|v| nodes.contains(v)).count();
    let from_inner = qset
        .inner_sets
        .iter()
        .filter(|inner| slice_by_counting(inner, nodes))
        .count();
    from_validators + from_inner >= qset.threshold as usize
}

fn is_closed(signers: &[(NodeId, QuorumSet)], members: &[NodeId]) -> bool {
    members.iter().all(|id| {
        signers
            .iter()
            .find(|(other, _)| other == id)
            .is_some_and(|(_, qset)| is_quorum_slice(qset, members))
    })
}

fn greatest_closed_subset(signers: &[(NodeId, QuorumSet)]) -> Vec<NodeId> {
    let ids: Vec<NodeId> = signers.iter().map(|(id, _)| *id).collect();
    let mut union: Vec<NodeId> = Vec::new();
    for mask in 0u32..(1 << ids.len()) {
        let candidate: Vec<NodeId> = ids
            .iter()
            .enumerate()
            .filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, id)| *id)
            .collect();
        if is_closed(signers, &candidate) {
            for id in candidate {
                if !union.contains(&id) {
                    union.push(id);
                }
            }
        }
    }
    union
}

fn any_closed_subset_satisfies(local: &QuorumSet, signers: &[(NodeId, QuorumSet)]) -> bool {
    let ids: Vec<NodeId> = signers.iter().map(|(id, _)| *id).collect();
    (0u32..(1 << ids.len())).any(|mask| {
        let candidate: Vec<NodeId> = ids
            .iter()
            .enumerate()
            .filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, id)| *id)
            .collect();
        !candidate.is_empty()
            && is_closed(signers, &candidate)
            && is_quorum_slice(local, &candidate)
    })
}

struct Case {
    local: QuorumSet,
    signers: Vec<(NodeId, QuorumSet)>,
    absent: Vec<(NodeId, QuorumSet)>,
}

fn generate(rng: &mut Rng) -> Case {
    let count = rng.range(3, MAX_NODES);
    let nodes: Vec<NodeId> = (1..=count).map(node).collect();
    let qsets: Vec<QuorumSet> = nodes.iter().map(|_| random_qset(rng, &nodes, 0)).collect();

    let mut signers = Vec::new();
    let mut absent = Vec::new();
    for (id, qset) in nodes.iter().zip(qsets.iter()) {
        if rng.chance(3) {
            absent.push((*id, qset.clone()));
        } else {
            signers.push((*id, qset.clone()));
        }
    }

    Case {
        local: random_qset(rng, &nodes, 0),
        signers,
        absent,
    }
}

#[test]
fn the_fixed_point_agrees_with_exhaustive_subset_search() {
    let mut quorums = 0usize;
    for seed in 1..=CASES as u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let case = generate(&mut rng);

        let theirs = is_quorum(&case.local, &case.signers);
        let by_union = is_quorum_slice(&case.local, &greatest_closed_subset(&case.signers));
        let by_search = any_closed_subset_satisfies(&case.local, &case.signers);

        assert_eq!(
            theirs, by_union,
            "seed {seed}: is_quorum disagrees with the greatest closed subset"
        );
        assert_eq!(
            theirs, by_search,
            "seed {seed}: is_quorum disagrees with the whitepaper definition searched exhaustively"
        );

        if theirs {
            quorums += 1;
        }
    }

    let share = quorums * 100 / CASES;
    assert!(
        (5..=95).contains(&share),
        "{share}% of generated cases were quorums - the generator has degenerated and the \
         comparison is no longer meaningful"
    );
}

#[test]
fn slices_agree_with_a_counting_implementation() {
    for seed in 1..=CASES as u64 {
        let mut rng = Rng(seed.wrapping_mul(0x2545_f491_4f6c_dd1d) | 1);
        let case = generate(&mut rng);
        let present: Vec<NodeId> = case.signers.iter().map(|(id, _)| *id).collect();

        for (id, qset) in case.signers.iter().chain(case.absent.iter()) {
            assert_eq!(
                is_quorum_slice(qset, &present),
                slice_by_counting(qset, &present),
                "seed {seed}: early-exit slice check disagrees with counting for node {}",
                id[0]
            );
        }
    }
}

#[test]
fn adding_signers_never_destroys_a_quorum() {
    for seed in 1..=CASES as u64 {
        let mut rng = Rng(seed.wrapping_mul(0xd1b5_4a32_d192_ed03) | 1);
        let case = generate(&mut rng);
        if case.absent.is_empty() {
            continue;
        }

        if !is_quorum(&case.local, &case.signers) {
            continue;
        }

        let mut grown = case.signers.clone();
        grown.extend(case.absent.iter().cloned());

        assert!(
            is_quorum(&case.local, &grown),
            "seed {seed}: adding signers turned a quorum into a non-quorum"
        );
    }
}
