//! Engine-neutral network inspection placement.
//!
//! Inputs are observed facts. The deterministic planner selects the smallest
//! useful set of candidates, reports blind spots, and explains every score;
//! it never assumes that installing a particular IDS grants visibility.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

pub const INSPECTION_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InspectionDepth {
    HostFlows,
    PacketMetadata,
    DeepPackets,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationMethod {
    Endpoint,
    Gateway,
    Mirror,
    Tap,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectionIntent {
    pub schema_version: u32,
    pub networks: BTreeSet<String>,
    pub depth: InspectionDepth,
    pub redundancy: u8,
}

impl InspectionIntent {
    pub fn new(
        networks: BTreeSet<String>,
        depth: InspectionDepth,
        redundancy: u8,
    ) -> Result<Self, String> {
        if networks.is_empty() {
            return Err("inspection intent needs at least one network".into());
        }
        if redundancy == 0 {
            return Err("inspection redundancy must be at least one".into());
        }
        Ok(Self {
            schema_version: INSPECTION_SCHEMA_VERSION,
            networks,
            depth,
            redundancy,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InspectionCandidate {
    pub node_id: String,
    pub hostname: String,
    pub site: String,
    pub method: ObservationMethod,
    pub depths: BTreeSet<InspectionDepth>,
    pub visible_networks: BTreeSet<String>,
    pub logical_cpus: u32,
    pub memory_available_bytes: u64,
    pub load_per_cpu: f64,
    pub uptime_seconds: u64,
    pub trusted: bool,
    pub stable_power: bool,
    #[serde(default)]
    pub failure_domain: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CandidateAssessment {
    pub node_id: String,
    pub hostname: String,
    pub eligible: bool,
    pub score: i64,
    pub covers: BTreeSet<String>,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InspectionPlacement {
    pub node_id: String,
    pub hostname: String,
    pub method: ObservationMethod,
    pub networks: BTreeSet<String>,
    pub score: i64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InspectionPlan {
    pub schema_version: u32,
    pub intent: InspectionIntent,
    pub placements: Vec<InspectionPlacement>,
    pub assessments: Vec<CandidateAssessment>,
    /// Missing copies per network. Empty means the requested redundancy is met.
    pub blind_spots: BTreeMap<String, u8>,
}

pub fn plan_inspection(
    intent: InspectionIntent,
    candidates: &[InspectionCandidate],
) -> InspectionPlan {
    let mut assessments = candidates
        .iter()
        .map(|candidate| assess(&intent, candidate))
        .collect::<Vec<_>>();
    assessments.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.node_id.cmp(&b.node_id))
    });
    let by_id = candidates
        .iter()
        .map(|candidate| (candidate.node_id.as_str(), candidate))
        .collect::<BTreeMap<_, _>>();
    let mut required = intent
        .networks
        .iter()
        .map(|network| (network.clone(), intent.redundancy))
        .collect::<BTreeMap<_, _>>();
    let mut used_domains = BTreeMap::<String, BTreeSet<String>>::new();
    let mut placements = Vec::new();

    loop {
        let best = assessments
            .iter()
            .filter(|assessment| {
                assessment.eligible
                    && !placements.iter().any(|placement: &InspectionPlacement| {
                        placement.node_id == assessment.node_id
                    })
            })
            .filter_map(|assessment| {
                let candidate = by_id[assessment.node_id.as_str()];
                let useful = assessment
                    .covers
                    .iter()
                    .filter(|network| {
                        required.get(*network).copied().unwrap_or(0) > 0
                            && !used_domains
                                .get(*network)
                                .is_some_and(|domains| domains.contains(&candidate.failure_domain))
                    })
                    .cloned()
                    .collect::<BTreeSet<_>>();
                (!useful.is_empty()).then_some((assessment, candidate, useful))
            })
            .max_by(|(left, _, left_coverage), (right, _, right_coverage)| {
                left_coverage
                    .len()
                    .cmp(&right_coverage.len())
                    .then_with(|| left.score.cmp(&right.score))
                    .then_with(|| right.node_id.cmp(&left.node_id))
            });
        let Some((assessment, candidate, useful)) = best else {
            break;
        };
        for network in &useful {
            if let Some(remaining) = required.get_mut(network) {
                *remaining = remaining.saturating_sub(1);
            }
            used_domains
                .entry(network.clone())
                .or_default()
                .insert(candidate.failure_domain.clone());
        }
        placements.push(InspectionPlacement {
            node_id: candidate.node_id.clone(),
            hostname: candidate.hostname.clone(),
            method: candidate.method,
            networks: useful,
            score: assessment.score,
        });
    }

    InspectionPlan {
        schema_version: INSPECTION_SCHEMA_VERSION,
        intent,
        placements,
        assessments,
        blind_spots: required
            .into_iter()
            .filter(|(_, missing)| *missing > 0)
            .collect(),
    }
}

fn assess(intent: &InspectionIntent, candidate: &InspectionCandidate) -> CandidateAssessment {
    let covers = candidate
        .visible_networks
        .intersection(&intent.networks)
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut reasons = Vec::new();
    if !candidate.trusted {
        reasons.push("peer identity is not trusted".into());
    }
    if !candidate.depths.contains(&intent.depth) {
        reasons.push(format!("does not support {:?}", intent.depth).to_lowercase());
    }
    if covers.is_empty() {
        reasons.push("no evidenced visibility into requested networks".into());
    }
    if candidate.logical_cpus == 0 {
        reasons.push("CPU capacity is unknown".into());
    }
    if candidate.memory_available_bytes < 256 * 1024 * 1024 {
        reasons.push("less than 256 MiB memory available".into());
    }
    let eligible = reasons.is_empty();
    let method = match candidate.method {
        ObservationMethod::Tap => 400,
        ObservationMethod::Mirror => 350,
        ObservationMethod::Gateway => 300,
        ObservationMethod::Endpoint => 100,
    };
    let capacity = i64::from(candidate.logical_cpus.min(32)) * 20
        + ((candidate.memory_available_bytes / (1024 * 1024 * 1024)).min(64) as i64) * 10;
    let reliability = if candidate.stable_power { 80 } else { 0 }
        + if candidate.uptime_seconds >= 86_400 {
            40
        } else {
            0
        };
    let load_penalty = (candidate.load_per_cpu.clamp(0.0, 4.0) * 100.0) as i64;
    let score = if eligible {
        covers.len() as i64 * 1000 + method + capacity + reliability - load_penalty
    } else {
        i64::MIN / 2
    };
    if eligible {
        reasons.push(format!("covers {} requested network(s)", covers.len()));
        reasons.push(format!("method={:?}", candidate.method).to_lowercase());
    }
    CandidateAssessment {
        node_id: candidate.node_id.clone(),
        hostname: candidate.hostname.clone(),
        eligible,
        score,
        covers,
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn candidate(id: &str, networks: &[&str], domain: &str) -> InspectionCandidate {
        InspectionCandidate {
            node_id: id.into(),
            hostname: id.into(),
            site: "lab".into(),
            method: ObservationMethod::Gateway,
            depths: [InspectionDepth::HostFlows, InspectionDepth::PacketMetadata].into(),
            visible_networks: networks.iter().map(|v| (*v).into()).collect(),
            logical_cpus: 4,
            memory_available_bytes: 4 * 1024 * 1024 * 1024,
            load_per_cpu: 0.1,
            uptime_seconds: 100_000,
            trusted: true,
            stable_power: true,
            failure_domain: domain.into(),
        }
    }
    #[test]
    fn chooses_set_cover_deterministically() {
        let intent = InspectionIntent::new(
            ["a".into(), "b".into()].into(),
            InspectionDepth::PacketMetadata,
            1,
        )
        .unwrap();
        let plan = plan_inspection(
            intent,
            &[
                candidate("one", &["a"], "x"),
                candidate("both", &["a", "b"], "y"),
            ],
        );
        assert_eq!(plan.placements.len(), 1);
        assert_eq!(plan.placements[0].node_id, "both");
        assert!(plan.blind_spots.is_empty());
    }
    #[test]
    fn redundancy_requires_independent_failure_domains() {
        let intent =
            InspectionIntent::new(["a".into()].into(), InspectionDepth::HostFlows, 2).unwrap();
        let plan = plan_inspection(
            intent,
            &[
                candidate("one", &["a"], "switch-a"),
                candidate("two", &["a"], "switch-a"),
            ],
        );
        assert_eq!(plan.blind_spots["a"], 1);
    }
    #[test]
    fn reports_unknown_visibility_as_blind_spot() {
        let intent =
            InspectionIntent::new(["cctv".into()].into(), InspectionDepth::HostFlows, 1).unwrap();
        let plan = plan_inspection(intent, &[candidate("one", &["lan"], "x")]);
        assert_eq!(plan.blind_spots["cctv"], 1);
        assert!(!plan.assessments[0].eligible);
    }
}
