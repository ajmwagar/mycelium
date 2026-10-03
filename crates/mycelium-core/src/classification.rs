//! Provider-neutral, pure device classification boundary.
//!
//! Discovery transports produce bounded evidence. Classifiers may refine an
//! identity, but cannot perform I/O or grant authority.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{DeviceKind, Result};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentityEvidence {
    pub source: String,
    pub address: String,
    #[serde(default)]
    pub facts: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceClassification {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<DeviceKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stable_id: Option<String>,
}

pub trait DeviceClassifier: Send + Sync {
    fn classify(&self, evidence: &DeviceIdentityEvidence) -> Result<Option<DeviceClassification>>;
}
