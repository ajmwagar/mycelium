//! Shared presentation contract. No discovery, credentials, model internals or
//! provider control. Providers own collection; hosts own grants and freshness.
use serde::{Deserialize, Serialize};
pub const MESSAGE_KIND: &str = "coherence.widget.snapshot.v1";
pub const MAX_SERIES: usize = 16;
pub const MAX_HISTORY: usize = 120;
pub const MAX_BYTES: usize = 32 * 1024;

/// A host retains the last valid frame when delivery pauses. Expiry changes its
/// status, not its contents; consumers must not fade useful data to nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedState {
    Connecting,
    Live,
    Stale,
}

#[derive(Default)]
pub struct RetainedFeed {
    snapshot: Option<Snapshot>,
}
impl RetainedFeed {
    /// Use one instance per authorized producer/widget pair. Identity binding
    /// and ACL checks belong to the host, before calling this method.
    pub fn update(&mut self, incoming: Snapshot, now: u64) -> Result<(), &'static str> {
        incoming.validate()?;
        if !incoming.fresh_at(now) {
            return Err("expired or future widget snapshot");
        }
        if let Some(previous) = &self.snapshot {
            if incoming.widget_id != previous.widget_id {
                return Err("widget identity changed");
            }
            if incoming.observed_at_unix_ms <= previous.observed_at_unix_ms {
                return Err("duplicate or out-of-order widget snapshot");
            }
        }
        self.snapshot = Some(incoming);
        Ok(())
    }
    pub fn snapshot(&self) -> Option<&Snapshot> {
        self.snapshot.as_ref()
    }
    pub fn state_at(&self, now: u64) -> FeedState {
        match &self.snapshot {
            None => FeedState::Connecting,
            Some(snapshot) if snapshot.fresh_at(now) => FeedState::Live,
            Some(_) => FeedState::Stale,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metric {
    pub id: String,
    pub label: String,
    pub unit: String,
    /// None is unavailable, never silently converted into zero.
    pub value: Option<f32>,
    pub maximum: Option<f32>,
    #[serde(default)]
    pub history: Vec<f32>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServedModel {
    pub id: String,
    pub owned_by: String,
}
/// Provider-advertised serving routes, not a disk inventory or load guarantee.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCatalog {
    pub available: bool,
    pub entries: Vec<ServedModel>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub schema_version: u16,
    pub widget_id: String,
    pub observed_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub metrics: Vec<Metric>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_catalog: Option<ModelCatalog>,
}
pub fn identifier(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"-_.".contains(&c))
}
impl Snapshot {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != 1
            || !identifier(&self.widget_id)
            || self.metrics.len() > MAX_SERIES
            || self.expires_at_unix_ms <= self.observed_at_unix_ms
            || self
                .expires_at_unix_ms
                .saturating_sub(self.observed_at_unix_ms)
                > 120_000
        {
            return Err("invalid widget identity, version, size or lifetime");
        }
        let mut ids = std::collections::BTreeSet::new();
        if let Some(catalog) = &self.model_catalog {
            if catalog.entries.len() > 128 || (!catalog.available && !catalog.entries.is_empty()) {
                return Err("invalid model catalog size or availability");
            }
            let mut models = std::collections::BTreeSet::new();
            for model in &catalog.entries {
                if model.id.is_empty()
                    || model.id.len() > 256
                    || model.id.chars().any(char::is_control)
                    || model.owned_by.len() > 128
                    || model.owned_by.chars().any(char::is_control)
                    || !models.insert(&model.id)
                {
                    return Err("invalid or duplicate served model");
                }
            }
        }
        for metric in &self.metrics {
            if !identifier(&metric.id)
                || !ids.insert(&metric.id)
                || metric.label.is_empty()
                || metric.label.len() > 128
                || metric.label.chars().any(char::is_control)
                || metric.unit.len() > 32
                || metric.unit.chars().any(char::is_control)
                || metric.value.is_some_and(|v| !v.is_finite())
                || metric.maximum.is_some_and(|v| !v.is_finite() || v <= 0.)
                || metric.history.len() > MAX_HISTORY
                || metric.history.iter().any(|v| !v.is_finite())
            {
                return Err("invalid, duplicate or oversized widget metric");
            }
        }
        Ok(())
    }
    pub fn fresh_at(&self, now: u64) -> bool {
        self.observed_at_unix_ms <= now.saturating_add(5_000) && now < self.expires_at_unix_ms
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn snapshot() -> Snapshot {
        Snapshot {
            schema_version: 1,
            widget_id: "umie".into(),
            observed_at_unix_ms: 1000,
            expires_at_unix_ms: 31000,
            model_catalog: None,
            metrics: vec![Metric {
                id: "gpu".into(),
                label: "GPU use".into(),
                unit: "%".into(),
                value: None,
                maximum: Some(100.),
                history: vec![],
            }],
        }
    }
    #[test]
    fn model_catalog_rejects_duplicate_and_unavailable_entries() {
        let mut s = snapshot();
        let model = ServedModel {
            id: "org/model".into(),
            owned_by: "owner".into(),
        };
        s.model_catalog = Some(ModelCatalog {
            available: true,
            entries: vec![model.clone()],
        });
        assert!(s.validate().is_ok());
        s.model_catalog.as_mut().unwrap().entries.push(model);
        assert!(s.validate().is_err());
        s.model_catalog.as_mut().unwrap().entries.pop();
        s.model_catalog.as_mut().unwrap().available = false;
        assert!(s.validate().is_err());
    }
    #[test]
    fn unavailable_is_not_zero_and_expiry_is_exact() {
        let s = snapshot();
        s.validate().unwrap();
        assert!(s.fresh_at(1000));
        assert!(!s.fresh_at(31000));
        assert!(serde_json::to_string(&s)
            .unwrap()
            .contains("\"value\":null"));
    }
    #[test]
    fn malformed_or_unbounded_series_are_rejected() {
        let mut s = snapshot();
        s.metrics[0].value = Some(f32::NAN);
        assert!(s.validate().is_err());
        let mut s = snapshot();
        s.metrics[0].history = vec![0.; 121];
        assert!(s.validate().is_err());
        let mut s = snapshot();
        s.metrics.push(s.metrics[0].clone());
        assert!(s.validate().is_err());
        let mut s = snapshot();
        s.expires_at_unix_ms = 130000;
        assert!(s.validate().is_err());
    }
    #[test]
    fn stale_data_is_retained_and_recovers_without_replacing_the_host() {
        let mut feed = RetainedFeed::default();
        assert_eq!(feed.state_at(1000), FeedState::Connecting);
        feed.update(snapshot(), 1000).unwrap();
        assert_eq!(feed.state_at(1000), FeedState::Live);
        assert_eq!(feed.state_at(31000), FeedState::Stale);
        assert!(feed.snapshot().is_some());
        let mut next = snapshot();
        next.observed_at_unix_ms = 32000;
        next.expires_at_unix_ms = 62000;
        feed.update(next, 32000).unwrap();
        assert_eq!(feed.state_at(32000), FeedState::Live);
    }
    #[test]
    fn bad_updates_never_destroy_the_last_valid_frame() {
        let mut feed = RetainedFeed::default();
        feed.update(snapshot(), 1000).unwrap();
        assert!(feed.update(snapshot(), 1001).is_err());
        let mut wrong = snapshot();
        wrong.widget_id = "shroud".into();
        wrong.observed_at_unix_ms = 1001;
        assert!(feed.update(wrong, 1001).is_err());
        assert!(feed.update(snapshot(), 31000).is_err());
        assert_eq!(feed.snapshot().unwrap().widget_id, "umie");
    }
}
