//! NETGEAR/LVL7 FASTPATH integration.
//!
//! The first boundary is deliberately offline: parse an exported ASCII
//! startup configuration without contacting or changing a switch. Transport
//! and device capabilities build on this representation later.

pub mod intent;
pub mod reconcile;
pub mod snmp;
pub mod startup_config;

pub use intent::{
    Diagnostic, DiagnosticLevel, FastpathIntent, InterfaceIntent, LagIntent, NormalizeError,
    OpaqueStatement, StackIntent, VlanIntent, VoiceOui,
};
pub use reconcile::{Blocker, PlanOperation, PlanStep, ReconcileOptions, ReconciliationPlan};
pub use snmp::{SnmpCoverage, SnmpInterfaceState, SnmpSwitchState, SnmpVlanState};

pub use startup_config::{
    ConfigLine, ConfigSection, FastpathConfig, Header, LineKind, ParseError, SecretKind, SecretRef,
};
