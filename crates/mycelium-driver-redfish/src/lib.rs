//! HPE iLO driver over its standard Redfish interface.
//!
//! iLO commonly uses a private CA or self-signed certificate. The driver
//! therefore accepts the controller certificate while still requiring HTTPS
//! and authenticated requests. Secrets remain env-backed and are resolved at
//! request time rather than serialized into inventory state.

mod driver;

pub use driver::{
    RedfishDevice, RedfishDriver, DRIVER_NAME, ID_POWER_ON, ID_POWER_STATE, ID_THERMAL,
};
