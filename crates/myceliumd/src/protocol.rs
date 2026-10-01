use mycelium_core::{DiscoveryProtocol, MyceliumError, Value};
use serde::{Deserialize, Serialize};

/// One JSON-RPC request (newline-delimited over the socket).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum Request {
    Hello,
    /// Registered drivers (builtin + Lua plugins).
    Drivers,
    /// Recognize + open a device. `driver` pins the class; otherwise each
    /// driver probes in order and the first match attaches.
    DeviceAdd {
        target: String,
        #[serde(default)]
        driver: Option<String>,
        #[serde(default)]
        username: Option<String>,
        /// NAME of an env var holding the password. Literals are rejected
        /// at the CLI so secrets don't cross the socket or hit the disk.
        #[serde(default)]
        password_env: Option<String>,
        #[serde(default)]
        key_path: Option<String>,
    },
    DeviceRemove {
        id: String,
    },
    DeviceList,
    DeviceDescribe {
        id: String,
    },
    DeviceCall {
        id: String,
        capability: String,
        #[serde(default)]
        params: serde_json::Map<String, serde_json::Value>,
        /// Explicit write opt-in.
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    /// Pull observations from every open device and merge the topology.
    Scan,
    Topology,
    DiscoveryScopeList,
    DiscoveryScopeSet {
        observer: String,
        protocols: Vec<DiscoveryProtocol>,
        segments: Vec<String>,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    DiscoveryScopeRemove {
        observer: String,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    AllocationList,
    AllocationImport {
        site: String,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    NetworkList,
    NetworkAdopt {
        name: String,
        site: String,
        vlan: u16,
        subnet: String,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    NetworkDrift {
        #[serde(default)]
        name: Option<String>,
    },
    /// Return the locally converged view of signed peer observations.
    PeerList,
    ReleaseList,
    ReleaseKeygen {
        path: String,
        #[serde(default)]
        write: bool,
    },
    ReleasePublish {
        binary: String,
        signing_key: String,
        version: String,
        channel: String,
        #[serde(default)]
        target: Option<String>,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    ReleasePublishSet {
        manifest: String,
        signing_key: String,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    AccessList,
    AccessKeygen {
        path: String,
        #[serde(default)]
        write: bool,
    },
    AccessPublish {
        statement: String,
        signing_key: String,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    /// Set durable human knowledge on exactly one discovered node.
    TopologyAnnotate {
        selector: String,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        kind: Option<String>,
        #[serde(default)]
        write: bool,
        #[serde(default)]
        dry_run: bool,
    },
    /// Plan one local SSH forward through an inventory gateway. The daemon
    /// returns only argv and an optional env-var name, never secret values.
    TunnelPlan {
        target: String,
        remote_port: u16,
        local_port: u16,
        #[serde(default)]
        via: Option<String>,
    },
    /// Resolve a managed device to a secret-free SSH execution plan.
    SshPlan {
        selector: String,
        #[serde(default)]
        username: Option<String>,
    },
    /// Resolve a device's interactive out-of-band console without sending
    /// credentials over RPC.
    ConsolePlan {
        id: String,
    },
    /// Persist state and exit.
    Shutdown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Machine-readable error class for callers that branch on it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

impl Response {
    pub fn ok(result: serde_json::Value) -> Self {
        Self {
            ok: true,
            result: Some(result),
            error: None,
            kind: None,
        }
    }

    pub fn err(e: &MyceliumError) -> Self {
        let kind = match e {
            MyceliumError::WritesNotPermitted(_) => "writes_not_permitted",
            MyceliumError::UnknownDevice(_) => "unknown_device",
            MyceliumError::UnknownCapability(_) => "unknown_capability",
            MyceliumError::Validation(_) => "validation",
            MyceliumError::Transport(_) => "transport",
            MyceliumError::Auth(_) => "auth",
            MyceliumError::Device { .. } => "device",
            MyceliumError::Plugin { .. } => "plugin",
            MyceliumError::Parse(_) => "parse",
            MyceliumError::Unsupported { .. } => "unsupported",
            MyceliumError::Io(_) => "io",
        };
        Self {
            ok: false,
            result: None,
            error: Some(e.to_string()),
            kind: Some(kind.into()),
        }
    }

    pub fn fail(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            result: None,
            error: Some(msg.into()),
            kind: Some("daemon".into()),
        }
    }
}

/// Coerce CLI `k=v` strings into typed values: try bool, int, then string.
pub fn coerce_param(v: &str) -> Value {
    match v {
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        _ => {
            if let Ok(i) = v.parse::<i64>() {
                Value::Int(i)
            } else if v.starts_with('{') || v.starts_with('[') {
                serde_json::from_str::<serde_json::Value>(v)
                    .map(|j| Value::from_json(&j))
                    .unwrap_or_else(|_| Value::Str(v.to_owned()))
            } else {
                Value::Str(v.to_owned())
            }
        }
    }
}
