//! Lua plugin host for mycelium.
//!
//! # The ABI (one-way door, see docs/adr/0002)
//!
//! A plugin file defines a single global table:
//!
//! ```lua
//! plugin = {
//!   name  = "er-dns",           -- unique id; the driver is `lua:er-dns`
//!   kind  = "dns-filter",       -- router|switch|access-point|bmc|dns-filter|other
//!   match = function(target)    -- optional: {address="10.0.7.1", port=22} -> bool
//!     return target.address:match("^10%.") ~= nil
//!   end,
//!   capabilities = function()   -- called once at attach; declared data
//!     return {
//!       { id = "system.identify", description = "who am I", mutation = false,
//!         returns = "map {vendor, model, firmware, hostname}" },
//!       { id = "dns.block", description = "sinkhole a domain", mutation = true,
//!         params = { { name = "domain", ty = "string", docs = "e.g. ads.example" } } },
//!     }
//!   end,
//!   exec = function(cap, params, ctx)
//!     -- ctx   = { dry_run = bool, device = { id, kind, address } }
//!     -- pure:            return { result = <json value> }
//!     -- device work:     return { commands = { "show …" }, parse = "parse_fn" }
//!     -- opt-out of fail-on-nonzero: { ignore_errors = true }
//!   end,
//!   parse_fn = function(outputs, params)   -- named by `parse`
//!     return { result = … }
//!   end,
//! }
//! ```
//!
//! Plugins never touch sockets, files, or the wall clock: they *declare*
//! commands, and the Rust host runs them through a [`Transport`] — after
//! the write-gate/dry-run checks in `core::Device::invoke`, which every
//! plugin call passes through. Control flow stays deterministic (tenet #7);
//! the sandbox removes os/io/debug/require (defense in depth).

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;

use async_trait::async_trait;
use mlua::{serde::LuaSerdeExt, FromLua, IntoLua, Lua, Table, Value as LuaValue};
use mycelium_core::{
    CapResult, CapSpec, CredentialSet, Device, DeviceId, DeviceKind, DeviceMeta, Driver,
    ExecContext, Inventory, MyceliumError, Params, Result, Target, Transport, Value, ID_IDENTIFY,
};
use tokio::sync::Mutex;

/// JSON<->Lua bridge: serde_json::Value is *the* wire format at this seam,
/// so plugin authors see plain objects, never Rust enum tag noise.
struct JsonBridge(serde_json::Value);

impl IntoLua for JsonBridge {
    fn into_lua(self, lua: &Lua) -> mlua::Result<LuaValue> {
        use serde::Serialize;
        self.0.serialize(mlua::serde::Serializer::new(lua))
    }
}

impl FromLua for JsonBridge {
    fn from_lua(value: LuaValue, _lua: &Lua) -> mlua::Result<Self> {
        use serde::Deserialize;
        serde_json::Value::deserialize(mlua::serde::Deserializer::new(value)).map(JsonBridge)
    }
}

impl JsonBridge {
    fn to_core(v: &serde_json::Value) -> Value {
        Value::from_json(v)
    }
}

fn err(plugin: &str, e: &mlua::Error) -> MyceliumError {
    MyceliumError::Plugin { plugin: plugin.to_owned(), message: e.to_string() }
}

/// Fresh sandboxed instance with the plugin chunk executed. One per open
/// device: `mlua::Lua` is not shareable across threads, and per-device
/// globals keep plugin state from bleeding between appliances.
fn instantiate(source: &str, name: &str) -> Result<Lua> {
    let lua = Lua::new();
    {
        // Remove dangerous stdlib entries before loading user code.
        const DANGEROUS: &[&str] =
            &["os", "io", "debug", "load", "dofile", "loadfile", "require", "package"];
        let keys: Vec<LuaValue> = lua
            .globals()
            .pairs::<LuaValue, LuaValue>()
            .filter_map(|kv| kv.ok())
            .map(|(k, _)| k)
            .collect();
        for k in keys {
            if let LuaValue::String(s) = &k {
                if DANGEROUS.contains(&s.to_string_lossy().as_str()) {
                    let _ = lua.globals().set(s.clone(), LuaValue::Nil);
                }
            }
        }
    }
    let chunk = lua.load(source).set_name(name).into_function().map_err(|e| err(name, &e))?;
    chunk.call::<()>(()).map_err(|e| err(name, &e))?;
    Ok(lua)
}

fn plugin_table(lua: &Lua, name: &str) -> Result<Table> {
    lua.globals().get::<Table>("plugin").map_err(|e| err(name, &e))
}

/// A validated plugin, ready to open devices. Validation happens at load
/// (fail loud at boot, not at first use).
pub struct Plugin {
    pub name: String,
    pub kind: DeviceKind,
    pub source: Arc<str>,
    has_match: bool,
}

impl Plugin {
    pub fn load(source: impl Into<Arc<str>>) -> Result<Self> {
        let source: Arc<str> = source.into();
        let lua = instantiate(&source, "<new>")?;
        let plugin = plugin_table(&lua, "<new>")?;
        let get_str = |key: &str| -> Result<String> {
            plugin.get::<String>(key).map_err(|_| MyceliumError::Plugin {
                plugin: "<new>".into(),
                message: format!("`plugin.{key}` must be a string"),
            })
        };
        let name = get_str("name")?;
        let kind_s = get_str("kind")?;
        let kind = serde_json::from_value::<DeviceKind>(serde_json::Value::String(kind_s.clone()))
            .map_err(|_| MyceliumError::Plugin {
                plugin: name.clone(),
                message: format!("unknown plugin.kind `{kind_s}`"),
            })?;
        for f in ["capabilities", "exec"] {
            if plugin.get::<mlua::Function>(f).is_err() {
                return Err(MyceliumError::Plugin {
                    plugin: name.clone(),
                    message: format!("`plugin.{f}` must be a function"),
                });
            }
        }
        let has_match = plugin.get::<mlua::Function>("match").is_ok();
        Ok(Self { name, kind, source, has_match })
    }

    pub fn driver(self: Arc<Self>, connect: Arc<dyn Connect>) -> LuaDriver {
        LuaDriver::new(self, connect)
    }

    fn declared_caps(&self, lua: &Lua) -> Result<BTreeMap<String, CapSpec>> {
        let plugin = plugin_table(lua, &self.name)?;
        let f: mlua::Function = plugin.get("capabilities").expect("validated at load");
        let out: LuaValue = f.call(()).map_err(|e| err(&self.name, &e))?;
        let json: serde_json::Value =
            lua.from_value(out).map_err(|e| err(&self.name, &e))?;
        let specs: Vec<CapSpec> = serde_json::from_value(json).map_err(|e| {
            MyceliumError::Plugin {
                plugin: self.name.clone(),
                message: format!("capabilities() must return declared CapSpec rows: {e}"),
            }
        })?;
        let mut map = BTreeMap::new();
        for mut spec in specs {
            if spec.id.is_empty() {
                return Err(MyceliumError::Plugin {
                    plugin: self.name.clone(),
                    message: "every declared capability needs an `id`".into(),
                });
            }
            let id = std::mem::take(&mut spec.id);
            map.insert(id, spec);
        }
        Ok(map)
    }
}

/// Opens transports for plugin devices. The daemon injects real
/// connectables (SSH etc.); tests inject canned transports.
#[async_trait]
pub trait Connect: Send + Sync {
    async fn connect(&self, target: &Target, creds: &CredentialSet) -> Result<Arc<dyn Transport>>;
}

/// Blanket: plain async closures work as connectors.
#[async_trait]
impl<F, Fut> Connect for F
where
    F: Fn(Target, CredentialSet) -> Fut + Send + Sync,
    Fut: Future<Output = Result<Arc<dyn Transport>>> + Send,
{
    async fn connect(&self, target: &Target, creds: &CredentialSet) -> Result<Arc<dyn Transport>> {
        (self)(target.clone(), creds.clone()).await
    }
}

pub struct LuaDriver {
    plugin: Arc<Plugin>,
    connect: Arc<dyn Connect>,
    driver_name: String,
}

impl LuaDriver {
    pub fn new(plugin: Arc<Plugin>, connect: Arc<dyn Connect>) -> Self {
        let driver_name = format!("lua:{}", plugin.name);
        Self { plugin, connect, driver_name }
    }
}

#[async_trait]
impl Driver for LuaDriver {
    fn name(&self) -> &str {
        &self.driver_name
    }

    async fn recognizes(&self, target: &Target, _creds: &CredentialSet) -> Result<bool> {
        if !self.plugin.has_match {
            return Ok(false);
        }
        let lua = instantiate(&self.plugin.source, &self.plugin.name)?;
        let plugin = plugin_table(&lua, &self.plugin.name)?;
        let f: mlua::Function = plugin.get("match").expect("checked");
        let desc = serde_json::to_value(match target {
            Target::Host { host, port } => serde_json::json!({"address": host, "port": port.unwrap_or(0)}),
            Target::Subnet { network } => serde_json::json!({"subnet": network}),
        })
        .expect("infallible");
        let arg = JsonBridge(desc);
        let hit: bool = f.call(arg).map_err(|e| err(&self.plugin.name, &e))?;
        Ok(hit)
    }

    async fn attach(
        &self,
        target: &Target,
        creds: &CredentialSet,
        inventory: &Inventory,
    ) -> Result<DeviceId> {
        let transport = self.connect.connect(target, creds).await?;
        let lua = instantiate(&self.plugin.source, &self.plugin.name)?;
        let caps = self.plugin.declared_caps(&lua)?;
        if !caps.contains_key(ID_IDENTIFY) {
            return Err(MyceliumError::Plugin {
                plugin: self.plugin.name.clone(),
                message: format!("plugins must declare `{ID_IDENTIFY}` so attach() can name the device"),
            });
        }

        let address = match target {
            Target::Host { host, port } => format!("{host}:{}", port.unwrap_or(0)),
            Target::Subnet { network } => network.clone(),
        };
        let device = LuaDevice {
            lua: Arc::new(Mutex::new(lua)),
            transport,
            plugin: self.plugin.clone(),
            meta: std::sync::OnceLock::new(),
            caps: std::sync::Mutex::new(Some(caps)),
        };
        // Identify via the plugin's own declared capability. Build meta
        // through a temporary invocation context.
        let ctx = ExecContext::readonly(ID_IDENTIFY);
        let out = device.invoke(&ctx, ID_IDENTIFY, Params::new()).await?;
        let map = match &out.output {
            Value::Map(m) => m.clone(),
            _ => Params::new(),
        };
        let slug = |s: &str| {
            s.replace(|c: char| !(c.is_ascii_alphanumeric()), "-").trim_matches('-').to_owned()
        };
        let id = DeviceId::new(format!(
            "{}-{}",
            slug(map.get("hostname").and_then(|v| v.as_str()).unwrap_or("device")),
            slug(&self.plugin.name)
        ));
        let meta = DeviceMeta {
            id: id.clone(),
            kind: self.plugin.kind,
            driver: self.plugin.name.clone(),
            vendor: map.get("vendor").and_then(|v| v.as_str()).map(str::to_owned),
            model: map.get("model").and_then(|v| v.as_str()).map(str::to_owned),
            firmware: map.get("firmware").and_then(|v| v.as_str()).map(str::to_owned),
            address,
        };
        let _ = device.meta.set(meta);
        inventory.add(Arc::new(device));
        Ok(id)
    }
}

pub struct LuaDevice {
    lua: Arc<Mutex<Lua>>,
    transport: Arc<dyn Transport>,
    plugin: Arc<Plugin>,
    meta: std::sync::OnceLock<DeviceMeta>,
    caps: std::sync::Mutex<Option<BTreeMap<String, CapSpec>>>,
}

impl LuaDevice {
    fn caps(&self) -> BTreeMap<String, CapSpec> {
        let guard = self.caps.lock().expect("caps poisoned");
        guard.clone().unwrap_or_default()
    }

    /// Available once attach() has identified the device; absent during
    /// the bootstrap identify invocation itself.
    fn meta_opt(&self) -> Option<&DeviceMeta> {
        self.meta.get()
    }
}

#[async_trait]
impl Device for LuaDevice {
    fn meta(&self) -> &DeviceMeta {
        self.meta.get().expect("meta set before device is shared")
    }

    fn capabilities(&self) -> BTreeMap<String, CapSpec> {
        self.caps()
    }

    async fn exec(&self, ctx: &ExecContext, cap: &str, params: Params) -> Result<CapResult> {
        // 1. Ask the plugin what to do (pure Lua; no device I/O here).
        let plan: serde_json::Value = {
            let guard = self.lua.lock().await;
            let lua = &*guard;
            let plugin = plugin_table(lua, &self.plugin.name)?;
            let exec: mlua::Function = plugin
                .get("exec")
                .expect("capabilities/exec validated at load");
            let m = self.meta_opt();
            let c = serde_json::json!({
                "dry_run": ctx.dry_run,
                "device": {
                    "id": m.map(|x| x.id.to_string()).unwrap_or_else(|| "pending".into()),
                    "kind": m.map(|x| x.kind.to_string()).unwrap_or_else(|| self.plugin.kind.to_string()),
                    "address": m.map(|x| x.address.clone()).unwrap_or_default(),
                },
            });
            let out: LuaValue = exec
                .call((cap.to_owned(), JsonBridge(Value::Map(params.clone()).to_json()), JsonBridge(c)))
                .map_err(|e| err(&self.plugin.name, &e))?;
            lua.from_value(out).map_err(|e| err(&self.plugin.name, &e))?
        };

        let commands: Vec<String> = plan
            .get("commands")
            .and_then(|c| c.as_array())
            .map(|a| a.iter().map(|s| s.as_str().unwrap_or_default().to_owned()).collect())
            .unwrap_or_default();

        // 2. Dry-run never touches the transport: the plan *is* the output.
        if ctx.dry_run && !commands.is_empty() {
            return Ok(CapResult::dry_run(Value::List(
                commands.into_iter().map(Value::Str).collect(),
            )));
        }

        // 3. Run the declared commands through the host transport.
        let ignore_errors = plan.get("ignore_errors").and_then(|v| v.as_bool()) == Some(true);
        let mut outputs = Vec::new();
        for cmd in &commands {
            let out = self.transport.exec(cmd).await?;
            if !out.success() && !ignore_errors {
                return Err(MyceliumError::Device {
                    exit_code: out.exit_code,
                    stderr: out.stderr.trim().to_owned(),
                });
            }
            outputs.push(serde_json::Value::String(out.stdout));
        }

        // 4. Pure result, or hand outputs to the named parse function.
        let parse_name = plan.get("parse").and_then(|p| p.as_str()).map(str::to_owned);
        match (commands.is_empty(), parse_name) {
            (true, _) => result_from_plan(&self.plugin, &plan),
            (false, None) => Ok(CapResult::ok(Value::List(
                outputs.into_iter().map(|o| Value::from_json(&o)).collect(),
            ))),
            (false, Some(name)) => {
                let params_json = Value::Map(params.clone()).to_json();
                let guard = self.lua.lock().await;
                let plugin = plugin_table(&guard, &self.plugin.name)?;
                let parse: mlua::Function = plugin.get(name.as_str()).map_err(|e| {
                    MyceliumError::Plugin {
                        plugin: self.plugin.name.clone(),
                        message: format!("parse function `{name}` missing: {e}"),
                    }
                })?;
                let out: LuaValue = parse
                    .call((JsonBridge(serde_json::Value::Array(outputs)), JsonBridge(params_json)))
                    .map_err(|e| err(&self.plugin.name, &e))?;
                let json: serde_json::Value =
                    guard.from_value(out).map_err(|e| err(&self.plugin.name, &e))?;
                result_from_plan(&self.plugin, &json)
            }
        }
    }
}

fn result_from_plan(plugin: &Plugin, plan: &serde_json::Value) -> Result<CapResult> {
    if plan.get("ok").and_then(|v| v.as_bool()) == Some(false) {
        return Err(MyceliumError::Plugin {
            plugin: plugin.name.clone(),
            message: plan
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("plugin reported failure")
                .to_owned(),
        });
    }
    let output = plan.get("result").cloned().unwrap_or(serde_json::Value::Null);
    Ok(CapResult {
        ok: true,
        output: JsonBridge::to_core(&output),
        message: plan.get("message").and_then(|m| m.as_str()).map(str::to_owned),
        dry_run: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mycelium_core::RecordingTransport;

    const GUEST: &str = include_str!("../examples/guest_dns.lua");

    fn fixture() -> (Arc<Plugin>, Arc<RecordingTransport>) {
        let transport = Arc::new(RecordingTransport::new());
        let plugin = Arc::new(Plugin::load(GUEST).unwrap());
        (plugin, transport)
    }

    #[tokio::test]
    async fn attaches_and_identifies_through_lua() {
        let (plugin, transport) = fixture();
        let t: Arc<dyn Transport> = transport.clone();
        let driver = plugin.clone().driver(Arc::new(move |_target: Target, _creds| {
            let t = t.clone();
            async move { Ok(t.clone()) }
        }));
        let inv = Inventory::new();
        let creds = CredentialSet::default().with_user("u");
        let id = driver
            .attach(&Target::host("10.0.0.9"), &creds, &inv)
            .await
            .unwrap();
        assert_eq!(id.to_string(), "gh0st-guest");
        let dev = inv.get(&id.to_string()).unwrap();
        let meta = dev.meta();
        assert_eq!(meta.vendor.as_deref(), Some("Test"));
        assert_eq!(meta.model.as_deref(), Some("guestbox"));
        assert_eq!(meta.driver, "guest");
        assert!(dev.capabilities().contains_key("dns.block"));
    }

    #[tokio::test]
    async fn match_is_pure_lua_on_target_desc() {
        let (plugin, _transport) = fixture();
        let driver = plugin.driver(Arc::new(|_: Target, _| async { panic!("no connect for match") }));
        assert!(driver.recognizes(&Target::Host { host: "x".into(), port: Some(8053) }, &CredentialSet::default()).await.unwrap());
        assert!(!driver.recognizes(&Target::host("x"), &CredentialSet::default()).await.unwrap());
    }

    #[tokio::test]
    async fn commands_run_through_host_transport() {
        let (plugin, transport) = fixture();
        transport.reply("list", "a.com\nb.com\n");
        transport.reply("block ads.example", "");
        let t: Arc<dyn Transport> = transport.clone();
        let driver = plugin.driver(Arc::new(move |_: Target, _| {
            let t = t.clone();
            async move { Ok(t.clone()) }
        }));
        let inv = Inventory::new();
        let id = driver.attach(&Target::host("h"), &CredentialSet::default(), &inv).await.unwrap();
        let dev = inv.get(&id.to_string()).unwrap();

        let ctx = ExecContext::readonly("dns.list");
        let res = dev.invoke(&ctx, "dns.list", Params::new()).await.unwrap();
        assert_eq!(
            res.output,
            Value::List(vec![Value::Str("a.com".into()), Value::Str("b.com".into())])
        );

        // write gate: mutation without allow_writes never reaches Lua
        let gated = ExecContext { capability: "dns.block".into(), allow_writes: false, dry_run: false };
        let err = dev.invoke(&gated, "dns.block", params_internal("domain", "ads.example")).await.unwrap_err();
        assert!(matches!(err, MyceliumError::WritesNotPermitted(_)));
        assert!(!transport.calls.lock().unwrap().iter().any(|c| c.starts_with("block ")));

        // ...and opt-in runs the declared command
        let opted = ExecContext { capability: "dns.block".into(), allow_writes: true, dry_run: false };
        dev.invoke(&opted, "dns.block", params_internal("domain", "ads.example")).await.unwrap();
        assert!(transport.calls.lock().unwrap().iter().any(|c| c == "block ads.example"));
    }

    #[tokio::test]
    async fn dry_run_returns_plan_without_touching_transport() {
        let (plugin, transport) = fixture();
        let t: Arc<dyn Transport> = transport.clone();
        let driver = plugin.driver(Arc::new(move |_: Target, _| {
            let t = t.clone();
            async move { Ok(t.clone()) }
        }));
        let inv = Inventory::new();
        let id = driver.attach(&Target::host("h"), &CredentialSet::default(), &inv).await.unwrap();
        let dev = inv.get(&id.to_string()).unwrap();
        let ctx = ExecContext { capability: "dns.block".into(), allow_writes: true, dry_run: true };
        let res = dev.invoke(&ctx, "dns.block", params_internal("domain", "ads.example")).await.unwrap();
        assert!(res.dry_run);
        assert_eq!(res.output, Value::List(vec![Value::Str("block ads.example".into())]));
        assert!(transport.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn sandbox_denies_stdlib() {
        let lua = instantiate(
            r#"
plugin = { name = "evil", kind = "other",
  capabilities = function() return {} end,
  exec = function() return { result = pcall(function() return io end) } end }
"#,
            "evil",
        )
        .unwrap();
        let io: LuaValue = lua.globals().get("io").unwrap();
        assert!(matches!(io, LuaValue::Nil));
    }

    #[test]
    fn load_validates_shape() {
        assert!(Plugin::load("plugin = { name = 'x' }").is_err());
        assert!(Plugin::load("local notglobal = {}").is_err());
        let bad_kind = Plugin::load(
            "plugin = { name = 'x', kind = 'toaster', capabilities = function() return {} end, exec = function() end }",
        );
        assert!(bad_kind.is_err());
    }

    fn params_internal(k: &str, v: &str) -> Params {
        Params::from_iter([(k.to_owned(), Value::Str(v.to_owned()))])
    }
}
