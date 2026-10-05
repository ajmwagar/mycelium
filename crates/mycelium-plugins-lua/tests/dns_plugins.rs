use mycelium_core::{
    CredentialSet, Driver, ExecContext, Inventory, Params, RecordingTransport, Target, Transport,
    Value,
};
use mycelium_plugins_lua::Plugin;
use std::sync::Arc;

const NEXTDNS: &str = include_str!("../plugins/nextdns.lua");
const PIHOLE: &str = include_str!("../plugins/pihole.lua");

#[tokio::test]
async fn pihole_recognition_requires_v6() {
    for (version, expected) in [
        ("Core version is v6.3", true),
        ("Core version is v5.18", false),
        ("not pihole", false),
    ] {
        let transport = Arc::new(RecordingTransport::new());
        transport.reply("pihole 'version'", version);
        let plugin = Arc::new(Plugin::load(PIHOLE).unwrap());
        let driver = plugin.driver(Arc::new(move |_: Target, _: CredentialSet| {
            let transport = transport.clone();
            async move { Ok(transport as Arc<dyn Transport>) }
        }));
        assert_eq!(
            driver
                .recognizes(&Target::host("dns.example"), &CredentialSet::default())
                .await
                .unwrap(),
            expected
        );
    }
}

async fn attach(source: &str, transport: Arc<RecordingTransport>) -> (Inventory, String) {
    let plugin = Arc::new(Plugin::load(source).unwrap());
    let driver = plugin.driver(Arc::new(move |_: Target, _: CredentialSet| {
        let transport = transport.clone();
        async move { Ok(transport as Arc<dyn Transport>) }
    }));
    let inventory = Inventory::new();
    let id = driver
        .attach(
            &Target::host("dns.example"),
            &CredentialSet::default(),
            &inventory,
        )
        .await
        .unwrap();
    (inventory, id.to_string())
}

fn pihole_transport(list: &str) -> Arc<RecordingTransport> {
    let transport = Arc::new(RecordingTransport::new());
    transport.reply("pihole 'version'", "Core version is v6.3 (Latest: v6.3)\n");
    transport.reply("hostname", "dns-box\n");
    transport.reply("pihole 'deny' '--list'", list);
    transport.reply("pihole 'deny' 'ads.example'", "Added domain\n");
    transport
}

#[tokio::test]
async fn nextdns_projects_only_profiles_and_native_health() {
    let transport = Arc::new(RecordingTransport::new());
    transport.reply("nextdns 'version'", "nextdns version 1.46.0\n");
    transport.reply("hostname", "dns-box\n");
    transport.reply("nextdns 'status'", "running\n");
    transport.reply(
        "nextdns 'config' 'list'",
        "profile abc123\nprofile 10.1.0.0/16=def456\nother-secret do-not-project\n",
    );
    let (inventory, id) = attach(NEXTDNS, transport).await;
    let device = inventory.get(&id).unwrap();
    assert!(!device.capabilities().contains_key("dns.block"));
    let result = device
        .invoke(
            &ExecContext::readonly("nextdns.profiles"),
            "nextdns.profiles",
            Params::new(),
        )
        .await
        .unwrap();
    assert!(!format!("{:?}", result.output).contains("do-not-project"));
    assert!(format!("{:?}", result.output).contains("abc123"));
    device
        .invoke(
            &ExecContext::readonly("system.health"),
            "system.health",
            Params::new(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn pihole_write_gate_dry_run_and_verified_block() {
    let transport = pihole_transport("  [✓] Found 1 domain(s) in the exact denylist:\n    - \"ads.example\"\n      Groups: [0]\n");
    let (inventory, id) = attach(PIHOLE, transport.clone()).await;
    let device = inventory.get(&id).unwrap();
    let params = Params::from([("domain".into(), Value::Str("ads.example".into()))]);
    let before = transport.calls.lock().unwrap().len();
    assert!(device
        .invoke(
            &ExecContext::readonly("dns.block"),
            "dns.block",
            params.clone()
        )
        .await
        .is_err());
    let dry = ExecContext {
        capability: "dns.block".into(),
        allow_writes: false,
        dry_run: true,
    };
    device
        .invoke(&dry, "dns.block", params.clone())
        .await
        .unwrap();
    assert_eq!(transport.calls.lock().unwrap().len(), before);
    let write = ExecContext {
        capability: "dns.block".into(),
        allow_writes: true,
        dry_run: false,
    };
    let result = device.invoke(&write, "dns.block", params).await.unwrap();
    assert!(format!("{:?}", result.output).contains("true"));
    assert_eq!(
        device.capabilities()["dns.block"]
            .verification
            .as_ref()
            .unwrap()
            .capability,
        "dns.list-entries"
    );
    let before = transport.calls.lock().unwrap().len();
    for invalid in [
        "ads.example;reboot",
        "-option",
        "*.example",
        "a..example",
        "a.-b.example",
        "a.example\n",
    ] {
        let params = Params::from([("domain".into(), Value::Str(invalid.into()))]);
        assert!(device.invoke(&write, "dns.block", params).await.is_err());
    }
    assert_eq!(transport.calls.lock().unwrap().len(), before);
}

#[tokio::test]
async fn pihole_rejects_ambiguous_or_absent_confirmation() {
    for list in [
        "authentication required",
        "Found 2 domain(s) in the exact denylist:\n - \"ads.example\"",
        "No domains found in the exact denylist",
    ] {
        let (inventory, id) = attach(PIHOLE, pihole_transport(list)).await;
        let device = inventory.get(&id).unwrap();
        let write = ExecContext {
            capability: "dns.block".into(),
            allow_writes: true,
            dry_run: false,
        };
        assert!(device
            .invoke(
                &write,
                "dns.block",
                Params::from([("domain".into(), Value::Str("ads.example".into()))])
            )
            .await
            .is_err());
    }
}
