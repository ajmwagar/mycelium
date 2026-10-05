#![forbid(unsafe_code)]

//! Pure planning and verification for a dnsmasq-backed Genesis boot network.
//!
//! This crate never starts dnsmasq or changes an interface. It renders the
//! exact files an executor may apply and verifies observations afterward.

use std::{collections::BTreeMap, net::IpAddr, path::PathBuf};

use fpl_boot_contract::{BootArtifactKind, BootFirmware, BootIntentV1, BootProfileV1, MacAddress};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyDhcpSettings {
    pub interface: String,
    pub server_address: IpAddr,
    pub http_base_url: String,
    pub tftp_root: PathBuf,
    pub first_stage_filename: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterRequest {
    pub settings: ProxyDhcpSettings,
    pub intent: BootIntentV1,
    pub profile: BootProfileV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyDhcpPlan {
    pub intent_digest: String,
    pub profile_digest: String,
    pub machine: String,
    pub mac: MacAddress,
    pub dnsmasq_config: String,
    pub tftp: TftpPlan,
    pub http_files: BTreeMap<String, String>,
    pub postconditions: Vec<Postcondition>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TftpPlan {
    pub root: PathBuf,
    pub allowed_files: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Postcondition {
    ProxyDhcpOnly,
    InterfaceBound { interface: String },
    TftpAllowlist { files: Vec<String> },
    HttpFilePresent { path: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyDhcpObservation {
    pub dnsmasq_config: String,
    pub tftp_files: Vec<String>,
    pub http_files: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReport {
    pub satisfied: bool,
    pub checks: Vec<VerificationCheck>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationCheck {
    pub name: String,
    pub satisfied: bool,
    pub detail: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("invalid boot intent: {0}")]
    Intent(String),
    #[error("invalid boot profile: {0}")]
    Profile(String),
    #[error("intent profile `{intent}` does not match supplied profile `{profile}`")]
    ProfileMismatch { intent: String, profile: String },
    #[error("ProxyDHCP requires an explicit machine MAC selector")]
    MissingMac,
    #[error("dnsmasq adapter supports amd64 UEFI only, got {architecture}/{firmware:?}")]
    UnsupportedPlatform {
        architecture: String,
        firmware: BootFirmware,
    },
    #[error("profile must contain exactly one TFTP bootloader")]
    MissingBootloader,
    #[error("unsupported or unsafe adapter setting `{field}`: {value}")]
    UnsafeSetting { field: &'static str, value: String },
}

pub fn plan(request: &AdapterRequest) -> Result<ProxyDhcpPlan, AdapterError> {
    request
        .intent
        .validate()
        .map_err(|error| AdapterError::Intent(error.to_string()))?;
    request
        .profile
        .validate()
        .map_err(|error| AdapterError::Profile(error.to_string()))?;
    if request.intent.profile != request.profile.id {
        return Err(AdapterError::ProfileMismatch {
            intent: request.intent.profile.clone(),
            profile: request.profile.id.clone(),
        });
    }
    if !matches!(request.profile.architecture.as_str(), "amd64" | "x86_64")
        || request.profile.firmware != BootFirmware::Uefi
    {
        return Err(AdapterError::UnsupportedPlatform {
            architecture: request.profile.architecture.clone(),
            firmware: request.profile.firmware,
        });
    }
    let mac = request
        .intent
        .selector
        .mac
        .ok_or(AdapterError::MissingMac)?;
    validate_settings(&request.settings)?;

    let bootloader = request
        .profile
        .artifacts
        .get(&BootArtifactKind::Bootloader)
        .filter(|artifact| artifact.url.starts_with("tftp://"))
        .ok_or(AdapterError::MissingBootloader)?;
    let expected_tftp_url = format!(
        "tftp://{}/{}",
        request.settings.server_address, request.settings.first_stage_filename
    );
    if bootloader.url != expected_tftp_url {
        return Err(AdapterError::UnsafeSetting {
            field: "bootloader.url",
            value: bootloader.url.clone(),
        });
    }

    let mac_name = mac.to_string().replace(':', "-");
    let machine_path = format!("/v1/boot/{mac_name}.ipxe");
    let bootstrap_path = "/v1/boot/bootstrap.ipxe".to_owned();
    let mut http_files = BTreeMap::new();
    http_files.insert(
        bootstrap_path.clone(),
        render_bootstrap(&request.settings.http_base_url),
    );
    http_files.insert(machine_path.clone(), render_machine_script(request));

    let allowed_files = vec![request.settings.first_stage_filename.clone()];
    Ok(ProxyDhcpPlan {
        intent_digest: request.intent.digest(),
        profile_digest: request.profile.digest(),
        machine: request.intent.machine.clone(),
        mac,
        dnsmasq_config: render_dnsmasq(&request.settings, mac),
        tftp: TftpPlan {
            root: request.settings.tftp_root.clone(),
            allowed_files: allowed_files.clone(),
        },
        http_files,
        postconditions: vec![
            Postcondition::ProxyDhcpOnly,
            Postcondition::InterfaceBound {
                interface: request.settings.interface.clone(),
            },
            Postcondition::TftpAllowlist {
                files: allowed_files,
            },
            Postcondition::HttpFilePresent {
                path: bootstrap_path,
            },
            Postcondition::HttpFilePresent { path: machine_path },
        ],
    })
}

pub fn verify(plan: &ProxyDhcpPlan, observed: &ProxyDhcpObservation) -> VerificationReport {
    let mut checks = vec![
        check(
            "rendered configuration",
            observed.dnsmasq_config == plan.dnsmasq_config,
            "observed dnsmasq configuration matches the reviewed plan",
        ),
        check(
            "non-authoritative DHCP",
            observed
                .dnsmasq_config
                .lines()
                .any(|line| line.ends_with(",proxy"))
                && !observed
                    .dnsmasq_config
                    .lines()
                    .any(|line| line.starts_with("dhcp-range=") && !line.ends_with(",proxy")),
            "every DHCP range is ProxyDHCP-only",
        ),
        check(
            "TFTP allowlist",
            sorted(&observed.tftp_files) == sorted(&plan.tftp.allowed_files),
            "TFTP contains only the reviewed first-stage loader",
        ),
    ];
    for (path, content) in &plan.http_files {
        checks.push(check(
            &format!("HTTP file {path}"),
            observed.http_files.get(path) == Some(content),
            "HTTP boot file matches the reviewed plan",
        ));
    }
    VerificationReport {
        satisfied: checks.iter().all(|check| check.satisfied),
        checks,
    }
}

fn validate_settings(settings: &ProxyDhcpSettings) -> Result<(), AdapterError> {
    for (field, value) in [
        ("interface", settings.interface.as_str()),
        (
            "first_stage_filename",
            settings.first_stage_filename.as_str(),
        ),
    ] {
        if value.is_empty()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(AdapterError::UnsafeSetting {
                field,
                value: value.into(),
            });
        }
    }
    if !settings.http_base_url.starts_with("http://")
        || settings.http_base_url.ends_with('/')
        || settings
            .http_base_url
            .bytes()
            .any(|byte| byte.is_ascii_whitespace())
    {
        return Err(AdapterError::UnsafeSetting {
            field: "http_base_url",
            value: settings.http_base_url.clone(),
        });
    }
    if !settings.tftp_root.is_absolute() {
        return Err(AdapterError::UnsafeSetting {
            field: "tftp_root",
            value: settings.tftp_root.display().to_string(),
        });
    }
    Ok(())
}

fn render_dnsmasq(settings: &ProxyDhcpSettings, mac: MacAddress) -> String {
    format!(
        "# generated by genesis-dnsmasq; review before apply\n\
port=0\n\
bind-dynamic\n\
interface={}\n\
log-dhcp\n\
dhcp-range={},proxy\n\
dhcp-host={},set:genesis\n\
dhcp-match=set:efi-x86_64,option:client-arch,7\n\
dhcp-match=set:efi-x86_64,option:client-arch,9\n\
dhcp-userclass=set:ipxe,iPXE\n\
tag-if=set:genesis-first,tag:genesis,tag:efi-x86_64,tag:!ipxe\n\
pxe-service=tag:genesis-first,BC_EFI,Genesis iPXE,{},{}\n\
pxe-service=tag:genesis-first,x86-64_EFI,Genesis iPXE,{},{}\n\
dhcp-boot=tag:genesis,tag:efi-x86_64,tag:!ipxe,{},,{}\n\
dhcp-boot=tag:genesis,tag:ipxe,{}/v1/boot/bootstrap.ipxe\n\
enable-tftp\n\
tftp-root={}\n",
        settings.interface,
        settings.server_address,
        mac,
        settings.first_stage_filename,
        settings.server_address,
        settings.first_stage_filename,
        settings.server_address,
        settings.first_stage_filename,
        settings.server_address,
        settings.http_base_url,
        settings.tftp_root.display(),
    )
}

fn render_bootstrap(http_base_url: &str) -> String {
    format!(
        "#!ipxe\nchain {http_base_url}/v1/boot/${{net0/mac:hexhyp}}.ipxe || goto failed\nexit\n:failed\necho Genesis has no reviewed intent for ${{net0/mac}}\nshell\n"
    )
}

fn render_machine_script(request: &AdapterRequest) -> String {
    let kernel = request.profile.artifacts.get(&BootArtifactKind::Kernel);
    let initrd = request.profile.artifacts.get(&BootArtifactKind::Initrd);
    let mut script = format!(
        "#!ipxe\n# machine={} intent={} profile={}\n",
        request.intent.machine,
        request.intent.digest(),
        request.profile.digest()
    );
    if let Some(kernel) = kernel {
        script.push_str("kernel ");
        script.push_str(&kernel.url);
        for argument in &request.profile.kernel_arguments {
            script.push(' ');
            script.push_str(argument);
        }
        if initrd.is_some() {
            script.push_str(" initrd=initrd");
        }
        script.push('\n');
    }
    if let Some(initrd) = initrd {
        script.push_str(&format!("initrd --name initrd {}\n", initrd.url));
    }
    for kind in [
        BootArtifactKind::Installer,
        BootArtifactKind::RootFilesystem,
    ] {
        if let Some(artifact) = request.profile.artifacts.get(&kind) {
            script.push_str(&format!(
                "imgfetch --name {} {}\n",
                artifact_name(kind),
                artifact.url
            ));
        }
    }
    if kernel.is_some() {
        script.push_str("boot\n");
    } else {
        script.push_str("echo Profile has no directly bootable kernel\nshell\n");
    }
    script
}

fn artifact_name(kind: BootArtifactKind) -> &'static str {
    match kind {
        BootArtifactKind::Installer => "installer",
        BootArtifactKind::RootFilesystem => "rootfs",
        _ => "artifact",
    }
}

fn sorted(values: &[String]) -> Vec<&str> {
    let mut values = values.iter().map(String::as_str).collect::<Vec<_>>();
    values.sort_unstable();
    values
}

fn check(name: &str, satisfied: bool, detail: &str) -> VerificationCheck {
    VerificationCheck {
        name: name.into(),
        satisfied,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use fpl_boot_contract::{
        BootArtifact, BootIntentMode, BootMachineSelector, BootPostInstall, BootSecurityPolicy,
        SecureBootPolicy, BOOT_CONTRACT_SCHEMA_VERSION,
    };

    use super::*;

    fn request() -> AdapterRequest {
        AdapterRequest {
            settings: ProxyDhcpSettings {
                interface: "genesis0".into(),
                server_address: "192.0.2.1".parse().unwrap(),
                http_base_url: "http://192.0.2.1:8088".into(),
                tftp_root: "/srv/genesis/tftp".into(),
                first_stage_filename: "ipxe-x86_64.efi".into(),
            },
            intent: BootIntentV1 {
                schema_version: BOOT_CONTRACT_SCHEMA_VERSION,
                machine: "qemu-01".into(),
                selector: BootMachineSelector {
                    mac: Some(MacAddress([0x52, 0x54, 0, 0x12, 0x34, 0x56])),
                    ..BootMachineSelector::default()
                },
                profile: "fungos-qemu-amd64".into(),
                mode: BootIntentMode::InstallOnce,
                network: "genesis-isolated".into(),
                security: BootSecurityPolicy {
                    secure_boot: SecureBootPolicy::Disabled,
                    tang: None,
                },
                post_install: BootPostInstall::default(),
            },
            profile: BootProfileV1 {
                schema_version: BOOT_CONTRACT_SCHEMA_VERSION,
                id: "fungos-qemu-amd64".into(),
                architecture: "amd64".into(),
                firmware: BootFirmware::Uefi,
                artifacts: BTreeMap::from([
                    (
                        BootArtifactKind::Bootloader,
                        BootArtifact {
                            url: "tftp://192.0.2.1/ipxe-x86_64.efi".into(),
                            sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                .into(),
                        },
                    ),
                    (
                        BootArtifactKind::Kernel,
                        BootArtifact {
                            url: "http://192.0.2.1:8088/v1/artifacts/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                                .into(),
                            sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                                .into(),
                        },
                    ),
                    (
                        BootArtifactKind::Initrd,
                        BootArtifact {
                            url: "http://192.0.2.1:8088/v1/artifacts/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                                .into(),
                            sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                                .into(),
                        },
                    ),
                ]),
                kernel_arguments: vec!["console=ttyS0".into()],
            },
        }
    }

    #[test]
    fn renders_non_authoritative_machine_scoped_plan() {
        let request = request();
        let plan = plan(&request).unwrap();
        assert!(plan.dnsmasq_config.contains("dhcp-range=192.0.2.1,proxy"));
        assert!(plan.dnsmasq_config.contains("port=0"));
        assert_eq!(plan.tftp.allowed_files, ["ipxe-x86_64.efi"]);
        assert_eq!(plan.http_files.len(), 2);
        assert!(plan
            .http_files
            .contains_key("/v1/boot/52-54-00-12-34-56.ipxe"));
        assert!(plan
            .http_files
            .values()
            .all(|content| !content.contains("aaaaaaaaaaaaaaaa")));
        assert!(plan
            .http_files
            .values()
            .any(|content| content
                .contains("initrd --name initrd http://192.0.2.1:8088/v1/artifacts/")));
    }

    #[test]
    fn rejects_tftp_for_anything_but_the_reviewed_loader() {
        let mut request = request();
        request
            .profile
            .artifacts
            .get_mut(&BootArtifactKind::Kernel)
            .unwrap()
            .url = "tftp://192.0.2.1/vmlinuz".into();
        assert!(matches!(plan(&request), Err(AdapterError::Profile(_))));
    }

    #[test]
    fn verification_fails_on_extra_tftp_content() {
        let plan = plan(&request()).unwrap();
        let mut observation = ProxyDhcpObservation {
            dnsmasq_config: plan.dnsmasq_config.clone(),
            tftp_files: plan.tftp.allowed_files.clone(),
            http_files: plan.http_files.clone(),
        };
        assert!(verify(&plan, &observation).satisfied);
        observation.tftp_files.push("vmlinuz".into());
        assert!(!verify(&plan, &observation).satisfied);
    }
}
