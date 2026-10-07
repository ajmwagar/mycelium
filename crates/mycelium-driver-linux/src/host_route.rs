//! NetworkManager owns persistence; reapply changes the active profile without
//! a link disconnect. Remove only our newly added route on an ordinary failure.
use mycelium_core::{host_route::HostRoute, MyceliumError, Params, Result};

pub fn config(params: &Params) -> Result<HostRoute> {
    let text = mycelium_core::required_str(params, "config")?;
    if text.len() > 1024 {
        return Err(MyceliumError::Validation(
            "route intent exceeds bound".into(),
        ));
    }
    let route: HostRoute = serde_json::from_str(text)
        .map_err(|_| MyceliumError::Validation("invalid host route intent".into()))?;
    route.validate().map_err(MyceliumError::Validation)?;
    Ok(route)
}

fn check(route: &HostRoute) -> String {
    format!(
        r#"
test "$(nmcli -g GENERAL.CON-UUID device show {interface})" = '{uuid}'
profile=$(nmcli -g ipv4.routes connection show '{uuid}' | tr -d '[:space:]')
case ",$profile," in *'ip={destination}/32,nh={gateway},'*|*'ip={destination}/32,nh={gateway}}}'*|*',{destination}/32{gateway},'*) ;; *) exit 1 ;; esac
ip -4 route show exact {destination}/32 | grep -Fq 'via {gateway} dev {interface}'
"#,
        interface = route.interface,
        uuid = route.connection_uuid,
        destination = route.destination,
        gateway = route.gateway
    )
}

pub fn verify_command(route: &HostRoute) -> String {
    format!(
        "set -eu\n{}\nprintf '%s\\n' '{{\"persistent\":true,\"configuration_matches\":true}}'",
        check(route)
    )
}

pub fn apply_command(route: &HostRoute) -> String {
    format!(
        r#"sudo -n sh -s <<'MYCELIUM_HOST_ROUTE'
set -eu
test "$(nmcli -g GENERAL.CON-UUID device show {interface})" = '{uuid}'
ip -4 route get {gateway} | grep -Fq ' dev {interface} '
defaults=$(ip -4 route show default)
if ( {check} ); then printf '%s\n' '{{"persistent":true,"configuration_matches":true}}'; exit 0; fi
# Refuse a conflicting profile route or a foreign kernel route at this target.
test -z "$(ip -4 route show exact {destination}/32)"
! nmcli -g ipv4.routes connection show '{uuid}' | grep -Fq '{destination}/32'
rollback() {{ nmcli connection modify '{uuid}' -ipv4.routes '{destination}/32 {gateway}' && nmcli device reapply {interface}; }}
nmcli connection modify '{uuid}' +ipv4.routes '{destination}/32 {gateway}'
trap 'rollback >&2' EXIT
nmcli device reapply {interface} >&2
{check}
test "$(ip -4 route show default)" = "$defaults"
trap - EXIT
printf '%s\n' '{{"persistent":true,"configuration_matches":true}}'
MYCELIUM_HOST_ROUTE
"#,
        interface = route.interface,
        uuid = route.connection_uuid,
        destination = route.destination,
        gateway = route.gateway,
        check = check(route)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shell_is_bounded_add_only_and_has_rollback() {
        let r:HostRoute=serde_json::from_str(r#"{"destination":"10.253.0.1","gateway":"192.168.1.39","interface":"enP7s7","connection_uuid":"c6cf14db-1c49-34e5-adb2-33badd79a9b0"}"#).unwrap();
        for script in [apply_command(&r), verify_command(&r)] {
            assert!(std::process::Command::new("sh")
                .args(["-n", "-c", &script])
                .status()
                .unwrap()
                .success());
            assert!(!script.contains("connection up"));
            assert!(!script.contains("0.0.0.0/0"));
        }
        let script = apply_command(&r);
        assert!(script.contains("-ipv4.routes"));
        assert!(script.contains("trap 'rollback"));
        assert!(script.contains("route show default"));
    }
}
