# mycelium
A sensing framework for your networks. Home, Cloud, anywhere.

Mesh / AI control over home IoT devices and networkign applicances.

No more Port Forwarding, Manual VLAN tagging, or firewall rules.

Secure by default, and only with justification.

# Architechture

1. Rust Core / Lua Plugins

2. Integrate / Interop / Don't replace unless nessecary

3. Anti-Abondonware, generalize the common, implement everywhere.

4. Secure by default. Intelligent. Restraint is good.

5. Multi-LAN/WAN

# UX

A control plane / CLI for your home network.

Integrate across, brands, support iPMi, bare metal integration across the board.

Network Topology Mapping / Viewing

## Early-boot paths and NBDE

Mycelium can evaluate whether observed topology supports an early-boot path
to Tang endpoints. It distinguishes direct, routed, and unverified paths; a
routed path remains a warning until initramfs addressing and firewall policy
are verified. Planning is read-only and does not execute Clevis:

```sh
mycelium boot-path <device> --target http://192.168.20.8:7500
mycelium nbde plan <device> \
  --tang http://192.168.20.8:7500 \
  --tang http://192.168.99.8:7500 \
  --threshold 2
```

Tang endpoints currently use literal IP addresses deliberately: boot-time DNS
is not assumed. A later enrollment workflow will call the system Clevis/Tang
tools and retain a passphrase recovery slot rather than reimplementing NBDE.

## Intelligent SSH hops

For a service reachable through an inventory gateway, Mycelium derives the
hop from the target's observed segment and gateway:

```sh
# Plan only.
mycelium tunnel 192.168.99.12:80 --local-port 8080

# Open in the foreground; Ctrl-C closes it.
mycelium tunnel 192.168.99.12:80 --local-port 8080 --write
```

The daemon returns SSH arguments and an environment-variable name only. The
secret stays in the CLI environment and is passed to `sshpass` via `SSHPASS`,
never argv. `--via DEVICE` overrides inference when multiple paths are valid.

SEIM (FIPS Compliant Syslogs)?

## Initial Targets

EdgeRunner Routers, ER-10X EdgeRunner Edge?

wifi management (guest networks)

NETGEAR Switch

Dell iPMIE

Ubiquti APs.

Pi-Hole?

## SSH observation points

Ordinary Linux hosts can contribute their interfaces, connected routes, and
neighbor tables without becoming network appliances themselves:

```sh
mycelium add pris --driver linux --user ajmwagar
mycelium add titan --driver linux --user avery
mycelium scan
```

The Linux driver runs a fixed, read-only `iproute2` probe over SSH. It uses
OpenSSH configuration and agent credentials when no password or key is given.
Each observer hostname is also its site identity, so overlapping private
networks are stored separately (`pris/192.168.1.0/24` and
`titan/192.168.1.0/24`) instead of producing false address conflicts.

## Redfish servers

Redfish management controllers expose identity, power state, and thermal
telemetry. Power-on is write-gated and supports dry-run:

```sh
mycelium add 192.168.20.11 --driver redfish --user Administrator --password-env ILO4_PASS
mycelium call ilo-mxq33702q8 server.power-state
mycelium call ilo-mxq33702q8 server.thermal
mycelium call ilo-mxq33702q8 server.power-on --write --dry-run
```

Controller passwords remain env-backed; inventory persists only the variable
name. Self-signed controller certificates are accepted, but transport remains
HTTPS-only.

## UniFi access points

Controller-managed UniFi APs expose their local management surface over SSH.
The driver reads identity, adoption status, radio/SSID state, and associated
stations. Controller reassignment and reboot are mutations and require both
`--write` and an optional dry run first:

```sh
mycelium add 192.168.99.11 --driver unifi --user "$AP_USER" --password-env AP_PASS
mycelium call <ap-id> unifi.status
mycelium call <ap-id> wlan.list-ssids
mycelium call <ap-id> wlan.list-stations
mycelium call <ap-id> unifi.set-inform \
  --param url=http://192.168.99.20:8080/inform --write --dry-run
```

The saved inventory contains the environment-variable name, never the AP
password. UniFi network-wide configuration remains controller-owned; the AP
driver is for observation, recovery, and explicit adoption operations.

# Initial Features

DNS Management, DHCP Management, VLAN Management (rules, etc.)

SEIM / Intrusion Management / Exfiltration monitoring.
