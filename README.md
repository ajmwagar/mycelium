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

# Initial Features

DNS Management, DHCP Management, VLAN Management (rules, etc.)

SEIM / Intrusion Management / Exfiltration monitoring.
