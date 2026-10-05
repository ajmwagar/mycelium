# Genesis: machine provisioning and first contact

Genesis is a standalone bare-metal provisioning service. It turns a physical
machine into an installed, encrypted, Mycelium-enrolled node. Mycelium remains
the infrastructure nervous system: it supplies observed topology, identity,
reachability, plans, and narrow driver operations. Genesis owns the boot
service and its durable provisioning state.

> Genesis births machines; Mycelium discovers, connects, and manages them.

Neither service is a mandatory runtime dependency of the other. Genesis has
its own CLI and API; `mycelium-driver-genesis` translates the shared boot
contracts into that API. A different PXE service can implement the same
capabilities without changing Mycelium's topology or intent model.

## Ownership boundary

| Concern | Owner |
| --- | --- |
| Machine identity, site, VLAN, switch attachment, reachability | Mycelium |
| Desired boot profile and reviewed plan | Shared boot contract |
| ProxyDHCP/DHCP integration, TFTP, iPXE and HTTP artifacts | Genesis |
| OS/image construction | Existing image/build tooling called by Genesis |
| Tang service operation and Clevis execution | System Tang/Clevis tools |
| Tang reachability and threshold viability | Mycelium |
| One-time enrollment claim and peer certificate | Mycelium authority |
| Installer execution, retry state and birth receipt | Genesis |
| Ongoing access, updates, topology and health | Mycelium |

Mycelium must not become a DHCP, TFTP, image-building, Tang, or general
configuration-management service. Genesis must not copy Mycelium's identity,
topology, access-control, or gossip implementation.

## Boot flow

1. Mycelium correlates the machine's MAC, architecture, site, physical port,
   and network. Ambiguous identity blocks planning.
2. An operator selects a versioned `BootProfileV1`. Mycelium produces a
   `BootIntentV1` and checks DHCP, VLAN, PXE, artifact, and Tang reachability.
3. Genesis materializes architecture-specific DHCP/ProxyDHCP and iPXE state.
   TFTP serves only the first-stage loader; signed kernels, initrds, installers,
   and manifests use HTTP.
4. The installer retrieves a short-lived bootstrap envelope over HTTPS. The
   envelope contains a single-use Mycelium claim, never a permanent peer key.
5. The installed system generates its peer key locally and exchanges the claim
   for a scoped peer identity. The claim is atomically consumed.
6. Mycelium converges the node's personal SSH/access policy and confirms health.
7. Clevis binds encrypted storage to the planned Tang policy while retaining a
   recovery slot. A reboot verifies unattended unlock and network reachability.
8. Genesis emits `BootReceiptV1`; Mycelium retains the resulting peer and health
   facts. The completed install intent no longer causes network boot.

The workflow is deterministic and resumable. Retrying a plan may reproduce the
same artifacts, but a consumed enrollment claim can never issue a second peer
identity.

## Enrollment security

The intended physical-PXE design binds first contact to:

- the boot-intent digest;
- expected site, hostname, role, and machine selector;
- a short expiry and use count of one;
- the expected Genesis service identity;
- an optional TPM attestation key or hardware fingerprint.

These are design requirements, not implemented claim fields. The existing
Mycelium peer invitation binds the peer name, site, roles, seed peers, expiry,
and remaining uses; CSR signing checks the exact expected common name. It does
not currently bind a boot-intent digest, MAC, TPM identity, or Genesis server.
The QEMU experiment transports that existing invitation using protected virtual
media. Physical PXE's initial authorization channel remains an explicit operator
choice; HTTPS alone does not authenticate the new machine. See
[physical first contact](genesis-first-contact.md) for the boundary and runbook.

Claims must not be placed in TFTP files, public iPXE scripts, kernel command lines,
or logs. Any HTTPS handoff must reuse the existing invitation lifecycle, not
introduce a parallel claim database or release a claim merely for knowing a MAC.
The peer private key is generated on the new machine and is never returned to
Genesis. TPM-backed systems may seal or generate that key and attach attestation
evidence. Systems without a TPM use a locally generated key with explicitly
lower identity confidence.

Discovery proves availability, not authority. Finding a Genesis, Tang, TFTP,
or HTTP endpoint does not authorize its use; the reviewed boot plan names the
trusted service identities and artifact digests.

## NBDE and recovery

Tang endpoints use literal boot-reachable addresses until early-boot DNS is
explicitly modeled. A threshold plan may span sites, but only paths proven
usable by the initramfs count as viable. Routed paths require gateway and
firewall verification.

Clevis binding occurs only after Mycelium enrollment and health verification.
The first implementation must preserve an operator recovery slot, test the
LUKS metadata backup, and perform a reboot/unlock verification before marking
the birth complete. Tang is an availability dependency, not a substitute for
recovery material.

## Driver contract

`mycelium-driver-genesis` should expose narrow, vendor-neutral capabilities:

- `boot.profiles`
- `boot.machine-status`
- `boot.plan`
- `boot.ensure-intent`
- `boot.cancel-intent`
- `boot.verify`
- `tang.advertisements`
- `tang.health`

Every mutation crosses the normal Mycelium plan/apply gate and has a read-only
postcondition. `boot.ensure-intent`, for example, verifies the machine match,
DHCP/ProxyDHCP result, architecture loader, manifest digest, and artifact
availability. Genesis returns structured state; the driver never parses human
display output.

## First delivery slices

1. Define and test `BootIntentV1`, `BootProfileV1`, and `BootReceiptV1` without
   implementing a server.
2. Build `genesisd` and `genesisctl` around a local manifest store and an HTTP
   artifact service. Keep DHCP behind an adapter.
3. Add a dnsmasq/ProxyDHCP adapter and x86_64 UEFI iPXE profile.
4. Add `mycelium-driver-genesis` plan/apply/verify behavior.
5. Add single-use Mycelium first-contact enrollment and expiry/replay tests.
6. Add Tang/Clevis binding, recovery-slot validation, and reboot verification.
7. Add Raspberry Pi firmware boot as a separate adapter; do not force it into
   the x86 PXE model.
8. Add Secure Boot signing and measured-boot evidence after the basic workflow
   is reproducible.

## Manual runbook parity

If automation fails, an operator must be able to inspect the rendered DHCP
entry, fetch and verify every artifact by digest, boot the generated iPXE script,
consume the enrollment claim, enroll Clevis, and inspect both the birth receipt
and Mycelium peer record. Genesis should emit those concrete artifacts and
commands as its plan output rather than hiding them in an agent workflow.
