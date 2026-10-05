# Genesis encrypted boot: Tang and Clevis

Status: design and acceptance criteria. The persistent-root QEMU experiment has
verified enrollment, signed self-update and native package rollback, **not**
encrypted-root provisioning or network unlock. Existing `mycelium nbde plan`
models reachability; it does not bind a disk or prove initramfs unlock.

## Ownership

Genesis installs the system and its boot configuration. cryptsetup owns LUKS;
Clevis owns network-bound unlock; an independently operated Tang service supplies
the network dependency. Mycelium discovers and plans boot reachability, enrolls
the resulting host and distributes authorized updates. Do not implement another
key server, credential store or encryption protocol inside Mycelium.

Encrypted installation is opt-in. A signed claim authorizes peer enrollment, not
disk destruction. Installing or modifying encrypted storage needs separate,
explicit disk intent and target validation. Public PXE identity is not sufficient
authorization. The first-contact trust choice is still recorded in
[genesis-first-contact.md](genesis-first-contact.md).

## First isolated test

Use a new disposable QEMU disk; leave the working edge guest and real hosts alone.

1. Validate the intended disk and install encrypted root with an independent
   recovery passphrase. Keep recovery material out of image artifacts, claims,
   logs, gossip and Git. Verify the recovery slot before enabling network unlock.
2. Install system Clevis/LUKS and initramfs integration. Configure early-boot
   networking for the actual boot interface; ordinary systemd-networkd configuration
   is not proof that networking exists before root unlock.
3. Enroll Mycelium through the existing trusted claim path. Verify host identity,
   reachability and enrolled health before binding Clevis.
4. Obtain and validate the expected Tang advertisement through a trusted channel;
   do not blindly accept an advertisement found by discovery. Use boot-reachable
   addresses until early-boot DNS has been independently tested.
5. Bind Clevis, rebuild and inspect the initramfs, then reboot without injecting a
   passphrase. Prove that root is an active encrypted mapping and that enrollment
   and host identity persisted.
6. Make Tang unavailable and prove recovery unlock through the console. Restore
   Tang and prove network unlock again. Recheck signed updates after both boots.

Threshold policies and independent Tang hosts follow this single-endpoint test.
Tang availability is not user authentication, device attestation, Secure Boot or
a compliance certification. An encrypted disk that can auto-unlock on its network
has a different threat model from one requiring a person at every boot.

## Existing host adoption

Adopt existing Deckard and Esper/NVR without reinstalling or altering disk slots.
First verify host identity, architecture, current Mycelium installation, native
service state and a verified management route. Preserve existing encryption and
recovery arrangements; assess them independently after enrollment.

Inspection on 2026-10-05 found saved DHCP identities for Deckard at
`192.168.20.12` and Esper at `192.168.30.12`. Those are saved observations, not
proof of current availability. The current `deckard` SSH alias resolved to a Mac
Studio, so it must not be used to enroll the Linux host without reconciliation.
The EdgeRouter jump tunnel opened using the saved credential mapping, but Deckard
port 2222 returned no route to host and Esper port 22 timed out. Neither machine
was changed or newly enrolled during that inspection.
