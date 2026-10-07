# Isolated QEMU first-boot runbook

## Persistent edge update qualification

For an already disk-installed guest, detach the claim envelope before testing
reboots. Retain the existing enrollment; do not issue another claim. Record
hashes of `pki/node.pem`, `peer.key`, `/etc/machine-id`, and the SSH host public
key beneath the private Mycelium home, then compare them after reboot.

`/usr/local/bin/mycelium` dispatches to `$MYCELIUM_HOME/bin/mycelium` once
enrolled, with `/usr/libexec/mycelium-bootstrap` reserved for first boot. This
keeps interactive commands on the same executable as the managed daemon after
self-updates. The persisted update policy selects the distribution channel;
`MYCELIUM_UPDATE_CHANNEL` is only the fallback before that policy exists.
Malformed or unreadable policy is an error, not permission to use a fallback.

Qualify updates on a guest-only channel with a stable node-ID selector. Keep
unrelated assignments manual and keep compositor updates gated. Publish signed
metadata with the existing release authority; never move its private key into
the guest. A self-update proof requires a different installed SHA-256, completed
peer download, automatic activation, and healthy supervised restart—not merely
arrival of a manifest. Native application qualification additionally requires
the package's PID/digest-bound readiness check and verified restoration of the
previous executable after an intentionally failing candidate.

If bootstrapping an older updater, a verified candidate CLI may run
`update apply --channel CHANNEL --path /var/lib/mycelium/bin/mycelium --write`
after signed metadata has arrived and `releases seed` has verified its bytes.
The explicit destination is essential: without it a candidate CLI would update
its own temporary path. This bootstrap is not an automatic-distribution proof.

During activation, the complete daemon readiness probe retries within ten
seconds, including transient failures after connection, and bounds a silent RPC.
It still requires the socket PID to match the supervisor. Failed candidates
restore the previous executable; the reported error retains the failing probe.

After qualification, confirm `mycelium-update.timer` is enabled and active,
the enrolled identity is unchanged, and the edge units recover. Record failures
and pending checks explicitly. Do not clean up unrelated publisher daemons or
change fleet update policy to make an isolated guest check pass.

## Prerequisites

Use an x86_64 Linux KVM host with QEMU, OVMF, dnsmasq, iPXE, `jq`, `cpio`, a
static BusyBox, and the Rust workspace. The proven host is Agora-One. Keep all
runtime state beneath `~/.cache/fungos-qemu`; build artifacts belong beneath
`~/.cache/fungos-build`.

## Build and plan

1. Build and inspect `fungOS/base` using its runbook.
2. Build the QEMU initramfs with `scripts/build-initramfs.sh`, supplying the
   base tar, `rootfs-overlay`, and output path.
3. Calculate SHA-256 for the iPXE loader, kernel, base tar, and initramfs.
4. Update `first-boot.request.json` with those observed digests and the isolated
   server address.
5. Run `genesis-dnsmasq plan` and review the complete JSON before applying it.
6. Import the kernel and initramfs with `genesisctl artifact put`; install the
   two rendered scripts with `genesisctl boot put`.

Do not extract JSON strings with `jq -r`: it appends a newline. Use `jq -j` so
the applied file remains byte-identical to the reviewed plan.

## Isolated runtime

1. Create a bridge named `genesis0` at `192.0.2.1/24` and a persistent TAP
   named `genesis-tap`, owned by the invoking user. Attach only that TAP. Never
   attach a physical interface.
2. Start a lease-only dnsmasq from `lease-dnsmasq.conf`.
3. Validate and start the reviewed Genesis ProxyDHCP configuration. Its TFTP
   root must contain only `ipxe-amd64.efi`.
4. Start `genesisd` on `192.0.2.1:8088`; fetch `/health`, both iPXE files, and
   both digest-pinned artifacts before starting the guest.
5. Create a sparse disposable disk:

   ```console
   qemu-img create -f qcow2 ~/.cache/fungos-qemu/fungos-qemu-01.qcow2 8G
   ```

6. Boot OVMF/Q35 with KVM, 2 GiB RAM, the qcow2 disk, `genesis-tap`, MAC
   `52:54:00:12:34:56`, serial output, and network-first boot order.
7. Success requires `NBP file downloaded successfully`, the Genesis HTTP boot
   URL, `fungOS initramfs entering systemd`, `FUNGOS_QEMU_NETWORK_OK` with a
   global address, and `FUNGOS_QEMU_BOOT_OK` in the serial log.
8. Construct a `ProxyDhcpObservation` from the applied bytes and run
   `genesis-dnsmasq verify`; all postconditions must pass.

## Cleanup

1. Stop the QEMU process by its exact `fungos-genesis-first-boot` name.
2. Stop only the PID files created for Genesis, ProxyDHCP, and lease-only DHCP.
3. Delete `genesis-tap`, then `genesis0`.
4. Confirm both interfaces and all named processes are absent.
5. Retain or explicitly remove the qcow2, serial log, plan, observation, and
   Genesis state. They are evidence and are not deleted automatically.

## One-time peer enrollment

Build Mycelium on the Linux host for `x86_64-unknown-linux-musl`. Verify it
executes inside the Debian root filesystem before passing its absolute path as
`MYCELIUM_BINARY` to `build-initramfs.sh`. A binary linked to the host's newer
glibc may boot successfully into Linux but fail before starting enrollment.

Issue a peer pairing claim with a reachable authority and mesh seed. Store the
printed claim outside the repository in a mode-0600 file, then run:

```sh
./scripts/build-claim-envelope.sh /secure/claim /secure/claim-envelope.img
```

Delete the plaintext file after creating the image. Attach the image to the
guest using a read-only raw VirtIO disk. Its filesystem label is
`FUNGOS_CLAIM`. The guest copies the claim into mode-0600 tmpfs, unmounts the
disk, and calls `mycelium setup --claim-file` with `--system-service` and
`--path /var/lib/mycelium`. The joining guest generates its private key locally.
Successful setup removes the tmpfs claim and starts the system Mycelium service.

For this experiment, use a second QEMU user-mode NIC to reach the LAN pairing
authority. Keep the PXE NIC on the isolated bridge. No physical interface is
attached to that bridge.

Check the first-contact output in the serial log and verify the new peer from
the seed. Enrollment success is separate from `FUNGOS_QEMU_BOOT_OK`. Detach and
delete the envelope image once enrollment is verified. Treat the image as a
secret until it is deleted, including after a failed boot. Peer state currently
lives in the RAM root filesystem; disk installation and reboot persistence are
subsequent steps.

## TV console streaming on Agora-One

The existing `unibus-qemu` adapter can stream the guest without installing
Unibus or Canvas inside the base image. QEMU exposes loopback-only VNC on
`127.0.0.1:5901` and its owner-local QMP socket at
`/run/qemu-canvas-demo/demo.qmp`. The installed adapter configuration is
`~/.config/unibus/qemu.json` on Agora-One; Unibus owns the media announcement
and input boundary, while GStreamer sends NVENC H.264/MPEG-TS to the receiver.

The 2026-10-05 display experiment uses the already verified kernel and base
initramfs directly with QEMU `-kernel` and `-initrd`. This is a display test,
not another PXE or enrollment proof. There is no claim envelope or writable
system disk attached. Add `console=ttyS0,115200n8 console=tty0` to the kernel
arguments to show the boot console in VNC while retaining serial evidence.
The current image is a text-console base, not the future fungOS-edge desktop.

On Agora-One, `fungos-qemu-tv.service` is a transient system unit running as
`ajmwagar` with the supplementary `kvm` group; the user service manager did not
have the newly granted KVM group. Its serial log is
`~/.cache/fungos-qemu/tv-console.log`. `unibus-qemu.service` remains a transient
user unit and advertises the existing `agora-qemu-demo` stream, preserving the
receiver's source binding. VNC is not exposed to the LAN.

On the home-pi receiver, use the compositor account (`ajm`), not a separate
Mycelium-created SSH account:

```sh
echo 'workspace switch qemu' | canvasctl
echo 'inspect' | canvasctl
echo 'surfaces' | canvasctl
```

The installed `canvasctl` accepts commands on stdin. The documented positional
form in the upstream QEMU demo is not accepted by this installed version.
The selected workspace has a visible `agora-qemu-display` live-video surface.
Verify advancing frames under `/run/user/1000/dock/canvas/video-frames` and
the decoder process; an active producer alone does not prove receiver display.

Stop this experiment without stopping unrelated services:

```sh
# On Agora-One; leaves the separately managed media adapter available.
sudo systemctl stop fungos-qemu-tv
```

These transient units are not reboot-persistent. The experiment replaces the
previous empty QEMU demo on this stream, not the TV's compositor or layout.

## Persistent root experiment

Set `ROOTFS_IMAGE_OUTPUT` when running `scripts/build-initramfs.sh` as root.
The builder creates a new sparse 8 GiB ext4 image labeled `FUNGOS_ROOT`,
normalizes copied files to root ownership, and leaves machine-ID generation to
first boot. It refuses an existing image path. The output contains the same
Debian root, QEMU overlay, and optional static Mycelium binary as the initramfs.

Attach the image as a writable VirtIO disk and add
`fungos.root=LABEL=FUNGOS_ROOT` to the kernel arguments. The bootstrap waits at
most ten attempts for the labeled disk and switches root onto it. A missing or
invalid disk fails instead of silently using an ephemeral RAM root. Without
that argument the original RAM-root experiment remains available.

[`fungos-qemu-tv.service`](fungos-qemu-tv.service) records the Agora-One test
deployment. Unlike the earlier transient unit, it is installed under
`/etc/systemd/system`; it is deliberately not enabled for automatic host boot.
The kernel and initramfs are still supplied by the QEMU host: this is not yet
a standalone UEFI/GRUB disk installation or a physical-machine installer.

Use a claim disk only on the first un-enrolled boot. After successful setup,
detach and delete it. `/var/lib/mycelium`, `/etc/machine-id`, SSH host keys,
and `/etc/hostname` now live on the disk. Subsequent first-contact execution
skips claim-media handling when the enrolled certificate exists.

The claim disk is only the QEMU handoff adapter. Physical PXE needs an
authenticated, server-validated HTTPS claim handoff with an expiring one-use
secret staged into `/run`, then the same `setup --claim-file` consumption.
Never treat a MAC address alone as authority to disclose a claim or place a
claim in TFTP, kernel arguments, unauthenticated HTTP, or public boot logs.

## Isolated signed-update and rollback runbook

Use the guest's existing shared authority resolver, with a disposable test
root trusted only by that guest and an isolated channel (`fungos-qemu-test`).
Disconnect mesh seeds for the test; do not publish its artifacts from a
production node. Store candidates beneath `/var/lib/mycelium/test-candidates`,
not `/tmp`: the managed daemon uses `PrivateTmp` and cannot read the SSH
session's `/tmp`. Use `MYCELIUM_HOME=/var/lib/mycelium` and
`MYCELIUM_NO_AUTOSTART=1` for diagnostic CLI invocations.

1. Generate a test signer with `releases keygen`, configure its public key in
   `MYCELIUM_AUTHORITY_KEYS`, and restart the managed daemon.
2. Publish a compatible static binary with `releases publish --write`, then
   bootstrap it with `update apply --channel fungos-qemu-test --write`.
3. Compile [`tests/failing-update.rs`](tests/failing-update.rs) on Agora-One
   with the musl target. It passes candidate self-check but intentionally exits
   instead of running a daemon. Sign and publish it only in this isolated test.
4. Apply the broken release. Require an explicit rollback error, an active
   recovered system service, and the previous installed binary's digest.
5. Bootstrap a healthy release, publish a newer healthy artifact, then enable
   the test update policy. The minimum permitted test values are age `60s`,
   rollout window `300s`, and retry backoff `300s`; do not weaken validation.
6. Verify the system timer and runner load the enrolled `node.env`, respect the
   age/rollout delay, and activate only after eligibility. A diagnostic
   `systemctl start mycelium-update.service` exercises the same automatic runner.
7. Reboot without claim media. Compare certificate, machine-ID, installed
   binary, and update-state digests and confirm service readiness.
8. Disable the test policy, remove the private test signer, restore mesh seeds
   and production trust configuration, and verify peer convergence again.

The failure test exposed an unmanaged socket daemon masking a broken managed
replacement. Update activation now checks Unix socket peer credentials against
systemd's `MainPID`, both before replacement and during readiness checks.
