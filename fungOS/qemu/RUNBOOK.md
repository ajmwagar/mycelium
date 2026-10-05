# Isolated QEMU first-boot runbook

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
