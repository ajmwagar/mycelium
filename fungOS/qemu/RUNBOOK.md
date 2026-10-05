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
