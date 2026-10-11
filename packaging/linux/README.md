# Mycelium Debian package

This owner-built package contains the real CLI/daemon, its systemd unit, a fungOS
first-contact adapter and license/build notices. No peer identity, certificates,
claims, SSH keys, administrator account, signer, automatic updater or maintainer
scripts are shipped. Installing it neither enables nor starts the service. An
enabled but unenrolled service is inert because its private environment/key
conditions are unmet.

## Build from one clean source archive

Run on Linux with Rust, cargo-zigbuild/Zig, readelf, sha256sum, mktemp and dpkg-deb.
Build the executable and packager from the same clean archived source revision,
not an actively edited checkout or an unrelated cached executable.
An explicit notice-only repack may retain a previously qualified executable;
retain both clean source archives and record their separate revisions. Never
compile this tool against a dirty workspace lockfile for release use.

```sh
cargo check --locked -p mycelium-cli --features iroh-sync --tests
cargo test --locked -p mycelium-cli --features iroh-sync
cargo check --locked --manifest-path packaging/linux/Cargo.toml
cargo test --locked --manifest-path packaging/linux/Cargo.toml
cargo zigbuild --locked --release -p mycelium-cli --features iroh-sync \
  --target x86_64-unknown-linux-musl
cargo build --locked --release --manifest-path packaging/linux/Cargo.toml
packaging/linux/target/release/mycelium-debian-package \
  target/x86_64-unknown-linux-musl/release/mycelium \
  /new/package-output 0.1.0 FULL_40_CHARACTER_SOURCE_COMMIT
```

Use `aarch64-unknown-linux-musl` for ARM64. ELF headers determine amd64/arm64;
dynamic library/interpreter requirements are rejected. This initial static-musl
slice does not guess a GNU libc floor. Completed archives are published
atomically without overwriting existing packages. Building never installs on
the host.

The third argument is the Debian artifact version selected by the release owner,
not necessarily the workspace CLI version printed by `_self-check`. Both are
recorded in `/usr/share/doc/mycelium/build-inputs`, alongside source commit,
architecture and executable SHA-256. A supplied commit is metadata, not proof
that arbitrary bytes came from it. Retain locked builds, corresponding source
and dependency license notices; independently verify before release signing.

## Third-party notices input

Bare legacy packages are **qualification-only**, not publishable release
artifacts: their provenance explicitly records unknown third-party coverage.
For a release candidate, build this packager from its clean archive with
`MYCELIUM_PACKAGER_SOURCE_COMMIT=FULL_PACKAGER_COMMIT` set during `cargo build`.
Then append `--third-party-notices /absolute/reviewed-notices` to the invocation.
The positional source revision remains the **executable's** source revision;
notice-only changes do not pretend to rebuild or change that executable.

The explicit directory contract is:

```text
metadata.txt
inventory.tsv
notices/<component>/<raw-notice-file>
```

`metadata.txt` contains exactly these fields; unknown fields are rejected:

```text
schema_version=1
executable_sha256=<actual executable digest>
source_commit=<full executable source commit>
cargo_lock_sha256=<archived workspace Cargo.lock digest>
inventory_sha256=<digest of inventory.tsv bytes>
coverage=reviewed-complete
legal_clearance=not-asserted
```

`inventory.tsv` has the header `sha256<TAB>path`, followed by one digest and
safe relative `notices/...` path per raw nonempty notice. Paths, root and parent
directories cannot be symlinks; absolute paths, traversal, duplicates, missing
files, modified bytes, unknown/incomplete coverage and binding mismatches fail
before output creation. The lock digest is checked against the clean archive
compiled into the packager. Notice bytes are captured once and rehashed after
staging, before atomic package creation. Only listed raw notices and binding/
inventory metadata enter `/usr/share/doc/mycelium/third-party-notices`; no
runtime source tree or unrelated input file is copied.

`reviewed-complete` is an explicit release-owner evidence assertion, not legal
certification. Hashes prove byte identity, not sufficient license coverage.
Missing notices must be resolved by review, not relabeled complete. Notices do
not replace corresponding source or the distribution's full license audit.

## Install and enroll privately

```sh
sudo apt-get install /absolute/path/mycelium_VERSION_ARCH.deb
sudo /usr/bin/mycelium setup --packaged --claim-file /secure/peer-claim
sudo /usr/bin/mycelium daemon status
sudo systemctl status mycelium.service
sudo /usr/bin/mycelium setup --packaged --repair
```

The claim must be an authorized peer invitation in an owner-only file. Packaged
setup validates dpkg ownership and uses `/var/lib/mycelium` plus the system
manager. The same package mode is inferred for setup, direct peer redemption,
bundle install and repair from the canonical executable and installed unit,
not a writable marker. Wrong paths, malformed private policy, shadow units and
an existing native `bin/mycelium` fail before claiming. Existing identity state
must be repaired, not replaced with a new invitation.

The daemon explicitly runs as root because host actions require root;
enrollment, active grants and roles still authorize those actions. Private state
is root-owned 0700, node.env is 0600 and the service uses UMask0077. No shared
administrator is created. Root package CLI defaults to the system state; explicit
MYCELIUM_HOME and unprivileged personal state remain separate. Package CLI
autostart is disabled, never spawning a competing unmanaged daemon.

For a pre-issued bundle, `sudo mycelium enroll install --bundle /secure/bundle
--write` installs private state without starting the service. Explicitly run
`sudo systemctl daemon-reload` and `sudo systemctl enable --now mycelium.service`.
Claim enrollment and repair keep `/usr/bin/mycelium` and the package unit at
`/usr/lib/systemd/system/mycelium.service`: no binary copy or /etc unit shadow.

## fungOS first contact

The package supplies the existing dispatcher with one executable adapter at
`/usr/lib/fungos/first-contact.d/mycelium`. A private
`/etc/fungos/first-contact.env` contains the selector
`PROFILE=fungos-headless-edge` (also edge/cloud/compute). Provisioning privately
stages an owner-only claim at `/run/fungos-first-contact/claim`. The adapter never
sources shell code or publishes a claim in an ISO, kernel arguments, TFTP or
public HTTP. The common sandbox is retained with a narrow private-state drop-in.
The dispatcher also requires the staged claim to exist, so a consumed claim is
not retried on the next boot; the profile metadata remains available to inspect.
A missing claim leaves first contact waiting/inert, not successfully enrolled.
No QEMU-specific disk or new enrollment protocol is required.

## Updates and recovery

Debian owns the executable. Native update apply, automatic native policy
enablement and auto-run reject package-owned paths before writes, including
symlink destinations. No native timer is shipped. Other software's update
ownership is not changed.

Explicit enrollment installs the existing Mycelium health binding in private
software-services.json only if absent; operator entries are preserved. Use the
existing `mycelium software apt` plan/apply/recover commands and exact versions
from admitted signed repository generations, not a second updater. Retain the
previous archive and verify service health after updates. Apply automatically
rolls back a failed-health activation; `recover` resumes recovery of an interrupted
transaction. Manual recovery is installing the previous package and explicitly
restarting the service.

Removal has no implicit daemon stop: stop/disable explicitly first. Private peer
state is retained on removal/purge; deleting or migrating it is separately
authorized. Source checks are not final-image proof: qualify real install,
private claim, individual SSH, native-update rejection, APT rollback and reboot
in a disposable fungOS guest before release.
