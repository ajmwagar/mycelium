# Linux host access from signed grants

`mycelium access host` reconciles local accounts, OpenSSH principals/KRL,
sudoers and PAM **account** authorization from the existing access/authority
records. It does not introduce another identity service or password database.

## Authority

Root-owned policy selects trusted public authority roots and, during migration,
legacy access issuer keys. The shared `AuthorityResolver` verifies root-signed
delegations. A peer or OIDC identity alone is not a grant issuer. An
`access_publish` delegation is powerful: it authorizes access publication, not
just a particular human's role. Do not give it to ordinary operators.

The privileged reconciler independently checks record signatures, local-time
validity and signed revocations. It ignores the carrier's `active` flags. Root
policy and the executable must be root-owned through every path ancestor, with
no writable directories or symlinks. Never point a root timer at a user's
self-updating binary.

## Policy and runbook

Install the tested Linux binary at a root-owned path such as
`/usr/local/libexec/mycelium-access/mycelium`. Keep the normal peer daemon under
its existing user. Create `/etc/mycelium/access.json`, owned by root, containing:

```json
{
  "version": 1,
  "authority_roots": ["PUBLIC_AUTHORITY_KEY_HEX"],
  "legacy_access_keys": [],
  "accepted_roles": ["network-admin", "home-operator"],
  "sudo_roles": ["network-admin"],
  "ca_public": "/etc/ssh/mycelium/user_ca.pub",
  "pam_services": ["sshd", "sudo"]
}
```

Accepted roles are host admission policy; sudo roles must be a subset. Only
the root policy can map an admitted role to unrestricted passwordless sudo.
No grant creates a root account. Existing UID-zero aliases are rejected.

With a recovery SSH session open, run:

```sh
sudo env MYCELIUM_HOME=/home/OPERATOR/.mycelium MYCELIUM_NO_AUTOSTART=1 \
  /usr/local/libexec/mycelium-access/mycelium access host plan \
  --policy /etc/mycelium/access.json
sudo env MYCELIUM_HOME=/home/OPERATOR/.mycelium MYCELIUM_NO_AUTOSTART=1 \
  /usr/local/libexec/mycelium-access/mycelium access host apply \
  --policy /etc/mycelium/access.json --write
```

Verify a new SSH session, `id`, `sudo -n true`, rejection of an ungranted
identity, and `visudo -c` before enabling periodic enforcement:

```sh
sudo env MYCELIUM_HOME=/home/OPERATOR/.mycelium MYCELIUM_NO_AUTOSTART=1 \
  /usr/local/libexec/mycelium-access/mycelium access host install-timer \
  --policy /etc/mycelium/access.json --daemon-home /home/OPERATOR/.mycelium --write
systemctl status mycelium-host-access.timer mycelium-host-access.service
```

## Expiry, failure and recovery

Root-owned `/var/lib/mycelium/access/evidence.json` retains signed grants and
revocations. Daemon outage is reported explicitly; cached evidence still
expires against local time. Omission of a previously observed revocation
cannot resurrect a grant. Applies are serialized with an exclusive file lock.
The timer targets two-minute reconciliation, not instantaneous revocation;
failed enforcement remains a visible failed systemd service. Already-running
sessions/processes are not terminated.

Accounts and homes are retained after revocation. Managed sudo rules are
replaced, SSH principals removed and PAM denies previously managed accounts
without current grants. Unmanaged recovery users and unrelated sudoers rules
are not changed; pre-existing unmanaged grants may independently permit sudo.
Account creation uses the existing SSH host-bundle implementation and locks
passwords on newly created accounts only.

PAM uses the distribution's `pam_access.so`, prepended as an account check to
`sshd`/`sudo`. Authentication stacks, passwords and password rotation are not
modified. Original PAM stacks are retained as `.mycelium-pre` files. Sudo
candidates are validated before installation. Apply failures are reported;
this is a multi-file reconciliation, not a transaction across Linux account
databases. Keep recovery access until the full apply and verification finish.

For recovery, stop `mycelium-host-access.timer`; restore the affected PAM
stack from its root-owned `.mycelium-pre` backup and use the SSH host-apply
rollback copy if needed. Do not delete user homes or replace trusted issuers
as a troubleshooting shortcut. Certificate renewal and grant lifetime are
separate: renewing a certificate does not extend an expired access grant.
