# Hardware-backed peer secrets

## Current slice: observation only

Linux hardware inventory observes registered TPMs in `/sys/class/tpm/tpmN`.
Each appears as `security_module`, with a peer-scoped locator, `tpm-present`
capability and the documented `tpm_version_major` attribute when available.
Hardware snapshots already carry the observing node and observation timestamp.
No TPM commands, device opens, PCR reads, endorsement keys or private keys are
needed. No new resource-selection or authorization contract is introduced.

An empty successful Linux inventory means no TPM was registered with that OS,
not that the physical machine has none. Missing version attributes are `unknown`;
access and enumeration failures fail the collection rather than inventing absence.
TPM presence does not establish readiness, hardware rather than virtual backing,
Secure Boot, sealing support, or attestation. `key_protection` stays `unknown` and
`attestation` stays `not_verified`. No access policy consumes these observations.
Darwin Secure Enclave probing is not implemented; absence of a security-module
entry there must not be interpreted as absence of an enclave.

`security_module` is an additive enum variant, but older receivers have exhaustive
deserialization and cannot decode it. Upgrade receiving peers before deploying
this probe on TPM-equipped senders; there is no negotiated downgrade yet.

## Next slice: optional sealing, not identity replacement

Keep the enrolled peer signing identity, Iroh endpoint identity and existing TLS
credentials unchanged. Introduce one narrow local secret-loading boundary, with
the present file backend and an explicitly selected TPM-sealed backend. Call an
existing platform sealing implementation rather than writing a TPM stack.
Evaluate systemd encrypted credentials on supported Linux hosts; do not assume
their service-manager integration works for the current user-service deployment.
User-scoped encryption requires systemd 256 or newer. Explicitly require a TPM
backend rather than `auto` (which may choose host-only protection); never accept
`null` or `auto-initrd` modes that can produce unprotected credentials.
No backend is implemented or automatically selected by discovery yet.

Sealing encrypts an existing secret on disk and unlocks it through the TPM.
The existing Ed25519 signer and Iroh endpoint still need plaintext in process
memory. This protects against copied disks, not a compromised running daemon or
root. Non-exportable signing would require a separate signing interface and
algorithm support; it must not be advertised as an effect of sealing. Apple's
Secure Enclave uses P-256 and is not a drop-in Ed25519 key store.

Before migrating any key:

1. Record public identities and validate an independently protected recovery copy.
2. Create a sealed copy without deleting the working original; require explicit
   write authorization. Do not print secrets or include them in gossip.
3. Load through the new backend and prove peer signing and Iroh endpoint IDs are
   unchanged. Verify permissions and service-user access.
4. Test cold boot, daemon restart, signed update and executable rollback on a
   disposable target. Test denied access, corrupted blob, unavailable TPM,
   firmware/PCR changes and TPM clear/replacement as explicit failure cases.
5. Only remove the operational plaintext file after recovery and rollback work.
   Failure must not silently regenerate an enrolled identity or fall back to an
   unprotected copy. Recovery is an explicit operator action.

Avoid binding the first slice to changing PCR measurements. A boot-measured
policy later needs an intentional update authorization mechanism and tested
recovery: kernel, firmware and Secure Boot changes can otherwise lock out a
healthy node. Hardware-bound blobs are not portable backup copies. TPM-backed
storage remains local protection; enrollment, roles and revocation remain the
authority for network access. Attestation enforcement is deferred.

## Platform references

- [Linux TPM sysfs ABI](https://www.kernel.org/doc/Documentation/ABI/stable/sysfs-class-tpm): registered devices and version attribute.
- [systemd encrypted credentials](https://www.freedesktop.org/software/systemd/man/latest/systemd-creds.html): candidate platform sealing integration.
- [Linux trusted and encrypted keys](https://docs.kernel.org/security/keys/trusted-encrypted.html): sealing and policy distinctions.
- [Apple Secure Enclave keys](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave): algorithm constraints.
