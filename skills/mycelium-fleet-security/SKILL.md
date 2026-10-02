---
name: mycelium-fleet-security
description: Assess and improve security across Mycelium peers. Use for fleet health, update posture, CVE findings, DISA STIG scans, normalized SIEM events, signed evidence, remediation planning, staged updates, drains, reboots, and post-change verification.
---

# Mycelium fleet security

Keep collection local, summaries bounded, and evidence content-addressed. A missing scanner is unknown coverage, never a clean result.

## Assessment

1. Run `mycelium fleet status` and `mycelium security status`.
2. Inspect `mycelium security events`; correlate signed node identity, site, timestamp, category, and outcome.
3. Run an explicit scan only with content compatible with the host OS and release.
4. Reject all-not-applicable STIG results as a profile mismatch.

## Remediation

1. Generate a content-addressed remediation plan; never execute generated shell text directly.
2. Review with `mycelium security remediation list`.
3. Drain workloads and establish a recovery path before disruptive changes.
4. Apply only the exact digest with `--write`.
5. Run `mycelium security remediation verify` separately.
6. Report applied and verified as distinct states. Surface reboots and failures explicitly.

For software rollout, inspect fleet compatibility first. Release signatures authorize metadata; SHA-256 authorizes bytes. Let peers share matching artifacts, but do not weaken signer, target, or digest validation.
