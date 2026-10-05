# genesis-dnsmasq

This is Genesis's narrow dnsmasq adapter. It renders a reviewable ProxyDHCP,
TFTP, and HTTP-file plan and verifies an observation after an external executor
applies it. The adapter itself never starts dnsmasq or mutates an interface.

```console
genesis-dnsmasq plan request.json > plan.json
genesis-dnsmasq verify plan.json observation.json
```

The rendered configuration is deliberately non-authoritative: every DHCP
range uses `proxy`, and only the selected machine MAC receives a boot target.
TFTP's allowlist contains exactly one UEFI iPXE loader. The common and
machine-specific iPXE scripts, kernels, initrds, installers, and root
filesystems remain HTTP content.

An executor must materialize the plan into an isolated network or a reviewed
production interface, validate dnsmasq's configuration before reload, and
collect a fresh observation for `verify`. A failed postcondition is a failed
apply.
