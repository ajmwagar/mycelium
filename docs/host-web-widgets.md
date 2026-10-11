# Host identity and shared GPU widgets

The optional host viewer uses Coherence product tokens and its existing browser
widget bundle, including the Rust/WASM GFX renderer. It does not run a collector
or discover services independently. HTML owns identity, navigation and labels;
GFX owns live metric geometry. The page is responsive and retains the renderer
across updates rather than rebuilding the dashboard.

Install the four files from Coherence's verified widget build into an
operator-owned directory, then set the existing private `host-web.json` field:

```json
"widget_assets": "/home/USER/.local/share/coherence/widgets"
```

The files are `coherence-widgets.js`, `coherence_widget_web.js`,
`coherence_widget_web_bg.wasm`, and `widgets.css`. No arbitrary paths or remote
asset sources are accepted in HTTP requests. Each read is bounded to 2 MiB.
The pinned contract source is retained with provenance for standalone builds.
Update the bundle and contract together from Coherence, not independently.

Every asset and `/api/widgets/host` request uses the same existing host-viewer
authorization, with client TLS authentication and signed grants. The WASM MIME
type is explicit. CSP permits only same-origin scripts/connections and WASM
compilation; external scripts and framing remain denied. Configure valid TLS
and client identity before testing. A secure browser supporting WebGPU is
required for GPU rendering; the shared loader visibly reports degraded mode.

The health widget shows observed memory use and uptime; the separate hardware
widget shows indexed device count. Each feed uses its own source timestamp and
two-minute lifetime. A slower hardware scan cannot freeze fresh health updates
or mark health stale. Hardware may independently remain stale until another real
scan, retaining its useful last observation. Missing values remain null; no
synthetic history or traffic is generated. Polling cannot refresh old data by
changing the response timestamp.

The identity panel displays up to 64 observed non-loopback interface IPs, which
are explicitly not reachability guarantees. The QR encodes the canonical
`https://HOST.SITE.myc/` viewer link only: no keys, invitation claims or grants.
Names derive from node identity and normal DNS canonicalization. Port-443
ingress and DNS are prerequisites, not created by rendering the QR.

Restart the existing daemon after adding the configuration. Verify authorized
host JSON and widget JSON, asset content types, QR destination and IP labels.
Anonymous/unauthorized requests must remain denied. A visual browser check is
required before claiming the deployed appearance or GPU rendering verified.
