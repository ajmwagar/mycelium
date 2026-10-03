# Advertisement recognizers

Mycelium separates network observation from device-specific interpretation.
Rust observers collect bounded DNS-SD or HTTP-like SSDP advertisements. Pure
Lua recognizers may convert those advertisements into descriptive
`DiscoveredDevice` facts. Discovery never grants management or access authority.

Built-in recognizers currently cover:

| Recognizer | Evidence | Stable identity | Projected device |
|---|---|---|---|
| `bambu-lan` | Bambu SSDP `NOTIFY` | printer serial | 3D printer and LAN-mode endpoints |
| `homekit` | `_hap._tcp` | HomeKit accessory ID | bridge or accessory; known Hue bridge models are attributed to Philips Hue |
| `airplay` | `_airplay._tcp` | AirPlay device ID | media receiver, including advertised manufacturer/model/firmware |
| `print-scan` | IPP, LPD, Scanner or eSCL DNS-SD | printer/scanner UUID | one device with its distinct print and scan endpoints |

The Bambu recognizer identifies LAN-mode broadcasts by their exact service
type. It projects the advertised name, model, firmware, connection state,
signal, IP addresses, and known LAN-mode service endpoints. Access codes and
credentials are neither read nor emitted.

The print/scan recognizer intentionally uses the same stable UUID for IPP and
eSCL advertisements. A multifunction device therefore gains multiple services
instead of appearing as unrelated printer and scanner nodes. Advertisements
without the protocol's stable identifier are left unrecognized rather than
being assigned a fragile name- or address-derived identity.

Linux observation includes a bounded passive UDP 2021 window in addition to
ordinary SSDP M-SEARCH. The generic SSDP parser accepts both response and
`NOTIFY` records; only the Lua recognizer knows Bambu header names.

Additional recognizers can be installed as
`$MYCELIUM_HOME/recognizers/*.lua`. They are validated when the daemon starts;
an invalid or duplicate recognizer fails startup loudly. A recognizer has this
shape:

```lua
recognizer = {
  name = "vendor-device",
  recognize = function(advertisement)
    if advertisement.service_type ~= "vendor-service-type" then
      return nil
    end
    return {
      stable_id = "vendor:" .. advertisement.instance,
      name = advertisement.instance,
      kind = "appliance",
      addresses = advertisement.addresses or {},
      attributes = {},
      services = {},
    }
  end,
}
```

Alongside the serialized `ServiceAdvertisement`, the host supplies a derived
`txt_map` table by splitting each DNS-SD TXT or SSDP header entry at its first
`=`. This is the single canonical key/value projection; recognizers do not
duplicate TXT parsing. Raw `txt` remains available when a protocol needs it.

The sandbox exposes no filesystem, socket, process, module-loading, or clock
APIs. Rust supplies observation time and provenance after recognition. Results
are bounded to 64 attributes and 32 services before entering topology.

Recognizers are descriptive only. They do not fetch description documents,
try credentials, grant access, or claim authority. Generic DIAL and UPnP
responses are retained as advertisements until they contain enough evidence
for a non-speculative identity; for example, Mycelium does not label every
DIAL endpoint as a Fire TV.
