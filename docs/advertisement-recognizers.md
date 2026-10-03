# Advertisement recognizers

Mycelium separates network observation from device-specific interpretation.
Rust observers collect bounded DNS-SD or HTTP-like SSDP advertisements. Pure
Lua recognizers may convert those advertisements into descriptive
`DiscoveredDevice` facts. Discovery never grants management or access authority.

The built-in `bambu-lan` recognizer identifies Bambu Lab LAN-mode broadcasts by
their exact service type. It uses the printer serial as the stable identity and
projects the advertised name, model, firmware, connection state, signal, IP
addresses, and known LAN-mode service endpoints. Access codes and credentials
are neither read nor emitted.

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

The sandbox exposes no filesystem, socket, process, module-loading, or clock
APIs. Rust supplies observation time and provenance after recognition. Results
are bounded to 64 attributes and 32 services before entering topology.
