-- Host CLI adapter, not the NextDNS cloud policy API.
plugin = {
  name = "nextdns",
  kind = "dns-filter",
  probe = function() return { commands = { { program = "nextdns", args = { "version" } } } } end,
  recognize = function(outputs) return string.match(outputs[1] or "", "^nextdns version %S+") ~= nil end,
  capabilities = function() return {
    { id = "system.identify", description = "installed NextDNS CLI identity", mutation = false },
    { id = "system.health", description = "NextDNS native service status (not end-to-end DNS health)", mutation = false },
    { id = "nextdns.profiles", description = "configured conditional profile assignments", mutation = false },
  } end,
  exec = function(cap)
    if cap == "system.identify" then
      return { commands = { { program = "nextdns", args = { "version" } }, { program = "hostname" } }, parse = "identity" }
    elseif cap == "system.health" then
      return { commands = { { program = "nextdns", args = { "status" } } }, parse = "health" }
    elseif cap == "nextdns.profiles" then
      return { commands = { { program = "nextdns", args = { "config", "list" } } }, parse = "profiles" }
    end
    return { ok = false, message = "unsupported NextDNS capability; cloud policy writes are not implemented" }
  end,
  identity = function(outputs)
    local version = string.match(outputs[1] or "", "^nextdns version (%S+)")
    local hostname = string.match(outputs[2] or "", "^%s*(%S+)%s*$")
    if not version or not hostname then return { ok = false, message = "invalid NextDNS identity response" } end
    return { result = { vendor = "NextDNS", model = "nextdns-cli", firmware = version, hostname = hostname, stable_id = hostname } }
  end,
  health = function(outputs)
    local status = string.match(outputs[1] or "", "^%s*(.-)%s*$")
    if status ~= "running" and status ~= "stopped" and status ~= "not installed" then
      return { ok = false, message = "unrecognized NextDNS service status" }
    end
    return { result = { service_state = status, running = status == "running" } }
  end,
  profiles = function(outputs)
    local profiles = {}
    for line in string.gmatch(outputs[1] or "", "[^\r\n]+") do
      local value = string.match(line, "^profile%s+(.+)$")
      if value then profiles[#profiles + 1] = value end
    end
    -- Do not return raw configuration: only the declared non-secret projection.
    return { result = { profiles = profiles } }
  end,
}
