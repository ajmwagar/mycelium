local INFO_COMMAND = "mca-cli-op info 2>/dev/null || info 2>/dev/null"

local function is_uap(identity)
  local model = identity and identity.model or ""
  return string.find(string.upper(model), "UAP", 1, true) ~= nil
end

local function trim(value)
  return (string.gsub(value or "", "^%s*(.-)%s*$", "%1"))
end

plugin = {
  name = "unifi",
  kind = "access-point",

  probe = function(target)
    return {
      commands = {
        { command = INFO_COMMAND, decode = "key_value" },
      },
    }
  end,

  recognize = function(outputs, target)
    return is_uap(outputs[1])
  end,

  capabilities = function()
    return {
      { id = "system.identify", description = "UniFi AP identity and firmware", mutation = false },
      { id = "unifi.status", description = "adoption state and controller inform URL", mutation = false },
      { id = "wlan.list-ssids", description = "configured radio interfaces and SSIDs", mutation = false },
      { id = "wlan.list-stations", description = "currently associated wireless stations", mutation = false },
      {
        id = "unifi.set-inform",
        description = "change the UniFi controller inform URL",
        mutation = true,
        params = { { name = "url", ty = "string", docs = "HTTP(S) controller inform URL" } },
        verification = { risk = "disruptive", capability = "unifi.status" },
      },
      { id = "system.reboot", description = "reboot the access point", mutation = true },
    }
  end,

  exec = function(cap, params, ctx)
    if cap == "system.identify" then
      return {
        commands = { { command = INFO_COMMAND, decode = "key_value" } },
        parse = "parse_identity",
      }
    elseif cap == "unifi.status" then
      return { commands = { INFO_COMMAND }, parse = "parse_text" }
    elseif cap == "wlan.list-ssids" then
      return { commands = { "iwconfig 2>/dev/null" }, parse = "parse_text" }
    elseif cap == "wlan.list-stations" then
      return {
        commands = { { program = "wstalist", decode = "json" } },
        parse = "parse_first",
      }
    elseif cap == "unifi.set-inform" then
      local url = params.url or ""
      if not string.match(url, "^https?://") or string.find(url, "%s") or string.find(url, "%c") then
        return { ok = false, message = "url must be an HTTP(S) URL without whitespace or control characters" }
      end
      return {
        commands = { { program = "set-inform", args = { url } } },
        parse = "parse_text",
      }
    elseif cap == "system.reboot" then
      return { commands = { { program = "reboot" } }, parse = "parse_text" }
    end
    return { ok = false, message = "unknown capability " .. cap }
  end,

  parse_identity = function(outputs, params)
    local identity = outputs[1] or {}
    if not is_uap(identity) then
      return { ok = false, message = "SSH target did not report a UniFi AP model" }
    end
    local stable = identity.mac_address or identity.hostname
    if stable == nil or stable == "" then
      return { ok = false, message = "UniFi AP identity has no MAC address or hostname" }
    end
    return {
      result = {
        vendor = "Ubiquiti",
        model = identity.model,
        firmware = identity.version,
        hostname = identity.hostname or stable,
        stable_id = stable,
      },
    }
  end,

  parse_text = function(outputs, params)
    return { result = trim(outputs[1]) }
  end,

  parse_first = function(outputs, params)
    return { result = outputs[1] }
  end,
}
