local function command(args) return { program = "pihole", args = args } end
local function valid_domain(domain)
  if type(domain) ~= "string" or #domain > 253 or #domain == 0 then return false end
  if not string.match(domain, "^[A-Za-z0-9][A-Za-z0-9%.%-]*[A-Za-z0-9]$") then return false end
  for label in string.gmatch(domain, "[^%.]+") do
    if #label > 63 or string.sub(label, 1, 1) == "-" or string.sub(label, -1) == "-" then return false end
  end
  return not string.find(domain, "..", 1, true)
end

plugin = {
  name = "pihole",
  kind = "dns-filter",
  probe = function() return { commands = { command({ "version" }) } } end,
  recognize = function(outputs) return string.match(outputs[1] or "", "Core version is v6%.") ~= nil end,
  capabilities = function() return {
    { id = "system.identify", description = "Pi-hole v6 installed identity", mutation = false },
    { id = "dns.list-entries", description = "explicit exact denylist domains only (not gravity, regex or groups)", mutation = false },
    { id = "dns.block", description = "add an exact domain to the default denylist", mutation = true,
      params = { { name = "domain", ty = "string", docs = "ASCII domain; no regex or wildcard" } },
      verification = { risk = "disruptive", capability = "dns.list-entries" } },
  } end,
  exec = function(cap, params)
    if cap == "system.identify" then
      return { commands = { command({ "version" }), { program = "hostname" } }, parse = "identity" }
    elseif cap == "dns.list-entries" then
      return { commands = { command({ "deny", "--list" }) }, parse = "entries" }
    elseif cap == "dns.block" then
      if not valid_domain(params.domain) then return { ok = false, message = "domain must be an ASCII DNS name without wildcards" } end
      -- CLI output alone does not prove success; verify membership in the fresh list.
      return { commands = { command({ "deny", string.lower(params.domain) }), command({ "deny", "--list" }) }, parse = "blocked" }
    end
    return { ok = false, message = "unsupported Pi-hole capability" }
  end,
  identity = function(outputs)
    local version = string.match(outputs[1] or "", "Core version is (v6%.%S+)")
    local hostname = string.match(outputs[2] or "", "^%s*(%S+)%s*$")
    if not version or not hostname then return { ok = false, message = "Pi-hole v6 identity required" } end
    return { result = { vendor = "Pi-hole", model = "Pi-hole v6", firmware = version, hostname = hostname, stable_id = hostname } }
  end,
  entries = function(outputs)
    local text = string.gsub(outputs[1] or "", "\27%[[%d;]*m", "")
    local count = string.match(text, "Found (%d+) domain%(s%) in the exact denylist:")
    if not count then
      if string.find(text, "No domains found in the exact denylist", 1, true) then count = "0"
      else return { ok = false, message = "unrecognized Pi-hole exact denylist response" } end
    end
    local domains = {}
    for line in string.gmatch(text, "[^\r\n]+") do
      local domain = string.match(line, '^%s*%- "([^"]+)"%s*$')
      if domain then
        if not valid_domain(domain) then return { ok = false, message = "invalid domain in denylist" } end
        domains[#domains + 1] = string.lower(domain)
      end
    end
    if #domains ~= tonumber(count) then return { ok = false, message = "incomplete Pi-hole denylist evidence" } end
    return { result = domains }
  end,
  blocked = function(outputs, params)
    local parsed = plugin.entries({ outputs[2] })
    if parsed.ok == false then return parsed end
    for _, domain in ipairs(parsed.result) do
      if domain == string.lower(params.domain) then return { result = { domain = domain, blocked = true } } end
    end
    return { ok = false, message = "Pi-hole did not confirm requested domain in exact denylist" }
  end,
}
