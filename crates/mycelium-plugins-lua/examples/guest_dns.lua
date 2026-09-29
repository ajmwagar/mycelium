-- Example mycelium Lua plugin: a toy DNS filter appliance.
-- The same source is used verbatim by the crate's integration tests.
plugin = {
  name = "guest",
  kind = "dns-filter",
  match = function(t) return t.port == 8053 end,
  capabilities = function() return {
    { id = "system.identify", description = "who am I", mutation = false, returns = "map" },
    { id = "dns.block", description = "sinkhole a domain", mutation = true,
      params = { { name = "domain", ty = "string", docs = "domain" } } },
    { id = "dns.list", description = "list entries", mutation = false },
  } end,
  exec = function(cap, params, ctx)
    if cap == "system.identify" then
      return { result = { vendor = "Test", model = "guestbox", firmware = "1.0", hostname = "gh0st" } }
    elseif cap == "dns.block" then
      return { commands = { "block " .. params.domain } }
    elseif cap == "dns.list" then
      return { commands = { "list" }, parse = "parse_list" }
    end
    return { ok = false, message = "unknown cap " .. cap }
  end,
  parse_list = function(outputs, params)
    local out = {}
    for line in outputs[1]:gmatch("[^\n]+") do out[#out+1] = line end
    return { result = out }
  end,
}
