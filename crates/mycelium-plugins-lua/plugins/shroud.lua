-- Shroud owns namespace and health; Rust supplies JSON, time and owner identity.
local function label(s)
  return type(s) == "string" and #s > 0 and #s <= 63
    and not s:find("[^a-z0-9%-]") and s:sub(1,1) ~= "-" and s:sub(-1) ~= "-"
end
service_provider = {
  name = "shroud",
  request = { action = "discover", includeUnready = false },
  project = function(response, ctx)
    assert(response.ok == true and response.protocol == "shroud.control.v1", "failed or unsupported Shroud discovery")
    local records = response.services or {}
    assert(type(records) == "table" and #records <= 128, "invalid Shroud record bound")
    local by_id, aliases, result = {}, {}, {}
    for _, r in ipairs(records) do
      if r.power == "running" and r.health == "ready" and r.protocol == "tcp"
          and (r.scheme == "http" or r.scheme == "https") then
        assert(label(r.name) and label(r.port_name), "unsafe Shroud name")
        local port = r.guest and r.guest.port
        assert(type(port) == "number" and port % 1 == 0 and port > 0 and port <= 65535, "invalid Shroud port")
        local endpoint = r.scheme .. "://" .. r.name .. ".shroud.svc:" .. port .. "/"
        assert(not aliases[r.name] or aliases[r.name] == endpoint, "conflicting Shroud alias")
        aliases[r.name] = endpoint
        local id = "service/" .. ctx.node_id .. "/shroud/" .. r.name .. "/" .. r.port_name
        if not by_id[id] then
          by_id[id] = true
          result[#result+1] = {
            schema_version = ctx.schema_version, service_id = id,
            observed_at = ctx.observed_at, expires_at = ctx.observed_at + 120,
            provenance = { provider = "shroud-discover", observer = ctx.node_id, source_id = "shroud.control.v1/discover" },
            confidence = "strong",
            value = { kind = "shroud", endpoints = { endpoint }, protocols = { r.scheme },
              attributes = { node_id = ctx.node_id, service_name = r.name, port_name = r.port_name, owner_health = "ready" } },
          }
        end
      end
    end
    table.sort(result, function(a,b) return a.service_id < b.service_id end)
    return { schema_version = ctx.schema_version, observations = #result > 0 and result or ctx.empty_array }
  end,
}
