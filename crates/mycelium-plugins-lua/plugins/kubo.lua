-- Pure Kubo response mapping, used by the existing loopback observer.
-- The host owns transport, deadlines, origins and whether endpoints qualify.
service_provider = {
  name = "kubo",
  request = {},
  project = function(response, ctx)
    if ctx.operation == "version" then
      local v, repo, system, go = response.Version, response.Repo, response.System, response.Golang
      if type(v) ~= "string" or #v == 0 or #v > 64 or not v:match("^%d") or v:find("[^A-Za-z0-9%.%-%+]")
          or type(repo) ~= "string" or not repo:match("^%d+$")
          or type(system) ~= "string" or #system > 64 or not system:find("/",1,true)
          or type(go) ~= "string" or #go > 64 or go:sub(1,2) ~= "go" then
        return {}
      end
      return {version=v}
    elseif ctx.operation == "identity" then
      local id = response.ID
      assert(type(id)=="string" and #id>=32 and #id<=128 and not id:find("[^A-Za-z0-9]"), "invalid Kubo peer identity")
      local addresses=response.Addresses or {}
      assert(type(addresses)=="table" and #addresses<=32, "Kubo address bound exceeded")
      local unique, result = {}, {}
      for _, address in ipairs(addresses) do
        assert(type(address)=="string" and #address<=512 and address:sub(1,1)=="/" and not address:find("[%c%s]"), "invalid Kubo advertised address")
        local peer=address:match("/p2p/([^/]+)$")
        assert(not peer or peer==id, "Kubo address identity mismatch")
        if not unique[address] then unique[address]=true; result[#result+1]=address end
      end
      table.sort(result)
      -- Never export PublicKey, config, pins or remote API/gateway guesses.
      return {peer_id=id, swarm_addresses=#result>0 and result or ctx.empty_array}
    end
    error("unsupported Kubo projection operation")
  end,
}
