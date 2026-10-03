classifier = {
  name = "snmp-system",

  classify = function(evidence)
    if evidence.source ~= "snmp.system" then return nil end
    local facts = evidence.facts or {}
    local descr = string.lower(facts.sys_descr or "")
    local oid = facts.sys_object_id or ""
    local enterprise = string.match(oid, "^1%.3%.6%.1%.4%.1%.([0-9]+)")

    if enterprise == "4526" then
      return { kind = "switch", vendor = "NETGEAR" }
    end
    if string.find(descr, "edgerouter", 1, true)
        or string.find(descr, "edgeos", 1, true)
        or string.find(descr, "vyos", 1, true) then
      return { kind = "router", vendor = "Ubiquiti" }
    end
    if enterprise == "41112" or enterprise == "2271" then
      return { kind = "access-point", vendor = "Ubiquiti" }
    end
    if enterprise == "11" then
      return { kind = "switch", vendor = "HPE" }
    end
    if enterprise == "14823" then
      return { kind = "switch", vendor = "Aruba" }
    end
    return nil
  end,
}
