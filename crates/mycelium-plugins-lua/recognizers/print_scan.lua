recognizer = {
  name = "print-scan",

  recognize = function(advertisement)
    local service_names = {
      ["_ipp._tcp"] = "ipp",
      ["_ipps._tcp"] = "ipps",
      ["_printer._tcp"] = "lpd",
      ["_scanner._tcp"] = "scanner",
      ["_uscan._tcp"] = "escl",
      ["_uscans._tcp"] = "escls",
    }
    local service_name = service_names[advertisement.service_type]
    if service_name == nil then
      return nil
    end

    local txt = advertisement.txt_map or {}
    local id = txt["UUID"] or txt["uuid"]
    if id == nil or id == "" then
      return nil
    end

    local services = {}
    if advertisement.port ~= nil then
      services = {
        { name = service_name, transport = "tcp", port = advertisement.port },
      }
    end

    return {
      stable_id = "print-scan:" .. string.lower(id),
      name = advertisement.instance,
      kind = "printer",
      vendor = txt["usb_MFG"] or txt["mfg"],
      model = txt["usb_MDL"] or txt["mdl"] or txt["ty"],
      serial = id,
      addresses = advertisement.addresses or {},
      attributes = {
        color = txt["Color"] or "",
        duplex = txt["Duplex"] or txt["duplex"] or "",
        resource_path = txt["rp"] or "",
        target = advertisement.target or "",
      },
      services = services,
    }
  end,
}
