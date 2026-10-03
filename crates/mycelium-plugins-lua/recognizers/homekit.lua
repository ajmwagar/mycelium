recognizer = {
  name = "homekit",

  recognize = function(advertisement)
    if advertisement.service_type ~= "_hap._tcp" then
      return nil
    end

    local txt = advertisement.txt_map or {}
    local id = txt["id"]
    if id == nil or id == "" then
      return nil
    end

    local model = txt["md"]
    local vendor = nil
    if model == "BSB001" or model == "BSB002" then
      vendor = "Philips Hue"
    end

    local services = {}
    if advertisement.port ~= nil then
      services = {
        { name = "homekit-accessory", transport = "tcp", port = advertisement.port },
      }
    end

    return {
      stable_id = "homekit:" .. string.lower(id),
      name = advertisement.instance,
      kind = txt["ci"] == "2" and "automation.bridge" or "automation.accessory",
      vendor = vendor,
      model = model,
      serial = id,
      addresses = advertisement.addresses or {},
      attributes = {
        category = txt["ci"] or "",
        protocol_version = txt["pv"] or "",
        paired = txt["sf"] == "0" and "true" or "false",
        target = advertisement.target or "",
      },
      services = services,
    }
  end,
}
