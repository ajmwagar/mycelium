recognizer = {
  name = "airplay",

  recognize = function(advertisement)
    if advertisement.service_type ~= "_airplay._tcp" then
      return nil
    end

    local txt = advertisement.txt_map or {}
    local id = txt["deviceid"] or txt["pi"]
    if id == nil or id == "" then
      return nil
    end

    local services = {}
    if advertisement.port ~= nil then
      services = {
        { name = "airplay", transport = "tcp", port = advertisement.port },
      }
    end

    return {
      stable_id = "airplay:" .. string.lower(id),
      name = advertisement.instance,
      kind = "media.receiver",
      vendor = txt["manufacturer"],
      model = txt["model"],
      firmware = txt["fv"] or txt["srcvers"],
      serial = txt["serialNumber"],
      addresses = advertisement.addresses or {},
      attributes = {
        device_id = txt["deviceid"] or "",
        protocol_version = txt["protovers"] or "",
        target = advertisement.target or "",
      },
      services = services,
    }
  end,
}
