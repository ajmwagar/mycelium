recognizer = {
  name = "bambu-lan",

  recognize = function(advertisement)
    if advertisement.service_type ~= "urn:bambulab-com:device:3dprinter:1" then
      return nil
    end

    local headers = {}
    for _, item in ipairs(advertisement.txt or {}) do
      local split = string.find(item, "=", 1, true)
      if split then
        headers[string.sub(item, 1, split - 1)] = string.sub(item, split + 1)
      end
    end

    local serial = advertisement.instance
    if serial == nil or serial == "" then
      return nil
    end

    return {
      stable_id = "bambu:" .. serial,
      name = headers["devname.bambu.com"] or serial,
      kind = "printer.3d",
      vendor = "Bambu Lab",
      model = headers["devmodel.bambu.com"],
      firmware = headers["devversion.bambu.com"],
      serial = serial,
      addresses = advertisement.addresses or {},
      attributes = {
        interface = headers["devinf.bambu.com"] or "",
        connection = headers["devconnect.bambu.com"] or "",
        binding = headers["devbind.bambu.com"] or "",
        secure_link = headers["devseclink.bambu.com"] or "",
        signal_dbm = headers["devsignal.bambu.com"] or "",
      },
      services = {
        { name = "bambu-mqtt-tls", transport = "tcp", port = 8883 },
        { name = "bambu-ftps", transport = "tcp", port = 990 },
        { name = "bambu-camera", transport = "tcp", port = 6000 },
      },
    }
  end,
}
