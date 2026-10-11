-- Pure Canvas composition. The owner imports the public QR SVG into its asset
-- store, supplies the receipt, and invokes render again at expiry. No IO/auth.
local M = {}
function M.render(p, owner)
  assert(p.mode == "connection", "invite presentation is not supported")
  assert(owner.target_endpoint_id == p.target_endpoint_id, "wrong displayed target")
  assert(type(owner.now) == "number", "owner clock required")
  assert(type(p.observed_at) == "number" and type(p.expires_at) == "number", "freshness required")
  assert(p.observed_at <= owner.now, "future observation")
  local expired = p.expires_at <= owner.now
  local name = owner.target_name or p.target_server_name
  local site = owner.target_site or "Site not supplied by owner"
  local display = owner.display_name or "This display"
  local body = "Target: " .. name .. "\nSite: " .. site .. "\nDisplayed on: " .. display
  body = body .. "\nEndpoint: " .. p.target_endpoint_id
  if expired then
    body = body .. "\n\nConnection hints expired. Refresh at the source."
  else
    body = body .. "\n\nDirect address hints (not proven reachability):"
    for _, address in ipairs(p.direct_address_hints or {}) do body = body .. "\n" .. address end
    body = body .. "\nValid for " .. tostring(p.expires_at - owner.now) .. " seconds."
    body = body .. "\n\nScan saves public connection hints. Use the existing CLI sync join flow."
  end
  body = body .. "\n\nThis does not enroll the target or this display. Existing fleet authentication is required."
  local surfaces = {{id="pairing-details",title="Mycelium · connect to peer",content={kind="widget",spec={schema_version=2,id="pairing-details",kind="rich_card",title=name,format="code",body=body,chrome="frameless"}}}}
  local layout = {kind="surface",surface_id="pairing-details"}
  if not expired then
    assert(type(owner.qr_asset) == "table" and (owner.qr_asset.media_type == "image/svg+xml" or owner.qr_asset.media_type == "image/png"), "owner QR image receipt required")
    assert(type(owner.qr_asset.sha256) == "string" and #owner.qr_asset.sha256 == 64 and not owner.qr_asset.sha256:find("[^0-9a-f]"), "owner asset hash required")
    assert(type(owner.qr_asset.byte_length) == "number" and owner.qr_asset.byte_length > 0, "owner asset length required")
    surfaces[#surfaces+1] = {id="pairing-qr",title="Public connection QR · not an invite",content={kind="asset",asset=owner.qr_asset}}
    layout = {kind="split",axis=owner.tv and "horizontal" or "vertical",ratio=0.5,first={kind="surface",surface_id="pairing-qr"},second={kind="surface",surface_id="pairing-details"}}
  end
  return {schema_version=1,id="mycelium-pairing",project_id="mycelium-pairing",revision=owner.revision or 1,theme={source="project"},surfaces=surfaces,layout=layout}
end
return M
