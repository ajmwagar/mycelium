local M = dofile("config/canvas/pairing.lua")
local p = {mode="connection",target_endpoint_id=string.rep("a",64),target_server_name="peer.test",observed_at=100,expires_at=200,direct_address_hints={"192.168.10.74:1234"}}
local owner = {target_endpoint_id=p.target_endpoint_id,now=150,target_name="home-pi",target_site="wagar-house",display_name="Living-room TV",tv=true,qr_asset={sha256=string.rep("b",64),media_type="image/svg+xml",byte_length=200}}
local d = M.render(p,owner)
assert(#d.surfaces==2 and d.layout.axis=="horizontal")
assert(d.surfaces[1].content.spec.body:find("Displayed on: Living%-room TV"))
owner.tv=false
assert(M.render(p,owner).layout.axis=="vertical")
owner.now=200
assert(#M.render(p,owner).surfaces==1, "QR must disappear at expiry")
owner.target_endpoint_id=string.rep("c",64)
assert(not pcall(M.render,p,owner), "wrong target must fail")
owner.target_endpoint_id=p.target_endpoint_id
p.mode="invite"
assert(not pcall(M.render,p,owner), "no invite authority in renderer")
p.mode="connection"; owner.now=99
assert(not pcall(M.render,p,owner), "future hints must fail")
print("pairing presentation: 6 checks passed")
