--[[
	Guest portal (Hotspot) enforcement: the controller's guest ebtables rules,
	re-expressed in nftables, plus the HTTP answer that sends an unauthorized
	guest to the portal. LAB-VALIDATED ONLY (2026-10-10): never run against a
	real guest WLAN on the production APs.

	What the controller pushes (PROTOCOL-VALIDATION.md, "Guest portal
	(Hotspot)"): a GUESTIN chain on every guest VAP's ingress (policy DROP)
	and a GUESTOUT chain on its egress, ~47 ebtables fragments in all, plus
	redirector.url (the portal) and three iptables REDIRECTs for the frames
	the ebtables rules mark. The stock firmware's own parts are the
	AUTHORIZED_GUESTS chain -- pushed empty, the device fills it from
	authorize-guest -- and a local HTTP/DNS answerer for the marked frames.

	Not a verbatim translator. parse() reads the facts the rules carry: the
	(ip, port) pairs a guest may always reach (the portal), the ones to
	answer locally (`-I GUESTIN ... -j REDIRECT_HTTP`), and the subnets
	dropped either way. reconcile() builds openUF's own chains from them, in
	the stock order:

	  in:  EAPOL, portal accepts, intercepts, broadcast DHCP request, ARP,
	       DNS -> accept; IPv6, other broadcast, multicast, restricted
	       subnets -> drop; authorized MAC to another host -> accept;
	       tcp 80 -> local answer; everything else -> drop
	  out: DHCP reply, ARP -> accept; IPv6, other broadcast, multicast -> drop

	ahead of both, a per-guest rate limit from rate-update (set_rates), and
	after the authorized accept a `selfrun` chain that lets every guest
	through while the controller is unreachable (set_selfrun); with
	selfrun_guest_mode=off the guest VAPs go down instead (set_vaps_up).

	Deliberate narrowings, all of them stated in README/USAGE:
	- DNS passes for every guest. The stock firmware answers an unauthorized
	  guest's DNS itself (dnsmasq on br0); openUF runs no resolver, and a
	  captive-portal check needs real answers to reach the HTTP step at all.
	- No HTTPS answer. Marked 443 would need a certificate the client
	  trusts; it is dropped, so the client's HTTP probe is what finds the
	  portal.
	- The local answer needs an IPv4 address on the guest VAP's bridge: the
	  frame is handed to the bridge's own stack (ebtables `redirect`, here
	  `ether daddr set` + `pkttype set host`) and NAT-redirected to M.PORT,
	  and the reply leaves from that bridge. A guest WLAN on a VLAN bridge
	  without an address stays blocked but sees no portal.

	Mechanism as in firewall.lua/l2guard.lua: own tables, rebuilt from
	scratch on every reconcile, kernel state that dies with a reboot and is
	rebuilt at startup from state.json. The authorized set alone is
	refreshed in place (set_authorized), so an authorize-guest does not open
	a gap in the rest.
]]--

local M = {}

M._exec = function(cmd) return os.execute(cmd) end

local function exec_ok(status)
	return status == true or status == 0
end

M.BRIDGE_TABLE = "bridge openuf_guest"
M.NAT_TABLE    = "ip openuf_guest"
-- The stock REDIRECT_HTTP mark; the iptables side matches it under
-- 0xc0000000.
M.MARK_HTTP    = "0x40000000"
-- Where the NAT-redirected HTTP is answered. Not 80: uhttpd/LuCI may hold it.
M.PORT         = 8820

-- ─── Parsing ─────────────────────────────────────────────────────────────────

local function is_ipv4(s)
	if type(s) ~= "string" then return false end
	local a, b, c, d = s:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
	if not a then return false end
	for _, o in ipairs({a, b, c, d}) do
		if tonumber(o) > 255 then return false end
	end
	return true
end

local function is_cidr(s)
	if type(s) ~= "string" then return false end
	local ip, len = s:match("^([%d%.]+)/(%d+)$")
	if ip then return is_ipv4(ip) and tonumber(len) <= 32 end
	return is_ipv4(s)
end

local function is_port(s)
	local n = tonumber(s)
	return n ~= nil and n >= 1 and n <= 65535 and n == math.floor(n)
end

-- The fixed skeleton of the guest ruleset: chain declarations and rules the
-- chains above re-create by construction. %S+ stands for a VAP name.
local SKELETON = {
	"^%-t nat %-N GUESTIN %-P DROP$",
	"^%-t nat %-N GUESTOUT %-P ACCEPT$",
	"^%-t nat %-A POSTROUTING %-%-out%-interface %S+ %-j GUESTOUT$",
	"^%-t nat %-A GUESTIN %-%-in%-interface %S+ %-%-proto 0x888e %-j ACCEPT$",
	"^%-t nat %-A GUESTIN %-p 0x800 %-%-pkttype%-type broadcast %-%-ip%-proto 17 %-%-ip%-sport 68 %-%-ip%-dport 67 %-j ACCEPT$",
	"^%-t nat %-A GUESTIN %-p arp %-j ACCEPT$",
	"^%-t nat %-N GUEST_DNS %-P DROP$",
	"^%-t nat %-A GUESTIN %-p 0x800 %-%-ip%-proto 17 %-%-ip%-dport 53 %-j GUEST_DNS$",
	"^%-t nat %-A GUESTIN %-p 0x800 %-%-ip%-proto 6 %-%-ip%-dport 53 %-j GUEST_DNS$",
	"^%-t nat %-A GUESTIN %-p 0x86dd %-j DROP$",
	"^%-t nat %-A GUESTIN %-%-pkttype%-type broadcast %-j DROP$",
	"^%-t nat %-A GUESTOUT %-p 0x800 %-%-pkttype%-type broadcast %-%-ip%-proto 17 %-%-ip%-sport 67 %-%-ip%-dport 68 %-j ACCEPT$",
	"^%-t nat %-A GUESTOUT %-p arp %-j ACCEPT$",
	"^%-t nat %-A GUESTOUT %-p 0x86dd %-j DROP$",
	"^%-t nat %-A GUESTOUT %-%-pkttype%-type broadcast %-j DROP$",
	"^%-t nat %-N CAPTIVE_PORTAL %-P RETURN$",
	"^%-t nat %-A GUESTIN %-p 0x800 %-%-ip%-proto 6 %-%-ip%-dport 443 %-j CAPTIVE_PORTAL$",
	"^%-t nat %-N REDIRECT_HTTP$",
	"^%-t nat %-A REDIRECT_HTTP %-j mark %-%-mark%-or 0x40000000 %-%-mark%-target CONTINUE$",
	"^%-t nat %-A REDIRECT_HTTP %-j redirect$",
	"^%-t nat %-N REDIRECT_HTTPS$",
	"^%-t nat %-A REDIRECT_HTTPS %-j mark %-%-mark%-or 0x80000000 %-%-mark%-target CONTINUE$",
	"^%-t nat %-A REDIRECT_HTTPS %-j redirect$",
	"^%-t nat %-N AUTHORIZED_GUESTS %-P RETURN$",
	"^%-t nat %-A GUESTIN %-p 0x800 %-%-pkttype%-type otherhost %-j AUTHORIZED_GUESTS$",
	"^%-t nat %-A GUESTIN %-p 0x800 %-%-ip%-proto 6 %-%-ip%-dport 80 %-j REDIRECT_HTTP$",
	"^%-t nat %-A GUESTIN %-p 0x800 %-%-ip%-proto 6 %-%-ip%-dport 443 %-j REDIRECT_HTTPS$",
	"^%-t nat %-N REDIRECT_DNS$",
	"^%-t nat %-A REDIRECT_DNS %-j mark %-%-mark%-or 0x40000000 %-%-mark%-target CONTINUE$",
	"^%-t nat %-A REDIRECT_DNS %-j redirect$",
	"^%-t nat %-A GUEST_DNS %-p 0x800 %-%-ip%-proto 17 %-%-ip%-dport 53 %-j AUTHORIZED_GUESTS$",
	"^%-t nat %-A GUEST_DNS %-p 0x800 %-%-ip%-proto 6 %-%-ip%-dport 53 %-j AUTHORIZED_GUESTS$",
	"^%-t nat %-A GUEST_DNS %-p 0x800 %-%-ip%-proto 17 %-%-ip%-dport 53 %-j REDIRECT_DNS$",
	"^%-t nat %-A GUEST_DNS %-p 0x800 %-%-ip%-proto 6 %-%-ip%-dport 53 %-j REDIRECT_DNS$",
}

-- Chains only the guest ruleset uses: a rule naming one of them is the
-- portal's, whether or not parse() knows its shape.
local GUEST_CHAINS = {"GUESTIN", "GUESTOUT", "GUEST_DNS", "CAPTIVE_PORTAL",
	"REDIRECT_HTTP", "REDIRECT_HTTPS", "REDIRECT_DNS", "AUTHORIZED_GUESTS"}

-- Whether an ebtables fragment belongs to the guest ruleset (l2guard leaves
-- these to this module rather than reporting them as unrecognised).
function M.is_guest_rule(v)
	if type(v) ~= "string" then return false end
	for _, c in ipairs(GUEST_CHAINS) do
		if (" " .. v .. " "):find(" " .. c .. " ", 1, true) then return true end
	end
	return false
end

-- One guest-ruleset fragment into spec. Returns false when the shape is
-- not known.
local function classify(v, spec)
	local dev = v:match("^%-t nat %-A PREROUTING %-%-in%-interface (%S+) %-j GUESTIN$")
	if dev then
		spec.devs[#spec.devs + 1] = dev
		return true
	end
	for _, p in ipairs(SKELETON) do
		if v:match(p) then return true end
	end
	local port, ip = v:match("^%-t nat %-A GUESTIN %-p 0x800 %-%-ip%-proto 6 %-%-ip%-dport (%d+) %-%-ip%-dst (%S+) %-j ACCEPT$")
	if not port then
		ip, port = v:match("^%-t nat %-I GUESTIN %-p 0x800 %-%-ip%-dst (%S+) %-%-ip%-proto 6 %-%-ip%-dport (%d+) %-j ACCEPT$")
	end
	if port then
		if not (is_ipv4(ip) and is_port(port)) then return false end
		spec.accept[#spec.accept + 1] = {ip = ip, port = tonumber(port)}
		return true
	end
	ip, port = v:match("^%-t nat %-I GUESTIN %-p 0x800 %-%-ip%-dst (%S+) %-%-ip%-proto 6 %-%-ip%-dport (%d+) %-j REDIRECT_HTTP$")
	if ip then
		if not (is_ipv4(ip) and is_port(port)) then return false end
		spec.intercept[#spec.intercept + 1] = {ip = ip, port = tonumber(port)}
		return true
	end
	local chain, net = v:match("^%-t nat %-A (GUEST[IO][NU]T?) %-p 0x800 %-%-ip%-dst (%S+) %-j DROP$")
	if chain == "GUESTIN" or chain == "GUESTOUT" then
		if not is_cidr(net) then return false end
		local list = chain == "GUESTIN" and spec.restrict or spec.restrict_out
		list[#list + 1] = net
		return true
	end
	return false
end

-- The portal as pushed, or nil when the blob does not say (no
-- redirector.status: a partial push). enabled is false when the portal is
-- off, or on but without the facts to enforce it (no URL, no GUESTIN hook).
function M.parse(sys_raw)
	if type(sys_raw) ~= "string" then return nil end
	local spec = {enabled = false, devs = {}, accept = {}, intercept = {},
		restrict = {}, restrict_out = {}, unknown = {}}
	local status
	for line in (sys_raw .. "\n"):gmatch("([^\n]*)\n") do
		local k, v = line:match("^([^=]+)=(.*)$")
		if k == "redirector.status" then
			status = v
		elseif k == "redirector.url" then
			-- Spliced into a Location header: one token, http(s) only.
			if v:match("^https?://[%w%.%-:%[%]]+[%S]*$") and not v:find("[%c\"<>\\]") then
				spec.url = v
			end
		elseif k and k:match("^ebtables%.%d+%.cmd$") and M.is_guest_rule(v) then
			if not classify(v, spec) then spec.unknown[#spec.unknown + 1] = v end
		end
	end
	if status == nil then return nil end
	spec.enabled = (status == "enabled" and spec.url ~= nil and #spec.devs > 0)
	return spec
end

-- ─── Apply ───────────────────────────────────────────────────────────────────

local function valid_ifname(s)
	return type(s) == "string" and s:match("^[%w%-%._]+$") ~= nil and #s <= 15
end

local function is_mac(s)
	return type(s) == "string" and s:match("^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$") ~= nil
end

M._read = function(path)
	local f = io.open(path, "r")
	if not f then return nil end
	local s = f:read("*a")
	f:close()
	return s
end

-- The MAC of the bridge a VAP is enslaved to, or nil when it is not bridged.
function M.bridge_mac(ifname)
	if not valid_ifname(ifname) then return nil end
	local raw = M._read("/sys/class/net/" .. ifname .. "/master/address")
	local mac = raw and raw:match("^%s*(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
	return mac and mac:lower() or nil
end

local function nft(args)
	return exec_ok(M._exec("nft " .. args))
end

-- Refill the authorized set from macs (a list). Elements go in chunks, so a
-- full ledger does not make one huge command line.
function M.set_authorized(macs)
	if not nft("flush set " .. M.BRIDGE_TABLE .. " authorized 2>/dev/null") then return false end
	local chunk = {}
	local function flush()
		if #chunk == 0 then return end
		nft("add element " .. M.BRIDGE_TABLE .. " authorized '{ " .. table.concat(chunk, ", ") .. " }'")
		chunk = {}
	end
	for _, mac in ipairs(macs or {}) do
		if is_mac(mac) then
			chunk[#chunk + 1] = mac:lower()
			if #chunk >= 64 then flush() end
		end
	end
	flush()
	return true
end

-- One rate_up/rate_down rule set per limited guest, from rate-update
-- ({mac=, up=kbps, down=kbps}; nil, 0 or -1 = no limit that way). Policed
-- with nft `limit`, not queued: the per-VAP WiFi Speed Limit (shaper.lua)
-- owns the VAP's tc root qdisc, and a guest's frames cross this table in
-- both directions anyway. Excess is dropped and TCP backs off. ul_min /
-- dl_min (a 64 kbps floor) need queueing and are not applied.
M.RATE_BURST_S = 0.1
M.RATE_BURST_MIN = 16 * 1514
local function rate_rule(dir, mac, kbps)
	local bytes = math.floor(kbps * 125)
	local burst = math.max(math.floor(bytes * M.RATE_BURST_S), M.RATE_BURST_MIN)
	return "ether " .. dir .. " " .. mac .. " limit rate over " .. string.format("%.0f", bytes)
		.. " bytes/second burst " .. string.format("%.0f", burst) .. " bytes drop"
end
local function limited(kbps)
	kbps = tonumber(kbps)
	return kbps and kbps > 0 and kbps < 1e7 and kbps or nil
end

function M.set_rates(rates)
	local T = M.BRIDGE_TABLE
	if not nft("flush chain " .. T .. " rate_up 2>/dev/null") then return false end
	nft("flush chain " .. T .. " rate_down 2>/dev/null")
	local ok = true
	for _, r in ipairs(rates or {}) do
		if is_mac(r.mac) then
			local mac = r.mac:lower()
			local up, down = limited(r.up), limited(r.down)
			if up and not nft("add rule " .. T .. " rate_up '" .. rate_rule("saddr", mac, up) .. "'") then ok = false end
			if down and not nft("add rule " .. T .. " rate_down '" .. rate_rule("daddr", mac, down) .. "'") then ok = false end
		end
	end
	if not ok then
		io.stderr:write("openuf: guestportal: nft rejected a guest rate limit (nft_limit?); "
			.. "some guests are not rate-limited\n")
	end
	return ok
end

-- selfrun_guest_mode=pass while the controller is unreachable (the firmware's
-- AUTHORIZED_GUESTS ACCEPT-all): every guest
-- is let through as an authorized one would be (to other hosts only, and
-- still not into the restricted subnets), since nobody can log in to the
-- portal meanwhile. An empty chain otherwise. Refreshed in place.
function M.set_selfrun(pass)
	if not nft("flush chain " .. M.BRIDGE_TABLE .. " selfrun 2>/dev/null") then return false end
	if pass then
		return nft("add rule " .. M.BRIDGE_TABLE .. " selfrun 'meta pkttype other accept'")
	end
	return true
end

-- selfrun_guest_mode=off while the controller is unreachable: the guest
-- WLANs are taken down (ifnames, a list) and brought back up after, as the
-- UniFi firmware does with ifconfig. hostapd re-enables a BSS whose netdev
-- comes back up. Returns false if any interface refused.
function M.set_vaps_up(ifnames, up)
	local ok = true
	for _, n in ipairs(ifnames or {}) do
		if not (valid_ifname(n) and exec_ok(M._exec("ip link set dev " .. n
				.. (up and " up" or " down") .. " 2>/dev/null"))) then
			ok = false
		end
	end
	return ok
end

-- Rebuild both tables for spec on these VAPs ({ifname=, bridge_mac=}), with
-- macs authorized, rates (see set_rates) and selfrun (see set_selfrun) applied. Returns the number of
-- rules installed (0, tables gone, when there is nothing to enforce or
-- nothing to enforce it on).
function M.reconcile(spec, vaps, macs, rates, selfrun)
	M._exec("nft delete table " .. M.BRIDGE_TABLE .. " 2>/dev/null")
	M._exec("nft delete table " .. M.NAT_TABLE .. " 2>/dev/null")
	if type(spec) ~= "table" or not spec.enabled then return 0 end
	local names, redirect = {}, {}
	for _, v in ipairs(vaps or {}) do
		if valid_ifname(v.ifname) then
			names[#names + 1] = '"' .. v.ifname .. '"'
			if is_mac(v.bridge_mac) then redirect[#redirect + 1] = v end
		else
			io.stderr:write("guestportal: ignoring odd interface name "
				.. ("%q"):format(tostring(v.ifname)) .. "\n")
		end
	end
	if #names == 0 then
		io.stderr:write("guestportal: no guest interfaces up yet -- rules deferred\n")
		return 0
	end
	local T = M.BRIDGE_TABLE
	local set = "{ " .. table.concat(names, ", ") .. " }"
	nft("add table " .. T)
	nft("add set " .. T .. " authorized '{ type ether_addr; }'")
	nft("add chain " .. T .. " pre '{ type filter hook prerouting priority -300; policy accept; }'")
	nft("add chain " .. T .. " post '{ type filter hook postrouting priority 0; policy accept; }'")
	nft("add chain " .. T .. " guestin")
	nft("add chain " .. T .. " guestout")
	nft("add chain " .. T .. " redirect_http")
	nft("add chain " .. T .. " rate_up")
	nft("add chain " .. T .. " rate_down")
	nft("add chain " .. T .. " selfrun")

	local rules = {
		-- Rate limits first: guestin/guestout end in accept.
		{"pre",  "iifname " .. set .. " jump rate_up"},
		{"pre",  "iifname " .. set .. " jump guestin"},
		{"post", "oifname " .. set .. " jump rate_down"},
		{"post", "oifname " .. set .. " jump guestout"},
		{"guestin", "ether type 0x888e accept"},
	}
	local function add(chain, rule) rules[#rules + 1] = {chain, rule} end
	-- The controller inserts these at the top (-I): ahead of every drop.
	for _, a in ipairs(spec.intercept) do
		add("guestin", "ip daddr " .. a.ip .. " tcp dport " .. a.port .. " jump redirect_http")
	end
	for _, a in ipairs(spec.accept) do
		add("guestin", "ip daddr " .. a.ip .. " tcp dport " .. a.port .. " accept")
	end
	add("guestin", "meta pkttype broadcast udp sport 68 udp dport 67 accept")
	add("guestin", "ether type arp accept")
	add("guestin", "ether type ip udp dport 53 accept")
	add("guestin", "ether type ip tcp dport 53 accept")
	add("guestin", "ether type ip6 drop")
	add("guestin", "meta pkttype broadcast drop")
	for _, net in ipairs(spec.restrict) do
		add("guestin", "ip daddr " .. net .. " drop")
	end
	-- AUTHORIZED_GUESTS: --pkttype-type otherhost, i.e. not to the AP itself.
	add("guestin", "ether saddr @authorized meta pkttype other accept")
	add("guestin", "jump selfrun")
	add("guestin", "tcp dport 80 jump redirect_http")
	add("guestin", "drop")
	add("redirect_http", "meta mark set meta mark or " .. M.MARK_HTTP)
	for _, v in ipairs(redirect) do
		add("redirect_http", 'iifname "' .. v.ifname .. '" ether daddr set ' .. v.bridge_mac:lower()
			.. " meta pkttype set host accept")
	end
	add("redirect_http", "drop")
	add("guestout", "meta pkttype broadcast udp sport 67 udp dport 68 accept")
	add("guestout", "ether type arp accept")
	add("guestout", "ether type ip6 drop")
	add("guestout", "meta pkttype broadcast drop")
	for _, net in ipairs(spec.restrict_out) do
		add("guestout", "ip daddr " .. net .. " drop")
	end

	local n, failed = 0, 0
	for _, r in ipairs(rules) do
		if nft("add rule " .. T .. " " .. r[1] .. " '" .. r[2] .. "'") then
			n = n + 1
		else
			failed = failed + 1
			io.stderr:write("openuf: guestportal: nft rejected " .. ("%q"):format(r[2]) .. "\n")
		end
	end
	if failed > 0 then
		io.stderr:write("openuf: guestportal: " .. failed .. " rule(s) not installed; iifname/oifname in "
			.. "the bridge family need kmod-nft-bridge. The guest portal is NOT fully enforced.\n")
	end
	M.set_authorized(macs)
	M.set_rates(rates)
	M.set_selfrun(selfrun)

	-- The marked frames reach the bridge's own stack; send them to M.PORT.
	nft("add table " .. M.NAT_TABLE)
	nft("add chain " .. M.NAT_TABLE .. " pre '{ type nat hook prerouting priority -101; }'")
	if nft("add rule " .. M.NAT_TABLE .. " pre 'meta mark and 0xc0000000 == " .. M.MARK_HTTP
			.. " meta l4proto tcp redirect to :" .. M.PORT .. "'") then
		n = n + 1
	else
		io.stderr:write("openuf: guestportal: nft rejected the NAT redirect (kmod-nft-nat?). "
			.. "Guests stay blocked but are not shown the portal.\n")
	end
	if #redirect < #names then
		io.stderr:write("openuf: guestportal: " .. (#names - #redirect) .. " guest interface(s) not "
			.. "bridged; their guests are blocked but not shown the portal\n")
	end
	return n
end

-- ─── The HTTP answer ────────────────────────────────────────────────────────

local function urlencode(s)
	return (tostring(s):gsub("[^%w%-%._~]", function(c)
		return string.format("%%%02X", c:byte())
	end))
end

-- The station MAC behind an IPv4 address, from /proc/net/arp's text.
function M.arp_mac(ip, text)
	for line in ((text or "") .. "\n"):gmatch("([^\n]*)\n") do
		local a, flags, mac = line:match("^(%S+)%s+%S+%s+(%S+)%s+(%S+)")
		if a == ip and tonumber(flags) and tonumber(flags) % 4 >= 2 and is_mac(mac)
				and mac ~= "00:00:00:00:00:00" then
			return mac:lower()
		end
	end
	return nil
end

-- Where the portal is: the controller's redirect handler takes the guest
-- from id=, the AP from ap=, and refuses a t= more than 60 s from its own
-- clock (PROTOCOL-VALIDATION.md, "Guest portal (Hotspot)").
function M.location(ctx, mac, orig_url, ssid, now)
	local q = {"id=" .. urlencode(mac), "ap=" .. urlencode(ctx.ap or ""), "t=" .. string.format("%.0f", now)}
	if orig_url then q[#q + 1] = "url=" .. urlencode(orig_url) end
	if ssid then q[#q + 1] = "ssid=" .. urlencode(ssid) end
	return ctx.url .. (ctx.url:find("?", 1, true) and "&" or "?") .. table.concat(q, "&")
end

-- The request line and Host header, read with a bound: a guest is not
-- allowed to hold the inform loop.
local function read_request(client)
	local first, host
	for i = 1, 32 do
		local line = client:receive("*l")
		if not line or line == "" then break end
		if i == 1 then
			first = line
		else
			local h = line:match("^[Hh][Oo][Ss][Tt]:%s*([%w%.%-:%[%]]+)%s*$")
			if h then host = h end
		end
	end
	local path = first and first:match("^%u+ (/%S*) HTTP/%d%.%d$")
	if host and path and #path <= 1024 then return "http://" .. host .. path end
	return nil
end

-- Answer one waiting connection, if any. ctx: {url, ap, ssid_for(mac) or nil,
-- arp() -> /proc/net/arp text, now()}. Returns true when it answered.
function M.serve_one(server, ctx)
	local client = server:accept()
	if not client then return false end
	client:settimeout(1)
	local ok, err = pcall(function()
		local ip = client:getpeername()
		local orig = read_request(client)
		local mac = ip and M.arp_mac(ip, ctx.arp())
		if not mac then
			client:send("HTTP/1.1 503 Service Unavailable\r\nRetry-After: 1\r\n"
				.. "Content-Length: 0\r\nConnection: close\r\n\r\n")
			return
		end
		local ssid = ctx.ssid_for and ctx.ssid_for(mac) or nil
		client:send("HTTP/1.1 302 Found\r\nLocation: " .. M.location(ctx, mac, orig, ssid, ctx.now())
			.. "\r\nCache-Control: no-cache, no-store\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	end)
	client:close()
	if not ok then io.stderr:write("guestportal: answer failed: " .. tostring(err) .. "\n") end
	return true
end

-- A listening socket on M.PORT, or nil and the error.
function M.listen(socket)
	local server, err = socket.bind("*", M.PORT)
	if not server then return nil, err end
	server:settimeout(0)
	return server
end

return M
