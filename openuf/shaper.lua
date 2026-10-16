--[[
	"WiFi Speed Limit" enforcement (Settings -> Profiles -> WiFi Speed Limit,
	chosen per WLAN, or per client in the client's settings).

	THE WIRE

	The WLAN's profile arrives in system_cfg as qos.vap.<m>.dwnlink.maxspeed /
	uplink.1.maxspeed, in kbps, keyed by devname (inform.lua's parser has the
	evidence, and why the presence of *maxspeed* is what marks a VAP as
	limited). A client's own profile, and a guest's limit from the portal,
	arrive as the `rate-update` command ({mac, ul_max, dl_max}, kbps, -1 =
	no limit), sent each time that client connects, roams or reconnects to
	an AP and whenever its profile changes.

	WHAT THE FIRMWARE DOES (firmware-confirmed for 4.0.15)

	The limit is per client, not shared by the SSID. ubntbox's do_qos builds
	an HTB tree per interface (qosLinkInit.sh mode 1), a class per VAP capped
	at the link speed, not at maxspeed (qosLinkAddVap.sh), and hands maxspeed
	down as the per-station default. libubnt's config_sta_qosrule then adds
	one class per associated station under its VAP's class, classid
	(vap id << 11) + associd, with ceil = maxspeed and an sfq leaf: on the
	VAP for download, on the uplink port (eth0) for upload, so both
	directions are queued. Frames reach their station's class by an fwmark
	(the controller's qos.ebt.* ebtables marks plus the driver's associd);
	broadcast and multicast match no station class and pass unshaped. A
	VAP without a limit gets no station classes. `rate-update` changes one
	station's class (update_sta_qosrate, `tc class change`), adding it when
	its VAP had none; -1 lifts that station's cap altogether, even on a
	limited VAP. The class goes when the station disassociates, so an
	override lasts one association.

	WHAT OPENUF DOES

	The same per-station classes, keyed on MAC addresses instead of
	associd marks, which OpenWrt has no equivalent of:

	  * Download: HTB on the VAP netdev's egress. One class per station, the
	    frame's destination MAC picks it (u32 at offset -14). Unicast to a
	    station openUF has not seen yet goes to a class at the WLAN's limit,
	    so a client that connected since the last heartbeat is capped too,
	    if briefly sharing; group-addressed frames pass unshaped.
	  * Upload: the VAP's ingress is redirected to an IFB device (kmod-ifb),
	    and the same tree runs there on the source MAC. Without kmod-ifb,
	    upload falls back to policing (excess dropped, not queued) per
	    station, and says so.

	Each class gets an fq_codel leaf, the qdisc OpenWrt ships by default,
	in place of sfq, which OpenWrt does not ship by default.

	inform.lua owns the inputs: the WLAN limits (UCI openuf_ratelimit_*),
	the stations each netdev lists at a heartbeat, and the rate-update
	ledger. sync() takes the result and changes only what differs from what
	it applied last: a station joining or leaving adds or removes its class
	and filter alone, so the others' queues are left intact. A netdev that
	was recreated (wifi reload) is rebuilt from scratch, found by its
	ifindex.
]]--

local M = {}
local util = package.loaded["openuf.util"]
	or assert(loadfile("util.lua") or loadfile("openuf/util.lua"))()

-- Injectable seams.
M._exec = os.execute
M._read_file = util.read_file
M._popen = function(cmd) return util.popen(cmd) or "" end
M._time = function() return os.time() end

-- os.execute returns the raw exit status on Lua 5.1 (0 = success, non-zero =
-- failure, and BOTH are truthy) and ok/"exit"/code on 5.4+. A bare truth test
-- passes for a failed tc call on the interpreter the APs actually run.
local exec_ok = util.exec_ok
M._exec_ok = exec_ok

M.QUANTUM = 1514
-- fq_codel's default 1024 flows cost ~50 KB per instance; one class per
-- station per direction makes that matter on a 64 MB board.
M.LEAF = "fq_codel limit 1000 flows 64"
M.FIRST_ID = 0x10
M.MAX_ID = 0x7fff
-- Class 1:1, the WLAN's limit for unicast to (or from) a station that has
-- no class of its own yet, matched last.
M.CATCHALL_ID = 1
M.CATCHALL_PRIO = 65000
M.IFB_PREFIX = "oufb"
-- A station whose own limit lifts its WLAN's (rate-update -1) is given 0:
-- a class at this rate, or a pass in police mode, so it stays out of the
-- catch-all.
M.UNCAPPED_KBPS = 10000000
-- A build that failed is retried after this long, or at once when what is
-- wanted changes.
M.RETRY_S = 300

-- [ifname] = {ifindex = n, down = dir, up = dir}, where dir is
-- {dev, mode ("htb" | "police"), ifb, default, stas = {[mac] = {id, kbps}},
--  failed, sig, retry_at}.
M.applied = {}
M._swept = false
M._warned = {}

local function warn_once(key, msg)
	if M._warned[key] then return end
	M._warned[key] = true
	io.stderr:write("openuf: WiFi Speed Limit: " .. msg .. "\n")
end

local function run(cmd)
	return exec_ok(M._exec(cmd .. " 2>/dev/null"))
end

local valid_ifname = util.valid_ifname

local function mac_hex(mac)
	if type(mac) ~= "string" then return nil end
	local h = mac:lower():gsub(":", "")
	if #h ~= 12 or h:find("[^%x]") then return nil end
	return h
end

-- u32 matches are relative to the network header: the Ethernet header is
-- the 14 bytes before it, and a u32 key must sit on a 4-byte boundary (an
-- unaligned one is refused as `Illegal "match"`).
local function match_dst(h)
	return "match u16 0x" .. h:sub(1, 4) .. " 0xffff at -14 match u32 0x" .. h:sub(5, 12)
		.. " 0xffffffff at -12"
end
local function match_src(h)
	return "match u32 0x" .. h:sub(1, 8) .. " 0xffffffff at -8 match u16 0x" .. h:sub(9, 12)
		.. " 0xffff at -4"
end
-- Download catch-all: unicast only, so broadcast and multicast pass
-- unshaped as on the firmware. Upload catch-all: everything.
local CATCH_DOWN = "match u8 0x00 0x01 at -14"
local CATCH_UP = "match u32 0 0"

local function kbps_ok(k)
	k = tonumber(k)
	return k and k > 0 and k < 1e8 and math.floor(k) or nil
end

local function ifindex(ifname)
	return tonumber((M._read_file("/sys/class/net/" .. ifname .. "/ifindex") or ""):match("%d+"))
end

local function class_cmd(verb, dev, id, kbps)
	return string.format("tc class %s dev %s parent 1: classid 1:%x htb rate %dkbit ceil %dkbit quantum %d",
		verb, dev, id, kbps, kbps, M.QUANTUM)
end

-- The burst openUF's police has always used (kbps / 10, in KB): about 0.8 s
-- at the rate, generous because a tight bucket starves TCP far below the
-- limit (lab: 25 KB at 2 Mbit/s gave 0.78 Mbit/s).
local function police(kbps)
	return string.format("police rate %dkbit burst %dk drop", kbps, math.max(math.floor(kbps / 10), 32))
end

-- One station's class and filter (or police filter). kbps 0 = uncapped.
-- Returns ok.
local function add_sta(d, id, h, kbps)
	if d.mode == "police" then
		return run(string.format("tc filter add dev %s parent ffff: protocol all prio %d u32 %s %s flowid :1",
			d.dev, id, match_src(h), kbps == 0 and "action pass" or police(kbps)))
	end
	if not run(class_cmd("add", d.dev, id, kbps == 0 and M.UNCAPPED_KBPS or kbps)) then return false end
	if not run(string.format("tc qdisc add dev %s parent 1:%x handle %x: %s", d.dev, id, id + 0x8000, M.LEAF)) then
		warn_once("leaf", "tc rejected the " .. M.LEAF:match("^%S+") .. " leaf; the per-client queues are plain FIFOs")
	end
	return run(string.format("tc filter add dev %s parent 1: protocol all prio %d u32 %s flowid 1:%x",
		d.dev, id, d.dir == "up" and match_src(h) or match_dst(h), id))
end

local function del_sta(d, id)
	if d.mode == "police" then
		return run(string.format("tc filter del dev %s parent ffff: prio %d", d.dev, id))
	end
	local ok = run(string.format("tc filter del dev %s parent 1: prio %d", d.dev, id))
	return run(string.format("tc class del dev %s classid 1:%x", d.dev, id)) and ok
end

local function change_sta(d, id, h, kbps)
	if d.mode == "police" then
		return del_sta(d, id) and add_sta(d, id, h, kbps)
	end
	return run(class_cmd("change", d.dev, id, kbps == 0 and M.UNCAPPED_KBPS or kbps))
end

local function teardown(ifname, d)
	if not d then return end
	if d.dir == "down" then
		run("tc qdisc del dev " .. ifname .. " root")
	else
		run("tc qdisc del dev " .. ifname .. " ingress")
		if d.ifb then run("ip link del dev " .. d.ifb) end
	end
end

-- The signature of what a direction wants, so a failed build is not
-- retried every heartbeat for the same input.
local function sig(want)
	local macs = {}
	for mac, k in pairs(want.stas) do macs[#macs + 1] = mac .. "=" .. k end
	table.sort(macs)
	return tostring(want.default) .. "|" .. table.concat(macs, ",")
end

local function sorted_keys(t)
	local out = {}
	for k in pairs(t) do out[#out + 1] = k end
	table.sort(out)
	return out
end

local function free_id(used)
	for id = M.FIRST_ID, M.MAX_ID do
		if not used[id] then return id end
	end
	return nil
end

-- Build one direction from scratch on ifname. Returns the new dir state.
local function build(ifname, idx, dir, want)
	local d = {dir = dir, default = want.default, stas = {}, sig = sig(want)}
	local ok = true
	if dir == "down" then
		d.dev, d.mode = ifname, "htb"
		run("tc qdisc del dev " .. ifname .. " root")
		ok = run("tc qdisc add dev " .. ifname .. " root handle 1: htb default 0")
	else
		run("tc qdisc del dev " .. ifname .. " ingress")
		local ifb = M.IFB_PREFIX .. idx
		run("ip link del dev " .. ifb)
		if run("ip link add name " .. ifb .. " type ifb") and run("ip link set dev " .. ifb .. " up") then
			d.dev, d.mode, d.ifb = ifb, "htb", ifb
			ok = run("tc qdisc add dev " .. ifname .. " handle ffff: ingress")
				and run("tc filter add dev " .. ifname .. " parent ffff: protocol all prio 1 u32 "
					.. CATCH_UP .. " action mirred egress redirect dev " .. ifb)
				and run("tc qdisc add dev " .. ifb .. " root handle 1: htb default 0")
		else
			run("ip link del dev " .. ifb)
			warn_once("ifb", "no IFB device (install kmod-ifb); upload limits drop the excess "
				.. "instead of queueing it")
			d.dev, d.mode = ifname, "police"
			ok = run("tc qdisc add dev " .. ifname .. " handle ffff: ingress")
		end
	end
	if ok and d.default then
		if d.mode == "police" then
			ok = run(string.format("tc filter add dev %s parent ffff: protocol all prio %d u32 %s %s flowid :1",
				d.dev, M.CATCHALL_PRIO, CATCH_UP, police(d.default)))
		else
			ok = run(class_cmd("add", d.dev, M.CATCHALL_ID, d.default))
			if ok then
				run(string.format("tc qdisc add dev %s parent 1:%x handle %x: %s", d.dev, M.CATCHALL_ID,
					M.CATCHALL_ID + 0x8000, M.LEAF))
				ok = run(string.format("tc filter add dev %s parent 1: protocol all prio %d u32 %s flowid 1:%x",
					d.dev, M.CATCHALL_PRIO, dir == "up" and CATCH_UP or CATCH_DOWN, M.CATCHALL_ID))
			end
		end
	end
	local used = {}
	for _, mac in ipairs(sorted_keys(want.stas)) do
		if not ok then break end
		local id = free_id(used)
		if not id then break end
		used[id] = true
		ok = add_sta(d, id, mac_hex(mac), want.stas[mac])
		if ok then d.stas[mac] = {id = id, kbps = want.stas[mac]} end
	end
	if not ok then
		d.failed = true
		d.retry_at = M._time() + M.RETRY_S
		io.stderr:write(string.format("openuf: WiFi Speed Limit: tc rejected the %s rules on %s; "
			.. "retrying in %d s\n", dir == "down" and "download" or "upload", ifname, M.RETRY_S))
	end
	return d
end

-- Bring one direction from cur to want with the fewest changes. Returns the
-- new dir state, nil when nothing is shaped that way.
local function sync_dir(ifname, idx, dir, cur, want)
	if not want or (not want.default and not next(want.stas)) then
		teardown(ifname, cur)
		return nil
	end
	if cur and cur.failed then
		if cur.sig == sig(want) and M._time() < cur.retry_at then return cur end
		teardown(ifname, cur)
		return build(ifname, idx, dir, want)
	end
	if not cur or cur.default ~= want.default then
		teardown(ifname, cur)
		return build(ifname, idx, dir, want)
	end
	local ok = true
	local used = {}
	for mac, s in pairs(cur.stas) do
		local k = want.stas[mac]
		if not k then
			ok = del_sta(cur, s.id) and ok
			cur.stas[mac] = nil
		else
			used[s.id] = true
			if k ~= s.kbps then
				ok = change_sta(cur, s.id, mac_hex(mac), k) and ok
				s.kbps = k
			end
		end
	end
	for _, mac in ipairs(sorted_keys(want.stas)) do
		if not cur.stas[mac] then
			local id = free_id(used)
			if id then
				used[id] = true
				ok = add_sta(cur, id, mac_hex(mac), want.stas[mac]) and ok
				cur.stas[mac] = {id = id, kbps = want.stas[mac]}
			end
		end
	end
	cur.sig = sig(want)
	if ok then return cur end
	-- Something on the netdev is not what was applied: start over.
	teardown(ifname, cur)
	return build(ifname, idx, dir, want)
end

-- IFB devices a previous run left behind, once per process, with the
-- ingress redirect of the netdev each one served (its name carries that
-- netdev's ifindex): a redirect to a deleted device drops every frame.
local function sweep()
	M._swept = true
	local names = {}
	for name in M._popen("ls /sys/class/net 2>/dev/null"):gmatch("%S+") do names[#names + 1] = name end
	local by_index = {}
	for _, name in ipairs(names) do
		local idx = valid_ifname(name) and ifindex(name)
		if idx then by_index[idx] = name end
	end
	for _, name in ipairs(names) do
		local idx = tonumber(name:match("^" .. M.IFB_PREFIX .. "(%d+)$"))
		if idx then
			if by_index[idx] then run("tc qdisc del dev " .. by_index[idx] .. " ingress") end
			run("ip link del dev " .. name)
		end
	end
end

-- Normalise one direction of desired: {default = kbps, stas = {[mac] = kbps}},
-- a station's 0 meaning uncapped, which only matters under a default.
local function norm(w)
	local out = {default = kbps_ok(w and w.default), stas = {}}
	for mac, k in pairs((w and w.stas) or {}) do
		local kb = kbps_ok(k)
		if not kb and tonumber(k) == 0 and out.default then kb = 0 end
		if mac_hex(mac) and kb then out.stas[mac:lower()] = kb end
	end
	return out
end

-- desired: {[ifname] = {down = {default = kbps, stas = {[mac] = kbps}},
--                       up = {...}}}; a station's kbps 0 = uncapped.
-- A netdev missing from desired has its shaping removed. Returns true when
-- every netdev ended up as wanted.
function M.sync(desired)
	if not M._swept then sweep() end
	desired = desired or {}
	for _, ifname in ipairs(sorted_keys(M.applied)) do
		if not desired[ifname] then
			local a = M.applied[ifname]
			teardown(ifname, a.down)
			teardown(ifname, a.up)
			M.applied[ifname] = nil
		end
	end
	local all_ok = true
	for _, ifname in ipairs(sorted_keys(desired)) do
		if valid_ifname(ifname) then
			local idx = ifindex(ifname)
			local cur = M.applied[ifname]
			if not idx then
				-- Gone with its qdiscs; only its IFB is left to remove.
				if cur and cur.up and cur.up.ifb then run("ip link del dev " .. cur.up.ifb) end
				M.applied[ifname] = nil
			else
				if cur and cur.ifindex ~= idx then
					if cur.up and cur.up.ifb then run("ip link del dev " .. cur.up.ifb) end
					cur = nil
				end
				cur = cur or {ifindex = idx}
				local w = desired[ifname]
				cur.down = sync_dir(ifname, idx, "down", cur.down, norm(w.down))
				cur.up = sync_dir(ifname, idx, "up", cur.up, norm(w.up))
				if (cur.down and cur.down.failed) or (cur.up and cur.up.failed) then all_ok = false end
				M.applied[ifname] = (cur.down or cur.up) and cur or nil
			end
		end
	end
	return all_ok
end

return M
