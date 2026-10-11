-- Tests for openuf/shaper.lua ("WiFi Speed Limit": per-client tc classes).
-- Run from project root: lua tests/run_tests.lua
--
-- The command shapes pinned here ran against a real kernel and iproute2
-- (Docker lab, 2026-10-11): per-station HTB classes, the aligned u32 MAC
-- matches, the unicast catch-all, the uncapped class and `action pass`, and
-- `tc filter del ... prio` / `tc class del` / `tc class change` in place.

local A, B, C = "02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:03"

-- A fresh module per test (M.applied is module state), with every seam
-- stubbed. fail(cmd) -> true makes that command exit 1, the Lua 5.1 shape.
local function fresh(opts)
	opts = opts or {}
	local sh = dofile("openuf/shaper.lua")
	local env = {cmds = {}, logged = {}, ifindex = opts.ifindex or {wlan0 = 7, wlan1 = 8}, now = 1000}
	sh._exec = function(cmd)
		env.cmds[#env.cmds + 1] = cmd
		if opts.fail and opts.fail(cmd) then return 1 end
		return 0
	end
	sh._read_file = function(p)
		local n = p:match("^/sys/class/net/(.-)/ifindex$")
		local i = n and env.ifindex[n]
		return i and (i .. "\n") or nil
	end
	sh._popen = function() return opts.ls or "lo\nwlan0\nwlan1\n" end
	sh._time = function() return env.now end
	env.sh = sh
	return env
end

local function run_logged(env, fn)
	local orig = io.stderr
	io.stderr = {write = function(_, ...)
		for _, v in ipairs({...}) do env.logged[#env.logged + 1] = tostring(v) end
	end}
	local ok, err = pcall(fn)
	io.stderr = orig
	if not ok then error(err, 0) end
end

local function has(env, needle)
	for _, c in ipairs(env.cmds) do
		if c:find(needle, 1, true) then return true end
	end
	return false
end

local function count(env, needle)
	local n = 0
	for _, c in ipairs(env.cmds) do
		if c:find(needle, 1, true) then n = n + 1 end
	end
	return n
end

local function down_only(default, stas)
	return {wlan0 = {down = {default = default, stas = stas}}}
end

return {
	{
		name = "shaper: download is one HTB class per station, matched on the destination MAC",
		fn = function()
			local e = fresh()
			assert_true(e.sh.sync(down_only(5000, {[A] = 5000, [B] = 5000})))
			assert_true(has(e, "tc qdisc add dev wlan0 root handle 1: htb default 0"), "root, unclassified direct")
			assert_true(has(e, "tc class add dev wlan0 parent 1: classid 1:10 htb rate 5000kbit ceil 5000kbit quantum 1514"),
				"first station's class")
			assert_true(has(e, "tc class add dev wlan0 parent 1: classid 1:11 htb rate 5000kbit ceil 5000kbit quantum 1514"),
				"second station's own class: the limit is per client")
			assert_true(has(e, "tc filter add dev wlan0 parent 1: protocol all prio 16 u32 "
				.. "match u16 0x0200 0xffff at -14 match u32 0x00000001 0xffffffff at -12 flowid 1:10"),
				"destination MAC in aligned keys")
			assert_true(has(e, "tc qdisc add dev wlan0 parent 1:10 handle 8010: fq_codel limit 1000 flows 64"),
				"an fq_codel leaf")
			assert_eq(count(e, "ifb"), 0, "nothing for upload")
		end
	},
	{
		name = "shaper: unicast to an unknown station is capped at the WLAN's limit, group frames are not",
		fn = function()
			local e = fresh()
			e.sh.sync(down_only(3000, {}))
			assert_true(has(e, "classid 1:1 htb rate 3000kbit ceil 3000kbit"), "catch-all class")
			assert_true(has(e, "tc filter add dev wlan0 parent 1: protocol all prio 65000 u32 "
				.. "match u8 0x00 0x01 at -14 flowid 1:1"), "unicast only, matched last")
		end
	},
	{
		name = "shaper: upload is redirected to an IFB and queued there on the source MAC",
		fn = function()
			local e = fresh()
			e.sh.sync({wlan0 = {up = {default = 1000, stas = {[A] = 2000}}}})
			assert_true(has(e, "ip link add name oufb7 type ifb"), "named after the netdev's ifindex")
			assert_true(has(e, "ip link set dev oufb7 up"))
			assert_true(has(e, "tc qdisc add dev wlan0 handle ffff: ingress"))
			assert_true(has(e, "tc filter add dev wlan0 parent ffff: protocol all prio 1 u32 match u32 0 0 "
				.. "action mirred egress redirect dev oufb7"), "every frame to the IFB")
			assert_true(has(e, "tc qdisc add dev oufb7 root handle 1: htb default 0"))
			assert_true(has(e, "tc filter add dev oufb7 parent 1: protocol all prio 16 u32 "
				.. "match u32 0x02000000 0xffffffff at -8 match u16 0x0001 0xffff at -4 flowid 1:10"),
				"source MAC in aligned keys")
			assert_true(has(e, "prio 65000 u32 match u32 0 0 flowid 1:1"), "upload catch-all takes everything")
			assert_eq(count(e, "police"), 0, "queued, not policed")
		end
	},
	{
		name = "shaper: without kmod-ifb upload falls back to per-station policing, and says so once",
		fn = function()
			local e = fresh({fail = function(c) return c:find("type ifb", 1, true) end})
			run_logged(e, function()
				assert_true(e.sh.sync({wlan0 = {up = {default = 1000, stas = {[A] = 2000}}}}),
					"the fallback is a working state")
				e.sh.sync({wlan1 = {up = {default = 1000, stas = {}}}})
			end)
			assert_true(has(e, "tc filter add dev wlan0 parent ffff: protocol all prio 16 u32 "
				.. "match u32 0x02000000 0xffffffff at -8 match u16 0x0001 0xffff at -4 "
				.. "police rate 2000kbit burst 200k drop flowid :1"), "per-station police")
			assert_true(has(e, "prio 65000 u32 match u32 0 0 police rate 1000kbit burst 100k drop"),
				"catch-all police")
			local out = table.concat(e.logged)
			assert_true(out:find("kmod-ifb", 1, true) ~= nil, "names the package")
			local _, n = out:gsub("kmod%-ifb", "")
			assert_eq(n, 1, "once")
		end
	},
	{
		name = "shaper: a station joining or leaving touches only its own class",
		fn = function()
			local e = fresh()
			e.sh.sync(down_only(5000, {[A] = 5000, [B] = 5000}))
			e.cmds = {}
			e.sh.sync(down_only(5000, {[A] = 5000, [C] = 5000}))
			assert_true(has(e, "tc filter del dev wlan0 parent 1: prio 17"), "B's filter")
			assert_true(has(e, "tc class del dev wlan0 classid 1:11"), "B's class")
			assert_true(has(e, "classid 1:11 htb rate 5000kbit"), "C takes the free id")
			assert_eq(count(e, "qdisc del"), 0, "no rebuild: A's queue is left alone")
			assert_eq(count(e, "classid 1:10"), 0, "A untouched")
			e.cmds = {}
			e.sh.sync(down_only(5000, {[A] = 2000, [C] = 5000}))
			assert_eq(#e.cmds, 1, "a new rate is one command")
			assert_eq(e.cmds[1], "tc class change dev wlan0 parent 1: classid 1:10 htb rate 2000kbit "
				.. "ceil 2000kbit quantum 1514 2>/dev/null")
			e.cmds = {}
			e.sh.sync(down_only(5000, {[A] = 2000, [C] = 5000}))
			assert_eq(#e.cmds, 0, "steady state runs nothing")
		end
	},
	{
		name = "shaper: an uncapped station (0) gets its own class, only under a WLAN limit",
		fn = function()
			local e = fresh()
			e.sh.sync(down_only(5000, {[A] = 0}))
			assert_true(has(e, "classid 1:10 htb rate 10000000kbit ceil 10000000kbit"), "out of the catch-all")
			local p = fresh({fail = function(c) return c:find("type ifb", 1, true) end})
			run_logged(p, function() p.sh.sync({wlan0 = {up = {default = 1000, stas = {[A] = 0}}}}) end)
			assert_true(has(p, "match u16 0x0001 0xffff at -4 action pass flowid :1"), "police mode: pass")
			local n = fresh()
			assert_true(n.sh.sync(down_only(nil, {[A] = 0})))
			assert_eq(#n.cmds, 0, "no WLAN limit: nothing to escape, nothing built")
		end
	},
	{
		name = "shaper: a netdev that is no longer wanted is torn down, IFB included",
		fn = function()
			local e = fresh()
			e.sh.sync({wlan0 = {down = {default = 5000, stas = {}}, up = {default = 1000, stas = {}}}})
			e.cmds = {}
			e.sh.sync({})
			assert_true(has(e, "tc qdisc del dev wlan0 root"))
			assert_true(has(e, "tc qdisc del dev wlan0 ingress"))
			assert_true(has(e, "ip link del dev oufb7"))
			assert_nil(next(e.sh.applied), "forgotten")
			e.cmds = {}
			e.sh.sync({})
			assert_eq(#e.cmds, 0, "and not torn down twice")
		end
	},
	{
		name = "shaper: one direction going away leaves the other",
		fn = function()
			local e = fresh()
			e.sh.sync({wlan0 = {down = {default = 5000, stas = {}}, up = {default = 1000, stas = {}}}})
			e.cmds = {}
			e.sh.sync(down_only(5000, {}))
			assert_true(has(e, "tc qdisc del dev wlan0 ingress"))
			assert_eq(count(e, "root"), 0, "download untouched")
		end
	},
	{
		name = "shaper: a recreated netdev (new ifindex) is rebuilt and its old IFB removed",
		fn = function()
			local e = fresh()
			e.sh.sync({wlan0 = {down = {default = 5000, stas = {[A] = 5000}}, up = {default = 1000, stas = {}}}})
			e.ifindex.wlan0 = 21
			e.cmds = {}
			e.sh.sync({wlan0 = {down = {default = 5000, stas = {[A] = 5000}}, up = {default = 1000, stas = {}}}})
			assert_true(has(e, "ip link del dev oufb7"), "the old IFB")
			assert_true(has(e, "tc qdisc add dev wlan0 root handle 1: htb default 0"), "rebuilt")
			assert_true(has(e, "ip link add name oufb21 type ifb"), "a new IFB")
			e.ifindex.wlan0 = nil
			e.cmds = {}
			e.sh.sync({wlan0 = {up = {default = 1000, stas = {}}}})
			assert_true(has(e, "ip link del dev oufb21"), "gone: only its IFB to clean up")
			assert_nil(e.sh.applied.wlan0)
		end
	},
	{
		name = "shaper: changing the WLAN's limit rebuilds that direction",
		fn = function()
			local e = fresh()
			e.sh.sync(down_only(5000, {[A] = 5000}))
			e.cmds = {}
			e.sh.sync(down_only(2000, {[A] = 2000}))
			assert_true(has(e, "tc qdisc del dev wlan0 root"))
			assert_true(has(e, "classid 1:1 htb rate 2000kbit"))
		end
	},
	{
		name = "shaper: a rejected build is reported and retried later, not every heartbeat",
		fn = function()
			local e = fresh({fail = function(c) return c:find("root handle 1: htb", 1, true) end})
			run_logged(e, function()
				assert_false(e.sh.sync(down_only(5000, {[A] = 5000})), "reported")
			end)
			assert_true(table.concat(e.logged):find("download rules on wlan0", 1, true) ~= nil, "names the netdev")
			e.cmds = {}
			run_logged(e, function() e.sh.sync(down_only(5000, {[A] = 5000})) end)
			assert_eq(#e.cmds, 0, "same input, inside the hold: nothing run")
			e.now = e.now + e.sh.RETRY_S
			run_logged(e, function() e.sh.sync(down_only(5000, {[A] = 5000})) end)
			assert_true(has(e, "root handle 1: htb"), "retried after the hold")
			e.cmds = {}
			run_logged(e, function() e.sh.sync(down_only(5000, {[A] = 5000, [B] = 5000})) end)
			assert_true(has(e, "root handle 1: htb"), "and at once when the input changes")
		end
	},
	{
		name = "shaper: a failed incremental change starts the direction over",
		fn = function()
			local fail_change = false
			local e = fresh({fail = function(c) return fail_change and c:find("class change", 1, true) end})
			e.sh.sync(down_only(5000, {[A] = 5000}))
			fail_change = true
			e.cmds = {}
			e.sh.sync(down_only(5000, {[A] = 1000}))
			assert_true(has(e, "tc qdisc del dev wlan0 root"), "torn down")
			assert_true(has(e, "classid 1:10 htb rate 1000kbit"), "and rebuilt at the new rate")
		end
	},
	{
		name = "shaper: a leaf the kernel refuses leaves a working class and one warning",
		fn = function()
			local e = fresh({fail = function(c) return c:find("fq_codel", 1, true) end})
			run_logged(e, function()
				assert_true(e.sh.sync(down_only(5000, {[A] = 5000, [B] = 5000})), "still applied")
			end)
			local _, n = table.concat(e.logged):gsub("fq_codel", "")
			assert_eq(n, 1, "warned once")
		end
	},
	{
		name = "shaper: the first sync removes IFBs and redirects a previous run left",
		fn = function()
			local e = fresh({ls = "lo\nwlan0\noufb7\noufb99\n"})
			e.sh.sync({})
			assert_true(has(e, "tc qdisc del dev wlan0 ingress"), "the redirect into oufb7 (wlan0 is ifindex 7)")
			assert_true(has(e, "ip link del dev oufb7"))
			assert_true(has(e, "ip link del dev oufb99"), "one whose netdev is gone too")
			e.cmds = {}
			e.sh.sync({})
			assert_eq(#e.cmds, 0, "once per process")
		end
	},
	{
		name = "shaper: odd interface names and MACs never reach a command",
		fn = function()
			local e = fresh({ifindex = {["wlan0;reboot"] = 3, wlan0 = 7}})
			e.sh.sync({["wlan0;reboot"] = {down = {default = 5000, stas = {}}},
				wlan0 = {down = {default = nil, stas = {["02:00:00:00:00:0g"] = 5000, ["x;y"] = 5000}}}})
			for _, c in ipairs(e.cmds) do
				assert_nil(c:find("reboot", 1, true), c)
			end
			assert_eq(count(e, "class add"), 0, "no station class for a bad MAC")
		end
	},
	{
		name = "shaper: an all-successful sync reports success on both os.execute shapes",
		fn = function()
			local e = fresh()
			e.sh._exec = function() return true end   -- Lua 5.4 shape
			assert_true(e.sh.sync(down_only(5000, {[A] = 5000})))
		end
	},
}
