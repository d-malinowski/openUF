-- Tests for openuf/rrbguard.lua: spotting hostapd's stale 802.11r
-- key-exchange socket and repairing it at a cheap moment.
-- Run from project root: lua tests/run_tests.lua

local g = dofile("openuf/rrbguard.lua")

-- /proc/net/packet as the office AP printed it (2026-10-11), with the
-- 0x88b7 row's interface given.
local function packet(rrb_iface)
	return "sk               RefCnt Type Proto  Iface R Rmem   User   Inode\n"
		.. "000000006a0b7ddd 3      3    0003   17    1 0      121    21731903\n"
		.. "00000000e68982db 3      3    88b7   " .. rrb_iface .. "    1 0      101    65984491\n"
		.. "00000000d8ac6e24 3      3    890d   17    1 0      101    66022987\n"
end
local HEALTHY = packet("17")
local STALE   = packet("-1")

-- Fresh module state plus recording seams. sta: what station_count sees.
local function setup(text, sta)
	g.reset()
	local env = {text = text, sta = sta, execs = {}, logs = {}, popens = 0}
	g._read  = function() return env.text end
	g._popen = function() env.popens = env.popens + 1; return env.sta and (tostring(env.sta) .. "\n") end
	g._exec  = function(cmd) env.execs[#env.execs + 1] = cmd end
	g._log   = function(msg) env.logs[#env.logs + 1] = msg end
	return env
end

return {
	{
		name = "rrbguard: stale() is the 0x88b7 row on ifindex -1 and nothing else",
		fn = function()
			assert_true(g.stale(STALE), "88b7 on -1")
			assert_true(not g.stale(HEALTHY), "88b7 on br-lan's ifindex")
			assert_true(not g.stale(packet("-1"):gsub("88b7", "0003")), "another protocol on -1 is not ours")
			assert_true(not g.stale("sk RefCnt Type Proto Iface R Rmem User Inode\n"), "no FT: no 88b7 socket at all")
			assert_true(not g.stale(nil), "unreadable file")
			assert_true(g.stale(packet("-1"):gsub("88b7", "88B7")), "hex case does not matter")
		end
	},
	{
		name = "rrbguard: a healthy socket costs one file read a minute and spawns nothing",
		fn = function()
			local env = setup(HEALTHY, 3)
			assert_eq(g.tick(1000, 14), "ok", "checked")
			assert_eq(g.tick(1030, 14), nil, "not again within the minute")
			assert_eq(g.tick(1060, 14), "ok", "a minute later")
			assert_eq(env.popens, 0, "no station count")
			assert_eq(#env.execs, 0, "no repair")
			assert_eq(#env.logs, 0, "no log")
		end
	},
	{
		name = "rrbguard: repairs at once when no client is connected, after two stale readings",
		fn = function()
			local env = setup(STALE, 0)
			assert_eq(g.tick(1000, 14), "stale", "one reading is not enough: it may be mid-reload")
			assert_eq(#env.execs, 0, "nothing yet")
			assert_eq(g.tick(1060, 14), "repairing", "confirmed, nobody connected")
			assert_eq(#env.execs, 1, "one repair")
			assert_true(env.execs[1]:find("/etc/init.d/wpad restart; sleep 6; wifi up", 1, true) ~= nil,
				"wpad restart, then wifi up")
			assert_true(env.execs[1]:find("&$") ~= nil, "in the background: the heartbeat does not wait")
			assert_true(env.logs[1]:find("0x88b7", 1, true) ~= nil, "the warning names the socket")
		end
	},
	{
		name = "rrbguard: with clients connected it waits for the 04:00 hour",
		fn = function()
			local env = setup(STALE, 5)
			g.tick(1000, 14)
			assert_eq(g.tick(1060, 14), "deferred", "clients at 14:00")
			assert_eq(g.tick(1120, 23), "deferred", "clients at 23:00")
			assert_eq(#env.logs, 1, "warned once, not every minute")
			assert_eq(g.tick(1180, 4), "repairing", "04:00, clients or not")
			assert_eq(#env.execs, 1, "repaired")
			env.sta = nil
			setup(STALE, nil)
			g.tick(1000, 14)
			assert_eq(g.tick(1060, 14), "deferred", "an unknown client count is not zero")
		end
	},
	{
		name = "rrbguard: without a trusted clock only the no-clients path repairs",
		fn = function()
			local env = setup(STALE, 2)
			g.tick(1000, nil)
			assert_eq(g.tick(1060, nil), "deferred", "no hour, clients")
			env.sta = 0
			assert_eq(g.tick(1120, nil), "repairing", "no hour, nobody connected")
		end
	},
	{
		name = "rrbguard: at most one repair per six hours, and recovery is logged",
		fn = function()
			local env = setup(STALE, 0)
			g.tick(1000, 14)
			assert_eq(g.tick(1060, 14), "repairing", "first repair")
			g.tick(1120, 14)
			assert_eq(g.tick(1180, 14), "waiting", "still stale right after: no second restart")
			assert_eq(g.tick(1060 + g.REPAIR_GAP - 60, 14), "waiting", "just inside the gap")
			assert_eq(g.tick(1060 + g.REPAIR_GAP + 60, 14), "repairing", "after the gap")
			assert_eq(#env.execs, 2, "two repairs in all")
			env.text = HEALTHY
			assert_eq(g.tick(1060 + g.REPAIR_GAP + 120, 14), "ok", "bound again")
			assert_true(env.logs[#env.logs]:find("bound again", 1, true) ~= nil, "recovery logged")
		end
	},
}
