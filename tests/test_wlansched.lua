-- Tests for openuf/wlansched.lua: the WiFi Blackout Schedule.
-- Run from project root: lua tests/run_tests.lua

local ws = dofile("openuf/wlansched.lua")

-- The lab push (10.4.57, fw_caps 0x1110): blackout 22:00 for 540 min Mon-Fri,
-- 13:00 for 60 and 15:30 for 30 on Saturday, inverted by the controller.
local function captured()
	return {
		schedule_enabled = "enabled",
		["schedule_sun.0"] = "0000-2359",
		["schedule_mon.0"] = "0000-2200", ["schedule_mon.1"] = "0000-2200",
		["schedule_tue.0"] = "0700-2200", ["schedule_tue.1"] = "0700-2200",
		["schedule_wed.0"] = "0700-2200", ["schedule_wed.1"] = "0700-2200",
		["schedule_thu.0"] = "0700-2200", ["schedule_thu.1"] = "0700-2200",
		["schedule_fri.0"] = "0700-2200", ["schedule_fri.1"] = "0700-2200",
		["schedule_sat.0"] = "0700-1300", ["schedule_sat.1"] = "1400-1530",
		["schedule_sat.2"] = "1600-2359",
	}
end

local function mins(h, m) return h * 60 + m end

return {
	{
		name = "wlansched: the captured push becomes the firmware's schedule lines",
		fn = function()
			assert_eq(ws.encode(ws.lines(captured())),
				"0=00:00-23:59 1=00:00-22:00 1=00:00-22:00 2=07:00-22:00 2=07:00-22:00 "
				.. "3=07:00-22:00 3=07:00-22:00 4=07:00-22:00 4=07:00-22:00 "
				.. "5=07:00-22:00 5=07:00-22:00 6=07:00-13:00 6=14:00-15:30 6=16:00-23:59")
		end
	},
	{
		name = "wlansched: no schedule unless schedule_enabled is on",
		fn = function()
			local w = captured()
			w.schedule_enabled = "disabled"
			assert_nil(ws.lines(w), "disabled")
			w.schedule_enabled = nil
			assert_nil(ws.lines(w), "absent")
			assert_nil(ws.lines({}), "nothing at all")
			assert_nil(ws.lines(nil), "not a table")
			assert_eq(#ws.lines({schedule_enabled = "true", schedule_sun = "0000-2359"}), 7, "true is on")
		end
	},
	{
		name = "wlansched: a day without a key is off all day (00:01-00:00)",
		fn = function()
			local l = ws.lines({schedule_enabled = "enabled", ["schedule_mon.0"] = "0800-1700"})
			assert_eq(ws.encode(l), "0=00:01-00:00 1=08:00-17:00 2=00:01-00:00 3=00:01-00:00 "
				.. "4=00:01-00:00 5=00:01-00:00 6=00:01-00:00")
			for d = 0, 6 do
				for _, t in ipairs({0, 1, 600, 1439}) do
					if d ~= 1 then assert_false(ws.within(l, d, t), "day " .. d .. " minute " .. t) end
				end
			end
		end
	},
	{
		name = "wlansched: the bare key, else .0, then .1 on until the first gap (as ubntbox)",
		fn = function()
			local function sun(w)
				w.schedule_enabled = "enabled"
				local out = {}
				for _, l in ipairs(ws.lines(w)) do
					if l:sub(1, 1) == "0" then out[#out + 1] = l:sub(3) end
				end
				return table.concat(out, " ")
			end
			assert_eq(sun({schedule_sun = "0100-0200"}), "01:00-02:00", "bare key (no multi-block bit)")
			assert_eq(sun({schedule_sun = "0100-0200", ["schedule_sun.1"] = "0300-0400"}),
				"01:00-02:00 03:00-04:00", "bare key, then .1")
			assert_eq(sun({schedule_sun = "0100-0200", ["schedule_sun.0"] = "0900-1000"}),
				"01:00-02:00", "the bare key wins over .0")
			assert_eq(sun({["schedule_sun.1"] = "0300-0400"}), "00:01-00:00",
				"no bare key and no .0: .1 is never read")
			assert_eq(sun({["schedule_sun.0"] = "0100-0200", ["schedule_sun.1"] = "0300-0400",
				["schedule_sun.3"] = "0500-0600"}), "01:00-02:00 03:00-04:00", "stops at the gap")
		end
	},
	{
		name = "wlansched: up to .98 is read, .99 is not",
		fn = function()
			local w = {schedule_enabled = "enabled", ["schedule_sun.0"] = "0000-0000"}
			for i = 1, 99 do w["schedule_sun." .. i] = "0000-0000" end
			local n = 0
			for _, l in ipairs(ws.lines(w)) do if l:sub(1, 1) == "0" then n = n + 1 end end
			assert_eq(n, 99, ".0 to .98")
		end
	},
	{
		name = "wlansched: a block that does not parse is left out",
		fn = function()
			local l = ws.lines({schedule_enabled = "enabled", ["schedule_sun.0"] = "junk",
				["schedule_sun.1"] = "0800-0900"})
			assert_eq(l[1], "0=08:00-09:00", "the good one stays")
			l = ws.lines({schedule_enabled = "enabled", ["schedule_sun.0"] = "8-9"})
			assert_eq(l[1], "0=00:01-00:00", "none left: off all day")
		end
	},
	{
		name = "wlansched: within() includes both ends, as within_schedule's -ge/-le",
		fn = function()
			local l = ws.lines(captured())
			assert_true(ws.within(l, 1, mins(0, 0)), "Mon 00:00")
			assert_true(ws.within(l, 1, mins(22, 0)), "Mon 22:00: still up (the -le)")
			assert_false(ws.within(l, 1, mins(22, 1)), "Mon 22:01: blackout")
			assert_false(ws.within(l, 2, mins(6, 59)), "Tue 06:59: blackout")
			assert_true(ws.within(l, 2, mins(7, 0)), "Tue 07:00: up")
			assert_false(ws.within(l, 6, mins(13, 1)), "Sat 13:01: blackout")
			assert_true(ws.within(l, 6, mins(14, 0)), "Sat 14:00: up")
			assert_false(ws.within(l, 6, mins(15, 45)), "Sat 15:45: blackout")
			assert_true(ws.within(l, 6, mins(23, 59)), "Sat 23:59: up")
			assert_true(ws.within(l, 0, mins(12, 0)), "Sunday: up all day")
			assert_false(ws.within({"1=00:01-00:00"}, 1, mins(0, 1)), "the off-day line never matches")
			assert_false(ws.within({}, 1, 0), "no lines: never")
		end
	},
	{
		name = "wlansched: down_set holds every BSS of a WLAN outside its schedule",
		fn = function()
			local l = ws.lines(captured())
			local vaps = {
				{ifnames = {"phy0-ap1", "phy0-ap2"}, lines = l},
				{ifnames = {"phy1-ap1"}, lines = {"0=00:00-23:59", "1=00:00-23:59"}},
			}
			local d = ws.down_set(vaps, 1, mins(23, 0))
			assert_true(d["phy0-ap1"] and d["phy0-ap2"], "both of the first")
			assert_nil(d["phy1-ap1"], "not the second")
			assert_nil(next(ws.down_set(vaps, 1, mins(12, 0))), "midday Monday: none")
		end
	},
	{
		name = "wlansched: reconcile takes down, brings back, and leaves selfrun's alone",
		fn = function()
			local links = {}
			local cmds = {}
			ws._read_file = function(p)
				local n = p:match("^/sys/class/net/(.-)/flags$")
				if links[n] == nil then return nil end
				return links[n] and "0x1003\n" or "0x1002\n"
			end
			ws._exec = function(c)
				cmds[#cmds + 1] = c
				local n, how = c:match("^ip link set dev (%S+) (%a+)")
				links[n] = (how == "up")
				return 0
			end
			local cli = {}
			ws._popen = function(c)
				cli[#cli + 1] = c
				return "OK\n"
			end
			links = {a = true, b = true, c = false}
			local held, ch = ws.reconcile({a = true}, nil, {})
			assert_eq(#cli, 0, "going down needs no hostapd call")
			assert_eq(table.concat(held, " "), "a", "held")
			assert_eq(table.concat(ch.down, " "), "a", "taken down")
			assert_eq(cmds[1], "ip link set dev a down 2>/dev/null")
			held, ch = ws.reconcile({a = true}, held, {})
			assert_eq(#cmds, 1, "already down: nothing run")
			assert_eq(#ch.down, 0, "nothing changed")
			links.a = true   -- a wifi reload recreated it up
			held, ch = ws.reconcile({a = true}, held, {})
			assert_eq(table.concat(ch.down, " "), "a", "down again")
			held, ch = ws.reconcile({}, held, {a = true})
			assert_eq(#ch.up, 0, "selfrun holds it: not brought up")
			assert_eq(#held, 0, "and no longer held here")
			links.a = false
			held, ch = ws.reconcile({}, {"a"}, {})
			assert_eq(table.concat(ch.up, " "), "a", "brought back up")
			assert_true(links.a, "up")
			assert_eq(table.concat(cli, " | "), "hostapd_cli -i a raw STOP_AP 2>/dev/null | "
				.. "hostapd_cli -i a update_beacon 2>/dev/null", "and its beacon restarted, STOP_AP first")
			assert_eq(#held, 0, "released")
			held, ch = ws.reconcile({}, {"b", "gone"}, {})
			assert_eq(#ch.up, 0, "already up / no such netdev: nothing to do")
			assert_eq(#held, 0, "both released")
		end
	},
	{
		name = "wlansched: a failed bring-up is retried, a bad ifname is never run",
		fn = function()
			local cmds = {}
			ws._read_file = function() return "0x1002" end
			ws._exec = function(c) cmds[#cmds + 1] = c; return 1 end
			local held, ch = ws.reconcile({}, {"a"}, {})
			assert_eq(#ch.up, 0, "failed")
			assert_eq(table.concat(held, " "), "a", "still held, tried again next time")
			-- The link comes up but hostapd will not start the beacon: down again, retried.
			local up = false
			ws._read_file = function() return up and "0x1003" or "0x1002" end
			ws._exec = function(c)
				cmds[#cmds + 1] = c
				up = c:match(" up ") ~= nil
				return 0
			end
			ws._popen = function(c) return c:find("update_beacon", 1, true) and "FAIL\n" or "OK\n" end
			cmds = {}
			held, ch = ws.reconcile({}, {"a"}, {})
			assert_eq(#ch.up, 0, "no beacon: not up")
			assert_false(up, "taken down again")
			assert_eq(cmds[#cmds], "ip link set dev a down 2>/dev/null", "the last command")
			assert_eq(table.concat(held, " "), "a", "still held, retried next time")
			ws._popen = function() return "OK\n" end
			held, ch = ws.reconcile({}, held, {})
			assert_eq(table.concat(ch.up, " "), "a", "the retry brings it up")
			assert_true(up, "and it stays up")
			assert_eq(#held, 0, "released")
			ws._exec = function(c) cmds[#cmds + 1] = c; return 1 end
			cmds = {}
			held = ws.reconcile({["a;reboot"] = true}, {"b c"}, {})
			assert_eq(#cmds, 0, "nothing run for either")
			assert_eq(#held, 0, "and neither kept")
		end
	},
	{
		name = "wlansched: set_bss takes one BSS off the air and puts it back with its beacon",
		fn = function()
			local cmds, cli, rc, beacon = {}, {}, 0, "OK\n"
			ws._exec = function(c) cmds[#cmds + 1] = c; return rc end
			ws._popen = function(c) cli[#cli + 1] = c; return c:find("update_beacon", 1, true) and beacon or "OK\n" end
			assert_true(ws.set_bss("phy0-ap1", false), "down")
			assert_eq(table.concat(cmds, " | "), "ip link set dev phy0-ap1 down 2>/dev/null", "the link only")
			assert_eq(#cli, 0, "no hostapd call going down")
			cmds = {}
			assert_true(ws.set_bss("phy0-ap1", true), "up")
			assert_eq(table.concat(cmds, " | "), "ip link set dev phy0-ap1 up 2>/dev/null", "the link")
			assert_eq(table.concat(cli, " | "), "hostapd_cli -i phy0-ap1 raw STOP_AP 2>/dev/null | "
				.. "hostapd_cli -i phy0-ap1 update_beacon 2>/dev/null", "then the beacon")
			cmds, cli, beacon = {}, {}, "FAIL\n"
			assert_false(ws.set_bss("phy0-ap1", true), "no beacon")
			assert_eq(cmds[#cmds], "ip link set dev phy0-ap1 down 2>/dev/null", "down again")
			cmds, cli, rc = {}, {}, 1
			assert_false(ws.set_bss("phy0-ap1", true), "the link refused")
			assert_eq(#cli, 0, "hostapd not asked")
			assert_false(ws.set_bss("phy0-ap1", false), "refused down")
			cmds, rc = {}, 0
			assert_false(ws.set_bss("x; reboot", true), "bad name")
			assert_false(ws.set_bss("x; reboot", false), "bad name")
			assert_eq(#cmds, 0, "never run")
			ws._popen = function() return "OK\n" end
		end
	},
}
