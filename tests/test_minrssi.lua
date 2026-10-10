-- Tests for openuf/minrssi.lua: Minimum RSSI's kick debounce and the
-- controller's threshold encoding.
-- Run from project root: lua tests/run_tests.lua

local mr = dofile("openuf/minrssi.lua")

local function obs(mac, signal, threshold)
	return {ifname = "wlan0", mac = mac, signal = signal, threshold = threshold or -80}
end

return {
	{
		name = "minrssi: the wire value is dBm + 95",
		fn = function()
			assert_eq(mr.dbm(15), -80, "UI -80 dBm")
			assert_eq(mr.dbm(10), -85, "UI -85 dBm")
			assert_eq(mr.dbm(1), -94, "the controller's floor")
		end
	},
	{
		name = "minrssi: a station is kicked after 30 s below in every sample, once",
		fn = function()
			mr._low_since = {}
			local a = "00:00:5e:00:53:01"
			assert_eq(#mr.tick({obs(a, -85)}, 1000), 0, "first sample below")
			assert_eq(#mr.tick({obs(a, -85)}, 1010), 0, "10 s")
			assert_eq(#mr.tick({obs(a, -81)}, 1029), 0, "29 s")
			local k = mr.tick({obs(a, -81)}, 1030)
			assert_eq(#k, 1, "30 s: kicked")
			assert_eq(k[1].mac, a, "that station")
			assert_eq(k[1].ifname, "wlan0", "on its interface")
			assert_eq(#mr.tick({obs(a, -85)}, 1040), 0, "a station still there after its kick starts over")
			assert_eq(#mr.tick({obs(a, -85)}, 1070), 1, "and is kicked again after another 30 s")
		end
	},
	{
		name = "minrssi: one sample at or above the threshold resets the run",
		fn = function()
			mr._low_since = {}
			local a = "00:00:5e:00:53:01"
			mr.tick({obs(a, -85)}, 1000)
			mr.tick({obs(a, -85)}, 1020)
			mr.tick({obs(a, -80)}, 1025)  -- exactly at the threshold: not below
			assert_eq(#mr.tick({obs(a, -85)}, 1030), 0, "the run restarted at 1030")
			assert_eq(#mr.tick({obs(a, -85)}, 1059), 0, "29 s into the new run")
			assert_eq(#mr.tick({obs(a, -85)}, 1060), 1, "30 s into it")
		end
	},
	{
		name = "minrssi: a station that leaves is forgotten; stations are independent",
		fn = function()
			mr._low_since = {}
			local a, b = "00:00:5e:00:53:01", "00:00:5e:00:53:02"
			mr.tick({obs(a, -85), obs(b, -60)}, 1000)
			mr.tick({obs(b, -85)}, 1010)  -- a gone
			local k = mr.tick({obs(a, -85), obs(b, -85)}, 1040)
			assert_eq(#k, 1, "only b has 30 s")
			assert_eq(k[1].mac, b, "b, below since 1010")
			assert_eq(#mr.tick({obs(a, -85)}, 1069), 0, "a restarted at 1040")
			assert_eq(#mr.tick({obs(a, -85)}, 1070), 1, "a at 30 s")
			assert_eq(#mr.tick({obs(a, -70, -75)}, 1100), 0, "per-observation threshold")
		end
	},
}
