-- Tests for openuf/loadbalance.lua: Load balance's per-radio client cap.
-- Run from project root: lua tests/run_tests.lua

local lb = dofile("openuf/loadbalance.lua")

local function obs(mac, inactive_ms, radio)
	return {radio = radio or "radio0", ifname = "wlan0", mac = mac, inactive_ms = inactive_ms}
end

local A, B, C = "00:00:5e:00:53:01", "00:00:5e:00:53:02", "00:00:5e:00:53:03"

local function macs(kicks)
	local t = {}
	for _, k in ipairs(kicks) do t[#t + 1] = k.mac end
	table.sort(t)
	return table.concat(t, ",")
end

return {
	{
		name = "loadbalance: no kick at or below the cap",
		fn = function()
			assert_eq(#lb.kicks({obs(A, 10), obs(B, 20)}, {radio0 = 2}), 0, "at the cap")
			assert_eq(#lb.kicks({obs(A, 10)}, {radio0 = 2}), 0, "below it")
		end
	},
	{
		name = "loadbalance: above the cap, the most idle stations go, as many as the excess",
		fn = function()
			local k = lb.kicks({obs(A, 100), obs(B, 5000), obs(C, 300)}, {radio0 = 2})
			assert_eq(#k, 1, "one over")
			assert_eq(k[1].mac, B, "the most idle")
			assert_eq(k[1].ifname, "wlan0", "on its interface")
			k = lb.kicks({obs(A, 100), obs(B, 5000), obs(C, 300)}, {radio0 = 1})
			assert_eq(macs(k), B .. "," .. C, "two over: the two most idle")
		end
	},
	{
		name = "loadbalance: ties go to the earlier station, as stamgr keeps the first",
		fn = function()
			local k = lb.kicks({obs(A, 700), obs(B, 700), obs(C, 10)}, {radio0 = 2})
			assert_eq(#k, 1, "one over")
			assert_eq(k[1].mac, A, "the earlier of the two equally idle")
		end
	},
	{
		name = "loadbalance: off (no cap, 0, negative) never kicks",
		fn = function()
			local three = {obs(A, 1), obs(B, 2), obs(C, 3)}
			assert_eq(#lb.kicks(three, {}), 0, "no cap for the radio")
			assert_eq(#lb.kicks(three, {radio0 = 0}), 0, "0")
			assert_eq(#lb.kicks(three, {radio0 = -1}), 0, "negative")
		end
	},
	{
		name = "loadbalance: radios are counted separately",
		fn = function()
			local k = lb.kicks({obs(A, 1, "radio0"), obs(B, 2, "radio1"), obs(C, 3, "radio1")},
				{radio0 = 1, radio1 = 1})
			assert_eq(#k, 1, "only radio1 is over")
			assert_eq(k[1].mac, C, "radio1's most idle")
		end
	},
	{
		name = "loadbalance: stations Minimum RSSI just kicked are not counted",
		fn = function()
			local three = {obs(A, 100), obs(B, 5000), obs(C, 300)}
			assert_eq(#lb.kicks(three, {radio0 = 2}, {[B] = true}), 0,
				"B is already gone: two left, at the cap")
			local k = lb.kicks(three, {radio0 = 1}, {[B] = true})
			assert_eq(#k, 1, "two left, one over")
			assert_eq(k[1].mac, C, "the most idle of the two left")
		end
	},
	{
		name = "loadbalance: a station without an idle time counts as 0 ms idle",
		fn = function()
			local k = lb.kicks({obs(A, nil), obs(B, 1)}, {radio0 = 1})
			assert_eq(#k, 1, "one over")
			assert_eq(k[1].mac, B, "the one with an idle time")
		end
	},
}
