-- Tests for openuf/roamassist.lua ("Roaming Assistant").
-- Run from project root: lua tests/run_tests.lua

local ra = dofile("openuf/roamassist.lua")
local cjson = require("cjson")

local HERE  = "phy1-ap0"
local MAC   = "00:00:5e:00:53:01"
local FAR   = "00:00:5e:00:53:02"
local PEER  = "198.51.100.4#hostapd.phy1-ap0"
local NR    = "00005e005305ef1900008024090603022a00"

-- usteer as seen from this AP: our 5 GHz BSS, a remote 5 GHz BSS on the same
-- SSID, a remote 5 GHz BSS on another SSID, and a remote 2.4 GHz one.
local function default_nodes()
	return {
		local_info = {
			["hostapd." .. HERE] = {ssid = "Home", freq = 5500,
				rrm_nr = {"00:00:5e:00:53:04", "Home", "aa"}},
		},
		remote_info = {
			[PEER] = {ssid = "Home", freq = 5180, bssid = "00:00:5e:00:53:05",
				rrm_nr = {"00:00:5e:00:53:05", "Home", NR}},
			["198.51.100.4#hostapd.phy1-ap1"] = {ssid = "Other", freq = 5180,
				rrm_nr = {"00:00:5e:00:53:06", "Other", "bb"}},
			["198.51.100.4#hostapd.phy0-ap0"] = {ssid = "Home", freq = 2462,
				rrm_nr = {"00:00:5e:00:53:07", "Home", "cc"}},
		},
	}
end

-- clients[mac] = get_client_info "nodes" table
local function with_ra(clients, fn, nodes)
	nodes = nodes or default_nodes()
	local cmds, popens, logs = {}, {}, {}
	local o_popen, o_exec, o_log = ra._popen, ra._exec, ra._log
	ra._state = {}
	ra._popen = function(cmd)
		popens[#popens + 1] = cmd
		if cmd:find("usteer local_info", 1, true) then return cjson.encode(nodes.local_info) end
		if cmd:find("usteer remote_info", 1, true) then return cjson.encode(nodes.remote_info) end
		local mac = cmd:match('"address":"([%x:]+)"')
		if mac and clients[mac] then return cjson.encode({nodes = clients[mac]}) end
		return ""
	end
	ra._exec = function(cmd) cmds[#cmds + 1] = cmd; return 0 end
	ra._log = function(m) logs[#logs + 1] = m end
	local ok, err = pcall(fn, cmds, popens, logs)
	ra._popen, ra._exec, ra._log = o_popen, o_exec, o_log
	ra._state = {}
	if not ok then error(err, 2) end
end

local function obs(mac, signal, connected)
	return {ifname = HERE, ssid = "Home", mac = mac or MAC, signal = signal or -80,
		connected_sec = connected or 600, threshold = -75}
end

-- The sticky-client case: we hear it at -80, the peer at -52.
local function sticky()
	return {[MAC] = {
		["hostapd." .. HERE] = {connected = true, signal = -80},
		[PEER] = {connected = false, signal = -52},
	}}
end

-- Drive one client below threshold long enough to be decided on.
local function run_until_decided(o, t0)
	ra.tick({o}, t0)
	return ra.tick({o}, t0 + ra.BELOW_HOLD)
end

local function has(list, s)
	for _, c in ipairs(list) do if c:find(s, 1, true) then return true end end
	return false
end

return {
	{
		name = "roamassist: a sticky client gets a BSS transition request naming the better AP",
		fn = function()
			with_ra(sticky(), function(cmds)
				assert_eq(run_until_decided(obs(), 1000), 1, "one action")
				assert_eq(#cmds, 1, "one command")
				assert_true(has(cmds, "ubus call hostapd." .. HERE .. " bss_transition_request"),
					"sent on the client's own BSS")
				assert_true(has(cmds, '"addr":"' .. MAC .. '"'), "to that client")
				assert_true(has(cmds, '"neighbors":["' .. NR .. '"]'), "naming the peer's neighbor report")
				assert_true(has(cmds, '"disassociation_imminent":true'), "disassoc imminent")
			end)
		end
	},
	{
		-- assoctrack's kick ledger: the departure that follows a BTM request
		-- or the disassociation is reported as Roaming Assistant's (8192), so
		-- the hook has to have run before the command that causes it.
		name = "roamassist: on_steer hears of the BTM request and the disassociation first",
		fn = function()
			with_ra(sticky(), function(cmds)
				local seen = {}
				local opts = {on_steer = function(mac) seen[#seen + 1] = mac .. "@" .. #cmds end}
				local o = obs()
				ra.tick({o}, 1000, opts)
				ra.tick({o}, 1000 + ra.BELOW_HOLD, opts)
				assert_eq(#seen, 1, "the BTM request")
				assert_eq(seen[1], MAC .. "@0", "before its command")
				ra.tick({o}, 1000 + ra.BELOW_HOLD + ra.GRACE, opts)
				assert_eq(#seen, 2, "then the disassociation")
				assert_eq(seen[2], MAC .. "@1", "before its command too")
				assert_true(has(cmds, "del_client"), "which did happen")
			end)
			with_ra(sticky(), function()
				ra.tick({obs()}, 1000, {on_steer = function() error("boom") end})
				assert_eq(ra.tick({obs()}, 1000 + ra.BELOW_HOLD,
					{on_steer = function() error("boom") end}), 1, "a failing hook stops nothing")
			end)
		end
	},
	{
		name = "roamassist: a far client with no better AP is never touched",
		fn = function()
			local clients = {[FAR] = {
				["hostapd." .. HERE] = {connected = true, signal = -82},
				[PEER] = {connected = false, signal = -86},
			}}
			with_ra(clients, function(cmds)
				local o = obs(FAR, -82)
				for t = 0, 3600, 10 do ra.tick({o}, 1000 + t) end
				assert_eq(#cmds, 0, "no request, no disassociation, in an hour")
			end)
		end
	},
	{
		name = "roamassist: a far client is re-examined every RECHECK, not every heartbeat",
		fn = function()
			local clients = {[FAR] = {[PEER] = {connected = false, signal = -90}}}
			with_ra(clients, function(_, popens)
				local o = obs(FAR, -82)
				for t = 0, 120, 10 do ra.tick({o}, 1000 + t) end
				local lookups = 0
				for _, c in ipairs(popens) do
					if c:find("get_client_info", 1, true) then lookups = lookups + 1 end
				end
				-- below at t=0; eligible from t=30, then every 30 s: 30, 60, 90, 120
				assert_eq(lookups, 4, "one lookup per RECHECK window")
			end)
		end
	},
	{
		name = "roamassist: a better AP on another SSID or another band is not a candidate",
		fn = function()
			local clients = {[MAC] = {
				["198.51.100.4#hostapd.phy1-ap1"] = {connected = false, signal = -40},
				["198.51.100.4#hostapd.phy0-ap0"] = {connected = false, signal = -40},
			}}
			with_ra(clients, function(cmds)
				run_until_decided(obs(), 1000)
				assert_eq(#cmds, 0, "neither the other SSID nor the 2.4 GHz BSS")
			end)
		end
	},
	{
		name = "roamassist: another radio of this same AP is not a candidate",
		fn = function()
			local nodes = default_nodes()
			nodes.local_info["hostapd.phy0-ap0"] = {ssid = "Home", freq = 5745,
				rrm_nr = {"00:00:5e:00:53:08", "Home", "dd"}}
			local clients = {[MAC] = {["hostapd.phy0-ap0"] = {connected = false, signal = -40}}}
			with_ra(clients, function(cmds)
				run_until_decided(obs(), 1000)
				assert_eq(#cmds, 0, "local node ignored")
			end, nodes)
		end
	},
	{
		name = "roamassist: a candidate must beat the client by diff_db and clear the threshold",
		fn = function()
			-- -73 clears -75 but is only 7 dB better than -80.
			local clients = {[MAC] = {[PEER] = {connected = false, signal = -73}}}
			with_ra(clients, function(cmds)
				run_until_decided(obs(), 1000)
				assert_eq(#cmds, 0, "7 dB is under the default 8")
			end)
			with_ra(clients, function(cmds)
				ra.tick({obs()}, 1000, {diff_db = 5})
				ra.tick({obs()}, 1000 + ra.BELOW_HOLD, {diff_db = 5})
				assert_eq(#cmds, 1, "diff_db override honoured")
			end)
			-- 10 dB better, but -86 -> -76 is still below the -75 threshold.
			local weak = {[MAC] = {[PEER] = {connected = false, signal = -76}}}
			with_ra(weak, function(cmds)
				run_until_decided(obs(MAC, -86), 1000)
				assert_eq(#cmds, 0, "candidate below the threshold itself")
			end)
		end
	},
	{
		name = "roamassist: a peer that already has the client connected is not a candidate",
		fn = function()
			-- usteer's view mid-roam: the peer already reports the association
			-- while this BSS has not yet dropped the station.
			local clients = {[MAC] = {[PEER] = {connected = true, signal = -52}}}
			with_ra(clients, function(cmds)
				run_until_decided(obs(), 1000)
				assert_eq(#cmds, 0, "nothing sent to a client that is already moving")
			end)
		end
	},
	{
		name = "roamassist: nothing happens before BELOW_HOLD or MIN_CONNECTED",
		fn = function()
			with_ra(sticky(), function(cmds)
				ra.tick({obs()}, 1000)
				ra.tick({obs()}, 1000 + ra.BELOW_HOLD - 1)
				assert_eq(#cmds, 0, "below for less than BELOW_HOLD")
			end)
			with_ra(sticky(), function(cmds)
				run_until_decided(obs(MAC, -80, ra.MIN_CONNECTED - 1), 1000)
				assert_eq(#cmds, 0, "associated for less than MIN_CONNECTED")
			end)
		end
	},
	{
		name = "roamassist: a signal back above the threshold resets the hold",
		fn = function()
			with_ra(sticky(), function(cmds)
				ra.tick({obs(MAC, -80)}, 1000)
				ra.tick({obs(MAC, -70)}, 1020)
				ra.tick({obs(MAC, -80)}, 1030)
				ra.tick({obs(MAC, -80)}, 1050)
				assert_eq(#cmds, 0, "hold restarted at 1030")
				ra.tick({obs(MAC, -80)}, 1030 + ra.BELOW_HOLD)
				assert_eq(#cmds, 1, "acts once the new hold elapses")
			end)
		end
	},
	{
		name = "roamassist: a client still here after GRACE is disassociated with a short ban",
		fn = function()
			with_ra(sticky(), function(cmds)
				local t = 1000 + ra.BELOW_HOLD
				run_until_decided(obs(), 1000)
				ra.tick({obs()}, t + ra.GRACE - 1)
				assert_eq(#cmds, 1, "no disassociation inside GRACE")
				ra.tick({obs()}, t + ra.GRACE)
				assert_eq(#cmds, 2, "disassociated after GRACE")
				assert_true(has(cmds, "ubus call hostapd." .. HERE .. " del_client"), "del_client")
				assert_true(has(cmds, '"deauth":false'), "a disassociation, not a deauth")
				assert_true(has(cmds, '"ban_time":' .. ra.BAN_MS), "short ban on this BSS")
				assert_true(has(cmds, '"reason":12'), "reason: BSS transition management")
			end)
		end
	},
	{
		name = "roamassist: a client that roamed away is not chased, and cooldown holds",
		fn = function()
			with_ra(sticky(), function(cmds)
				local t = 1000 + ra.BELOW_HOLD
				run_until_decided(obs(), 1000)
				-- It left: no observation for a while, then it is back here.
				ra.tick({}, t + ra.GRACE)
				local back = obs()
				back.ifname = "phy1-ap1"  -- a different BSS of ours
				ra.tick({back}, t + ra.GRACE + 10)
				assert_eq(#cmds, 1, "no disassociation on a different BSS")
				-- Back on the weak BSS inside COOLDOWN: nothing new.
				ra.tick({obs()}, t + ra.COOLDOWN - 1)
				assert_eq(#cmds, 1, "cooldown holds")
			end)
		end
	},
	{
		name = "roamassist: no usteer means no action, logged once",
		fn = function()
			with_ra({}, function(cmds, _, logs)
				run_until_decided(obs(), 1000)
				ra.tick({obs()}, 1000 + ra.BELOW_HOLD + ra.RECHECK)
				assert_eq(#cmds, 0, "nothing sent")
				local n = 0
				for _, l in ipairs(logs) do if l:find("usteer not answering", 1, true) then n = n + 1 end end
				assert_eq(n, 1, "warned once")
			end, {local_info = {}, remote_info = {}})
		end
	},
	{
		name = "roamassist: a malformed neighbor report or MAC never reaches a shell",
		fn = function()
			local nodes = default_nodes()
			nodes.remote_info[PEER].rrm_nr[3] = "aa'; reboot; '"
			with_ra(sticky(), function(cmds)
				run_until_decided(obs(), 1000)
				assert_eq(#cmds, 0, "rejected by the hex check")
			end, nodes)
			with_ra({}, function(cmds, popens)
				local o = obs("00:00:5e:00:53:01'; reboot; '", -80)
				run_until_decided(o, 1000)
				assert_eq(#cmds, 0, "nothing executed")
				assert_false(has(popens, "reboot"), "never interpolated into a ubus call")
			end)
		end
	},
	{
		name = "roamassist: state for clients unseen for FORGET is dropped",
		fn = function()
			with_ra(sticky(), function()
				ra.tick({obs()}, 1000)
				assert_true(ra._state[MAC] ~= nil, "tracked")
				ra.tick({}, 1000 + ra.FORGET)
				assert_nil(ra._state[MAC], "forgotten")
			end)
		end
	},
}
