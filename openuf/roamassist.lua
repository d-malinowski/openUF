--[[
	"Roaming Assistant": move a weak client to another AP that hears it
	clearly better, and leave it alone when no such AP exists.

	THE WIRE

	Decompiled from controller 10.6.101 (com.ubnt.service.config.ubntconf):
	wireless.<n>.btm_disassoc.status=enabled + .threshold=<dBm>, per WLAN,
	5GHz/6GHz vaps only, emitted only when wifi_caps2 bit 0x20
	(supportsAssistedRoaming) is claimed. The name says what a UniFi AP does
	with it: a BSS Transition Management request, then a disassociation.
	inform.lua parses it; ucihelper stamps the threshold on the wifi-iface as
	openuf_roam_assist; get_vap_table reads it back for build_json, which
	hands this module one observation per associated station per heartbeat.

	WHY NOT usteer's OWN ROAM TRIGGER

	usteer has one (roam_trigger_snr + signal_diff_threshold) and it is
	device-wide: every SSID, every band. Its only scoping knob, ssid_list,
	switches off every usteer function -- band steering included -- for the
	SSIDs it leaves out. The controller setting is per WLAN and per band, so
	the decision is made here, per vap, and usteer is used only for what
	nothing else on the device has: its cross-AP table of which AP heard
	which client how loudly (`ubus call usteer get_client_info`).

	That table carries no timestamps, but usteer expires every entry, local
	and remote, local_sta_timeout (120 s) after the client was last heard
	(usteer sta.c/remote.c). A reading here is therefore at most ~2 minutes
	old. If the client moved in that time the request can name an AP that
	is no longer better; the client then picks for itself after the
	disassociation, which is where a UniFi AP would leave it too.

	WHAT HAPPENS TO A CLIENT

	  1. Its signal stays below the WLAN's threshold for BELOW_HOLD seconds,
	     it has been associated for MIN_CONNECTED seconds, and it was not
	     acted on within COOLDOWN seconds.
	  2. Another AP (a remote usteer node) on the same SSID and the same
	     band hears it at or above the threshold AND at least diff_db
	     better. No such AP: nothing happens, now or later. A genuinely far
	     client is never disconnected by this module.
	  3. A BSS Transition request naming that AP goes out
	     (disassociation_imminent set). 802.11v clients usually roam on it.
	  4. GRACE seconds later, a client still here is disassociated with a
	     short ban (BAN_MS) on this BSS only, so it cannot bounce straight
	     back to the weak AP before trying the strong one. That is the
	     "disassoc" half of btm_disassoc, and it is the only way to move a
	     client without 802.11v at all. The ban is hostapd's own, expires
	     on its own and is not a block: see firewall.lua for that.
]]--

local M = {}
local util = package.loaded["openuf.util"]
	or assert(loadfile("util.lua") or loadfile("openuf/util.lua"))()

-- Seams, mirroring rrmscan.lua.
M._popen = util.popen
M._exec = os.execute
M._load_cjson = function()
	local ok, mod = pcall(require, "cjson")
	return ok and mod or nil
end
M._log = function(msg) io.stderr:write("roamassist: " .. msg .. "\n") end

M.DEFAULT_DIFF_DB  = 8      -- candidate must be this much louder
M.BELOW_HOLD       = 30     -- s below threshold before acting
M.MIN_CONNECTED    = 60     -- s associated before acting
M.COOLDOWN         = 120    -- s between actions on one client
M.GRACE            = 10     -- s from the BTM request to the disassociation
M.BAN_MS           = 30000  -- hostapd ban on the source BSS after it
M.RECHECK          = 30     -- s between looks for a better AP, per client
M.FORGET           = 300    -- s unseen before a client's state is dropped
-- IEEE 802.11 reason 12: "Disassociated because of BSS Transition Management".
M.REASON_BTM       = 12

-- Per-client state, in memory only: a restart forgets it, which costs at most
-- one BELOW_HOLD before the next decision.
--   below_since: when the signal first went under the threshold (nil = above)
--   pending:     {ifname, at} while a BTM request waits out its GRACE
--   acted_at:    last BTM or disassociation, for COOLDOWN
--   checked_at:  last look for a better AP that found none, for RECHECK
--   seen_at:     last heartbeat that observed it
M._state = {}

local warned = {}
local function warn_once(key, msg)
	if warned[key] then return end
	warned[key] = true
	M._log(msg)
end

local function ubus_json(cmd)
	local cjson = M._load_cjson()
	if not cjson then
		warn_once("cjson", "lua-cjson unavailable -- Roaming Assistant disabled")
		return nil
	end
	local out = M._popen(cmd .. " 2>/dev/null")
	if not out or out == "" then return nil end
	local ok, decoded = pcall(cjson.decode, out)
	if ok and type(decoded) == "table" then return decoded end
	return nil
end

local function band_of(freq)
	freq = tonumber(freq)
	if not freq then return nil end
	if freq >= 5925 then return "6e" end
	if freq >= 5000 then return "na" end
	return "ng"
end

-- The best other AP for this client, or nil. nodes: usteer's local_info and
-- remote_info merged, keyed by node name.
function M.find_candidate(obs, client_nodes, nodes, diff_db)
	local here = nodes["hostapd." .. obs.ifname]
	local band = here and band_of(here.freq)
	local best, best_signal = nil, nil
	for name, n in pairs(client_nodes) do
		local info = nodes[name]
		local signal = tonumber(n.signal)
		-- A remote node only: another radio of this same AP is not "another
		-- AP", and UniFi's own event for this is a move between APs
		-- (MOVED_DUE_TO_ROAMING_ASSISTANT).
		if name:find("#", 1, true) and info and signal and not n.connected
			and info.ssid == obs.ssid
			and band ~= nil and band_of(info.freq) == band
			and type(info.rrm_nr) == "table" and type(info.rrm_nr[3]) == "string"
			and signal >= obs.threshold
			and signal >= obs.signal + diff_db
			and (best_signal == nil or signal > best_signal) then
			best, best_signal = {name = name, signal = signal, nr = info.rrm_nr[3],
				bssid = info.bssid}, signal
		end
	end
	return best
end

local function btm_request(ifname, mac, nr)
	-- hostapd's bss_transition_request takes each neighbor as the hex body
	-- of a Neighbor Report element, exactly what usteer's rrm_nr[3] holds.
	-- ifname and nr come from netifd/usteer and mac from iw, never from the
	-- controller, and all three are validated by pattern before use.
	local cmd = string.format(
		"ubus call hostapd.%s bss_transition_request " ..
		"'{\"addr\":\"%s\",\"disassociation_imminent\":true," ..
		"\"abridged\":true,\"validity_period\":100,\"dialog_token\":1," ..
		"\"neighbors\":[\"%s\"]}' >/dev/null 2>&1",
		ifname, mac, nr)
	M._exec(cmd)
end

local function disassociate(ifname, mac)
	local cmd = string.format(
		"ubus call hostapd.%s del_client " ..
		"'{\"addr\":\"%s\",\"reason\":%d,\"deauth\":false,\"ban_time\":%d}' " ..
		">/dev/null 2>&1",
		ifname, mac, M.REASON_BTM, M.BAN_MS)
	M._exec(cmd)
end

local function safe(ifname, mac, nr)
	return type(ifname) == "string" and ifname:match("^[%w%-%._]+$")
		and type(mac) == "string" and mac:match("^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$")
		and (nr == nil or (type(nr) == "string" and nr:match("^%x+$")))
end

-- One pass. observations: one per associated station on a vap with Roaming
-- Assistant on: {ifname, ssid, mac, signal, connected_sec, threshold}.
-- opts.diff_db overrides DEFAULT_DIFF_DB. opts.on_steer(mac), when given, is
-- called just before each BTM request and disassociation (assoctrack's kick
-- ledger: the departure that follows is reported as Roaming Assistant's).
-- Returns the number of actions.
function M.tick(observations, now, opts)
	local diff_db = tonumber(opts and opts.diff_db) or M.DEFAULT_DIFF_DB
	local on_steer = opts and opts.on_steer
	local function steered(mac) if on_steer then pcall(on_steer, mac) end end
	local actions = 0
	local nodes = nil  -- fetched lazily: most heartbeats need no ubus at all

	for _, o in ipairs(observations or {}) do
		local cs = M._state[o.mac] or {}
		M._state[o.mac] = cs
		cs.seen_at = now

		-- A request this old was answered long ago: the client left and has
		-- since come back on its own, which is not a refusal.
		if cs.pending and now - cs.pending.at > M.GRACE + M.COOLDOWN then
			cs.pending = nil
		end
		if cs.pending then
			-- The client answers a BTM request by leaving. Still here on the
			-- same BSS after GRACE: disassociate with the short ban.
			if cs.pending.ifname == o.ifname and now - cs.pending.at >= M.GRACE then
				if safe(o.ifname, o.mac) then
					steered(o.mac)
					disassociate(o.ifname, o.mac)
					M._log(string.format("%s still on %s after BSS transition "
						.. "request; disassociated (ban %d s)", o.mac, o.ifname,
						M.BAN_MS / 1000))
					actions = actions + 1
				end
				cs.pending, cs.acted_at, cs.below_since = nil, now, nil
			elseif cs.pending.ifname ~= o.ifname then
				cs.pending = nil
			end
		elseif not (o.signal and o.threshold) or o.signal >= o.threshold then
			cs.below_since = nil
		else
			cs.below_since = cs.below_since or now
			if now - cs.below_since >= M.BELOW_HOLD
				and (tonumber(o.connected_sec) or 0) >= M.MIN_CONNECTED
				and (cs.acted_at == nil or now - cs.acted_at >= M.COOLDOWN)
				and (cs.checked_at == nil or now - cs.checked_at >= M.RECHECK) then
				if nodes == nil then
					nodes = {}
					for _, method in ipairs({"local_info", "remote_info"}) do
						local t = ubus_json("ubus call usteer " .. method)
						if t then for k, v in pairs(t) do nodes[k] = v end end
					end
					if next(nodes) == nil then
						warn_once("usteer", "usteer not answering -- Roaming "
							.. "Assistant cannot see other APs, doing nothing")
					end
				end
				local info = next(nodes) ~= nil and safe(o.ifname, o.mac)
					and ubus_json(string.format(
						"ubus call usteer get_client_info '{\"address\":\"%s\"}'", o.mac))
				local cand = info and type(info.nodes) == "table"
					and M.find_candidate(o, info.nodes, nodes, diff_db)
				if cand and safe(o.ifname, o.mac, cand.nr) then
					steered(o.mac)
					btm_request(o.ifname, o.mac, cand.nr)
					M._log(string.format("%s at %d dBm on %s (threshold %d); "
						.. "BSS transition request to %s (%s, %d dBm)",
						o.mac, o.signal, o.ifname, o.threshold,
						tostring(cand.bssid), cand.name, cand.signal))
					cs.pending = {ifname = o.ifname, at = now}
					cs.acted_at = now
					actions = actions + 1
				else
					-- No better AP. below_since keeps running, so the client
					-- is looked at again after RECHECK, not every heartbeat.
					cs.checked_at = now
				end
			end
		end
	end

	for mac, cs in pairs(M._state) do
		if now - (cs.seen_at or 0) >= M.FORGET then M._state[mac] = nil end
	end
	return actions
end

return M
