--[[
	"Minimum RSSI" (Devices -> [AP] -> Radios): the UniFi AP firmware's two
	halves of it, per radio.

	THE WIRE

	stamgr.<n>.minrssi.status=true + stamgr.<n>.minrssi.rssi=<raw>, indexed
	like radio.<n>; the whole block is absent when the feature is off. The
	controller encodes raw = max(dBm + 95, 1) (com.ubnt.service.config,
	min_rssi default -80), so dBm = raw - 95 here.

	WHAT THE FIRMWARE DOES (firmware-confirmed for 4.0.15)

	  1. Refuse. ubntbox sets the driver's minrssi to raw + offset, where
	     offset is stamgr.<n>.minrssi.rssi.offset (default 3, never sent by
	     the controller), and umac.ko then answers no probe request and no
	     authentication from a station below it ("probe/auth: disallowed by
	     minrssi"). openUF: hostapd's rssi_reject_assoc_rssi and
	     rssi_ignore_probe_request at threshold + REFUSE_MARGIN dBm, written
	     by ucihelper.rf_config.
	  2. Kick. stamgr samples every station each interval (stamgr.interval,
	     default 1 s) and kicks one whose RSSI was below raw in
	     minrssi_conseq_fails consecutive samples (default 30, never sent
	     by the controller). Any sample at or above resets the count. The
	     kick is the one-shot deauth of kick-sta; nothing is blocked.
	     openUF samples once per inform, so it counts time instead: a
	     station is kicked once it has been below in every sample for
	     HOLD seconds.

	The 3 dB gap is what keeps a weak client from looping: kicked below
	the threshold, it cannot come straight back until it is 3 dB above it.
]]--

local M = {}

-- The controller's encoding: raw = dBm + 95.
M.WIRE_OFFSET = 95
-- stamgr.<n>.minrssi.rssi.offset's default: the refusal sits this many dB
-- above the kick threshold.
M.REFUSE_MARGIN = 3
-- stamgr -i 1 -c 30: 30 consecutive one-second samples.
M.HOLD = 30

function M.dbm(raw)
	return raw - M.WIRE_OFFSET
end

-- Per-station state, in memory only: mac -> time of the first sample of
-- the current run below the threshold. A restart forgets it, which costs at
-- most one more HOLD before a kick.
M._low_since = {}

-- obs: one entry per station on a radio with Minimum RSSI on, this
-- heartbeat: {ifname, mac, signal, threshold} (signal and threshold in dBm).
-- Returns the stations to kick now. A station missing from obs has left (or
-- its radio's feature went off), and its run is forgotten.
function M.tick(obs, now)
	local low, kicks = {}, {}
	for _, o in ipairs(obs) do
		if o.signal < o.threshold then
			local since = M._low_since[o.mac] or now
			if now - since >= M.HOLD then
				kicks[#kicks + 1] = {ifname = o.ifname, mac = o.mac}
			else
				low[o.mac] = since
			end
		end
	end
	M._low_since = low
	return kicks
end

return M
