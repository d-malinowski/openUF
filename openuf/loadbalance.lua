--[[
	"Load balance" (radio_table[].loadbalance_enabled + maxsta): the UniFi AP
	firmware's per-radio client cap.

	THE WIRE

	stamgr.<n>.loadbalance.status=true + stamgr.<n>.loadbalance.maxsta=<N>,
	in the same per-radio stamgr block as Minimum RSSI, indexed like
	radio.<n>. The block is absent when neither feature is on. 10.6's UI has
	no control for it (only a change-log label); the REST API sets it.

	WHAT THE FIRMWARE DOES (firmware-confirmed for 4.0.15)

	ubntbox passes stamgr -n <maxsta> per radio, 0 unless
	loadbalance.status is true; stamgr ignores a maxsta of 0 or less. Every
	interval (1 s) stamgr counts the stations on all of the radio's VAPs,
	leaving out any it has just kicked for low RSSI, and remembers the one
	with the longest idle time. If the count is above maxsta it kicks that
	one (kick-sta-on, the one-shot deauth of kick-sta). Nothing refuses an
	association: a full radio still admits a new client, and the next pass
	kicks whichever station is then the most idle.

	openUF samples once per inform, not once a second, so one pass kicks
	the count - maxsta most idle stations: where the firmware arrives after
	that many seconds.
]]--

local M = {}

-- obs: one entry per station on a radio that has Load balance on, this
-- heartbeat: {radio, ifname, mac, inactive_ms}. maxsta_by_radio: radio name
-- -> cap. skip: mac -> true for stations already kicked this pass (Minimum
-- RSSI), which the firmware does not count. Returns the stations to kick.
function M.kicks(obs, maxsta_by_radio, skip)
	local by_radio = {}
	for i, o in ipairs(obs) do
		if not (skip and skip[o.mac]) then
			local list = by_radio[o.radio]
			if not list then
				list = {}
				by_radio[o.radio] = list
			end
			list[#list + 1] = {o = o, i = i}
		end
	end
	local kicks = {}
	for radio, list in pairs(by_radio) do
		local maxsta = maxsta_by_radio[radio]
		if maxsta and maxsta > 0 then
			-- Most idle first. stamgr keeps the first of equals, so ties go
			-- to the earlier station.
			table.sort(list, function(a, b)
				local ia, ib = a.o.inactive_ms or 0, b.o.inactive_ms or 0
				if ia ~= ib then return ia > ib end
				return a.i < b.i
			end)
			-- Above the cap by n: the n most idle. At or below it: none.
			for k = 1, #list - maxsta do
				kicks[#kicks + 1] = {ifname = list[k].o.ifname, mac = list[k].o.mac}
			end
		end
	end
	return kicks
end

return M
