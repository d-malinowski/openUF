--[[
	rrbguard.lua -- keep hostapd's 802.11r key-exchange socket alive.

	hostapd exchanges PMK-R1 keys with the other APs over one packet socket
	per ft_iface (ethertype 0x88b7, the RRB OUI frames), bound to br-lan by
	ifindex when the first FT BSS starts. It keeps that socket across wifi
	reloads and only reopens it when no BSS uses it any more. If br-lan is
	replaced under it, the kernel sets the socket's ifindex to -1 and every
	pull or push fails with ENXIO ("l2_packet_send - send: No such device or
	address"): cross-AP fast roaming silently falls back to full
	authentication until hostapd restarts. Seen once on the office AP after
	weeks of uptime (PROTOCOL-VALIDATION.md, 802.11r key holders).

	Restarting wpad is the only repair, and it costs every BSS on the AP
	~10 s, plus a 60 s CAC on a DFS channel, while a stale socket only makes
	roams slower. So it is done at a cheap moment: as soon as no client is
	connected, or in the 04:00 local hour (when the controller's nightly
	scan runs too), and at most once every REPAIR_GAP. The warning goes out
	at once.

	Steady-state cost: one read of /proc/net/packet a minute. Nothing is
	spawned unless the socket is stale.
]]

local M = {}

M.CHECK_INTERVAL = 60
-- Consecutive stale readings before acting, so a socket caught mid-reload
-- is not mistaken for a dead one.
M.CONFIRM        = 2
M.REPAIR_GAP     = 6 * 3600
M.NIGHT_HOUR     = 4
-- `wifi up` after the restart: the wpad init script restarts the daemons,
-- but netifd has to hand them their BSSes again (CLAUDE.local.md).
M.REPAIR_CMD     = "/etc/init.d/wpad restart; sleep 6; wifi up"
M.STA_COUNT_CMD  = "for i in $(iw dev 2>/dev/null | awk '$1==\"Interface\"{print $2}'); do "
	.. "iw dev \"$i\" station dump 2>/dev/null; done | grep -c '^Station'"

-- Injectable seams.
M._read = function(path)
	local f = io.open(path, "r")
	if not f then return nil end
	local s = f:read("*a")
	f:close()
	return s
end
M._popen = function(cmd)
	local p = io.popen(cmd)
	if not p then return nil end
	local s = p:read("*a")
	p:close()
	return s
end
M._exec = os.execute
M._log  = function(msg) io.stderr:write("openuf: rrbguard: " .. msg .. "\n") end

-- State: the next check time, how many stale readings in a row, whether this
-- episode was already reported, and when the last repair was started.
M._next, M._streak, M._warned, M._last_repair = 0, 0, false, nil

function M.reset()
	M._next, M._streak, M._warned, M._last_repair = 0, 0, false, nil
end

-- True when /proc/net/packet holds a 0x88b7 socket whose interface is gone.
-- Columns: sk RefCnt Type Proto Iface R Rmem User Inode.
function M.stale(packet_text)
	if type(packet_text) ~= "string" then return false end
	for line in packet_text:gmatch("[^\n]+") do
		local proto, iface = line:match("^%x+%s+%d+%s+%d+%s+(%x+)%s+(%-?%d+)%s")
		if proto and proto:lower() == "88b7" and tonumber(iface) == -1 then
			return true
		end
	end
	return false
end

-- Connected stations across every interface, or nil when unknown.
function M.station_count()
	local out = M._popen(M.STA_COUNT_CMD)
	return out and tonumber(out:match("%d+")) or nil
end

-- One step. now: epoch seconds; hour: local hour, or nil while the clock is
-- not trusted (the night window is then not used). Returns nil when there was
-- nothing to check, "ok", "stale" (not yet confirmed), "waiting" (repaired
-- too recently), "deferred" (clients connected outside the window) or
-- "repairing".
function M.tick(now, hour)
	if now < M._next then return nil end
	M._next = now + M.CHECK_INTERVAL
	if not M.stale(M._read("/proc/net/packet")) then
		if M._warned then M._log("the 802.11r key-exchange socket is bound again") end
		M._streak, M._warned = 0, false
		return "ok"
	end
	M._streak = M._streak + 1
	if M._streak < M.CONFIRM then return "stale" end
	if not M._warned then
		M._warned = true
		M._log("hostapd's 802.11r key-exchange socket (0x88b7) has lost its interface; "
			.. "cross-AP fast roaming falls back to full authentication until wpad restarts. "
			.. "Restarting it when no client is connected, or between 04:00 and 05:00")
	end
	if M._last_repair and now - M._last_repair < M.REPAIR_GAP then return "waiting" end
	if hour ~= M.NIGHT_HOUR and M.station_count() ~= 0 then return "deferred" end
	M._last_repair = now
	M._streak = 0
	M._log("restarting wpad to reopen it")
	M._exec("(" .. M.REPAIR_CMD .. ") >/dev/null 2>&1 </dev/null &")
	return "repairing"
end

return M
