--[[
	"WiFi Blackout Schedule" (a WLAN's schedule_with_duration): the windows in
	which a WLAN is off the air.

	THE WIRE (lab capture, controller 10.4.57; 10.6 has the same emitter)

	wireless.<n>.schedule_enabled=enabled, then the times the WLAN is ON, one
	key per block: schedule_<sun..sat>[.<i>]=HHMM-HHMM. The controller stores
	the blackout windows and inverts them itself, because openUF does not
	claim fw_caps 0x400000 (schedule_invert). A window past midnight is split
	at the day boundary. A day that is blacked out entirely has no key, and a
	day without a blackout gets 0000-2359. With fw_caps 0x1000, which openUF
	claims, a day's blocks are numbered .0, .1, ...; without it they all
	share the bare key, so only one of them survives a parse. The same push
	carries a cron job, `1-59/5 * * * * syswrapper.sh schedule-action`, the
	firmware's re-check; here the inform loop does that (sysconf.lua). A WLAN
	without a schedule gets no schedule_* keys at all.

	WHAT THE FIRMWARE DOES (firmware-confirmed for 4.0.15)

	ubntbox writes /var/run/schedules/schedule.<ath> for every VAP. With
	schedule_enabled off it writes 00:00-23:59 for every day. With it on, it
	writes one line d=HH:MM-HH:MM per block (the bare key, else .0, then .1
	up to .98) and d=00:01-00:00, which never matches, for a day with none.
	syswrapper.sh's configure_vap then brings a user or guest VAP up if the
	current minute is inside one of today's blocks (from <= now <= to, both
	ends included), and takes it down with ifconfig otherwise. Until
	ntpclient has set the clock (/var/run/ntp.ready) every VAP stays up. It
	runs on every config apply, when br0 comes up and from the 5-minute cron.

	openUF stores those lines on the wifi-iface (openuf_schedule) and checks
	them on every heartbeat, so a WLAN follows its schedule within one
	heartbeat instead of at the next 5-minute mark. Down is the firmware's:
	the BSS netdev goes down. Up needs one more step on OpenWrt: the netdev
	comes up, then hostapd is told to start that BSS's beacon again
	(restart_beacon).
]]--

local M = {}

-- Index - 1 is the weekday as `date +%w` counts it: 0 is Sunday.
M.DAYS = {"sun", "mon", "tue", "wed", "thu", "fri", "sat"}

-- ubntbox reads at most .98.
M.MAX_INDEX = 98

-- Injectable seams, as in the other modules.
M._exec = function(cmd) return os.execute(cmd) end
M._popen = function(cmd)
	local p = io.popen(cmd)
	if not p then return nil end
	local out = p:read("*a")
	p:close()
	return out
end
M._read_file = function(path)
	local f = io.open(path, "r")
	if not f then return nil end
	local s = f:read("*a")
	f:close()
	return s
end

-- ubntbox's sscanf("%2d%2d-%2d%2d"): "0700-2200" -> "07:00-22:00". nil when
-- it does not parse.
local function block(v)
	local h1, m1, h2, m2 = tostring(v):match("^(%d%d)(%d%d)%-(%d%d)(%d%d)")
	if not h1 then return nil end
	return h1 .. ":" .. m1 .. "-" .. h2 .. ":" .. m2
end

-- One WLAN's wireless.<n> keys (without the "wireless.<n>." prefix) -> the
-- firmware's schedule lines, or nil when schedule_enabled is not on. The
-- firmware's 00:00-23:59 for every day is the same as no schedule.
function M.lines(w)
	if type(w) ~= "table" then return nil end
	local on = w.schedule_enabled
	if not (on == "enabled" or on == "true" or on == "1") then return nil end
	local out = {}
	for d, name in ipairs(M.DAYS) do
		local key = "schedule_" .. name
		local n = 0
		local first = w[key]
		if first == nil then first = w[key .. ".0"] end
		if first ~= nil then
			local values = {first}
			for i = 1, M.MAX_INDEX do
				local v = w[key .. "." .. i]
				if v == nil then break end
				values[#values + 1] = v
			end
			for _, v in ipairs(values) do
				local b = block(v)
				if b then
					out[#out + 1] = (d - 1) .. "=" .. b
					n = n + 1
				end
			end
		end
		if n == 0 then out[#out + 1] = (d - 1) .. "=00:01-00:00" end
	end
	return out
end

-- The UCI option holds the lines space-separated.
function M.encode(lines) return table.concat(lines, " ") end
function M.decode(s)
	local out = {}
	for l in tostring(s or ""):gmatch("%S+") do out[#out + 1] = l end
	return out
end

-- syswrapper.sh's within_schedule: is minute `now` (0-1439) of weekday
-- `wday` (0 = Sunday) inside one of that day's blocks?
function M.within(lines, wday, now)
	for _, l in ipairs(lines or {}) do
		local d, h1, m1, h2, m2 = l:match("^(%d)=(%d%d):(%d%d)%-(%d%d):(%d%d)$")
		if d and tonumber(d) == wday then
			local from = tonumber(h1) * 60 + tonumber(m1)
			local to = tonumber(h2) * 60 + tonumber(m2)
			if now >= from and now <= to then return true end
		end
	end
	return false
end

-- vaps: {{ifnames = {...}, lines = {...}}, ...}. Returns the set of
-- ifnames to hold down at this weekday and minute.
function M.down_set(vaps, wday, now)
	local down = {}
	for _, v in ipairs(vaps or {}) do
		if not M.within(v.lines, wday, now) then
			for _, n in ipairs(v.ifnames or {}) do down[n] = true end
		end
	end
	return down
end

local function valid_ifname(n)
	return type(n) == "string" and n:match("^[%w%-%._]+$") ~= nil
end

-- IFF_UP from sysfs. nil when the netdev does not exist.
function M.is_up(ifname)
	local flags = tonumber(M._read_file("/sys/class/net/" .. ifname .. "/flags") or "")
	if not flags then return nil end
	return flags % 2 == 1
end

local function set_link(ifname, up)
	local rc = M._exec("ip link set dev " .. ifname .. (up and " up" or " down") .. " 2>/dev/null")
	return rc == 0 or rc == true
end

-- The BSS's beacon, after its netdev came back up. hostapd (OpenWrt 25.12,
-- ath9k/ath10k/mt76, 2026-10-11) does not act on the link going down, so
-- on the way up it still believes its beacon is set and only updates it,
-- which mac80211 refuses ("Failed to set beacon parameters") since the
-- netdev going down stopped the AP: the BSS stays up but off the air.
-- STOP_AP clears hostapd's beacon-set flag, so UPDATE_BEACON starts the AP
-- again. Both act on this BSS alone.
local function restart_beacon(ifname)
	local cli = "hostapd_cli -i " .. ifname .. " "
	M._popen(cli .. "raw STOP_AP 2>/dev/null")
	return tostring(M._popen(cli .. "update_beacon 2>/dev/null") or ""):match("^OK") ~= nil
end

-- Make the links match `down` (a set). held: the ifnames this module took
-- down earlier (a list, persisted). A held one no longer in `down` is
-- brought back up unless keep_down (a set: selfrun's guest VAPs) still
-- holds it. A netdev in `down` that is up is taken down even when it is
-- already held: a wifi reload recreates it up. Returns the new held list and
-- what changed, as {down = {...}, up = {...}}.
function M.reconcile(down, held, keep_down)
	local changed = {down = {}, up = {}}
	local names = {}
	for n in pairs(down or {}) do names[#names + 1] = n end
	table.sort(names)
	local new_held = {}
	for _, n in ipairs(names) do
		if valid_ifname(n) then
			if M.is_up(n) then
				if set_link(n, false) then changed.down[#changed.down + 1] = n end
			end
			new_held[#new_held + 1] = n
		end
	end
	for _, n in ipairs(held or {}) do
		if not (down and down[n]) and valid_ifname(n) and not (keep_down and keep_down[n]) then
			if M.is_up(n) == false then
				local up = set_link(n, true)
				if up and restart_beacon(n) then
					changed.up[#changed.up + 1] = n
				else
					-- Down again and still held, so the next pass retries
					-- the whole bring-up rather than leaving an up netdev
					-- with no beacon.
					if up then set_link(n, false) end
					new_held[#new_held + 1] = n
				end
			end
		end
	end
	return new_held, changed
end

return M
