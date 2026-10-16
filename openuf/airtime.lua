--[[
	Airtime Fairness: the controller's per-device ATF switch.

	The controller pushes it as `atf.status=enabled` / `atf.mode=enabled|disabled`
	in system_cfg, only to a device claiming wifi_caps 0x20 (supportATFConfig).
	`mode` is the switch: it is enabled when the device's `atf_enabled` is on
	(default on for a U6-IW) and the site's advanced features are on (always on
	for 10.x, which rewrites the setting back to true).

	On OpenWrt the matching feature is mac80211's own airtime scheduler: every
	station gets an equal airtime share (weight 256), charged from the TX and RX
	airtime the driver reports. It is on by default on any driver that schedules
	through mac80211 TXQs (ath9k, ath10k, mt76), so "enabled" is the board's own
	default. The only switch is the per-phy debugfs file

	  /sys/kernel/debug/ieee80211/phyN/airtime_flags

	whose AIRTIME_TX (1) and AIRTIME_RX (2) bits select what is charged; 0
	charges nothing and the scheduler falls back to plain round-robin. hostapd's
	airtime_mode is not this switch: all of its modes keep the scheduler on and
	only set station weights.

	debugfs is live kernel state and resets to 3 on reboot, so the pushed value
	is kept in state.json and reapplied at startup (inform's M.run).
]]--

local M = {}
local util = package.loaded["openuf.util"]
	or assert(loadfile("util.lua") or loadfile("openuf/util.lua"))()

M.DEBUGFS = "/sys/kernel/debug/ieee80211"
M.FLAGS_ON = "3"   -- AIRTIME_TX | AIRTIME_RX, mac80211's default
M.FLAGS_OFF = "0"

M._run_cmd = util.capture

M._write_file = function(path, contents)
	local f = io.open(path, "w")
	if not f then return false end
	local ok = f:write(contents)
	-- debugfs reports a rejected value on close, not on write.
	local closed = f:close()
	return ok ~= nil and closed ~= nil and closed ~= false
end

M._read_file = util.read_file

-- Every phy's airtime_flags file, sorted.
function M.flag_files()
	local out = {}
	for line in M._run_cmd("ls -d " .. M.DEBUGFS .. "/phy*/airtime_flags"):gmatch("[^\n]+") do
		if line:match("^/sys/kernel/debug/ieee80211/phy%d+/airtime_flags$") then
			out[#out + 1] = line
		end
	end
	table.sort(out)
	return out
end

-- Cached: the phys and debugfs do not come and go while the daemon runs, and
-- build_json asks on every heartbeat. nil = not probed yet.
M._supported_cache = nil

-- Can this device switch airtime fairness? Claimed to the controller as
-- wifi_caps 0x20; without it the controller sends no atf block at all.
function M.supported()
	if M._supported_cache ~= nil then return M._supported_cache end
	M._supported_cache = #M.flag_files() > 0
	return M._supported_cache
end

-- The atf.* block of a system_cfg: true/false for atf.mode, nil when the
-- block (or its mode) is absent, which leaves the current setting alone.
function M.parse(sys_raw)
	if type(sys_raw) ~= "string" then return nil end
	local mode = sys_raw:match("\natf%.mode=([%w_]+)")
		or sys_raw:match("^atf%.mode=([%w_]+)")
	if mode == "enabled" then return true end
	if mode == "disabled" then return false end
	return nil
end

-- Set every phy on or off. Returns the number of phys whose flags read back
-- as requested, and the number of phys found.
function M.set_enabled(enabled)
	local want = enabled and M.FLAGS_ON or M.FLAGS_OFF
	local files = M.flag_files()
	local done = 0
	for _, path in ipairs(files) do
		if M._write_file(path, want) then
			-- Read back: the file lists the names of the set bits, and is
			-- empty of them when 0.
			local now = M._read_file(path) or ""
			local on = now:find("AIRTIME_TX", 1, true) ~= nil
				and now:find("AIRTIME_RX", 1, true) ~= nil
			local off = now:find("AIRTIME_", 1, true) == nil
			if (enabled and on) or (not enabled and off) then
				done = done + 1
			end
		end
	end
	if done < #files then
		io.stderr:write(("airtime: turning fairness %s: %d of %d phys read back as requested\n"):format(
			enabled and "on" or "off", done, #files))
	end
	return done, #files
end

return M
