-- Tests for openuf/rrmscan.lua (802.11k client-assisted RF environment
-- enrichment). Run from project root: lua tests/run_tests.lua
--
-- Both fixtures are REAL captures taken 2026-09-02 off an Archer C5 and an
-- AX3000T: tests/fixtures/ubus_beacon_report.txt is verbatim
-- `ubus subscribe hostapd.phy0-ap0` output while beacon requests were in
-- flight, and ubus_get_clients_rrm.txt carries the four distinct RRM
-- capability shapes actually seen on the network.

local rrmscan = dofile("openuf/rrmscan.lua")

local function read_fixture(name)
	local f = assert(io.open("tests/fixtures/" .. name, "r"))
	local s = f:read("*a")
	f:close()
	return s
end

-- Drive harvest() off a fixture instead of the live collector file.
local function with_events(text, fn)
	local orig_file, orig_now = rrmscan.EVENT_FILE, rrmscan._now
	local path = os.tmpname()
	local f = assert(io.open(path, "w"))
	f:write(text)
	f:close()
	rrmscan.EVENT_FILE = path
	rrmscan._now = function() return 1000 end
	local ok, err = pcall(fn)
	rrmscan.EVENT_FILE, rrmscan._now = orig_file, orig_now
	os.remove(path)
	if not ok then error(err, 0) end
end

local function with_popen(answer, fn)
	local orig = rrmscan._popen
	local seen = {}
	rrmscan._popen = function(cmd)
		seen[#seen + 1] = cmd
		return type(answer) == "function" and answer(cmd) or answer
	end
	local ok, err = pcall(fn, seen)
	rrmscan._popen = orig
	if not ok then error(err, 0) end
end

local function with_exec(fn)
	local orig = rrmscan._exec
	local cmds = {}
	rrmscan._exec = function(cmd) cmds[#cmds + 1] = cmd; return true end
	local ok, err = pcall(fn, cmds)
	rrmscan._exec = orig
	if not ok then error(err, 0) end
end

local function by_bssid(list)
	local m = {}
	for _, e in ipairs(list) do m[e.bssid] = e end
	return m
end

return {
	{
		name = "rrmscan: RCPI converts on the 0.5-dBm scale anchored at -110",
		fn = function()
			-- The anchor and the step are both load-bearing: an off-by-one in
			-- either turns every neighbour's signal into a plausible-looking
			-- but wrong dBm, which nothing downstream can detect.
			assert_eq(rrmscan.rcpi_to_dbm(124), -48, "strong (own AP) sighting")
			assert_eq(rrmscan.rcpi_to_dbm(32), -94, "far neighbour")
			assert_eq(rrmscan.rcpi_to_dbm(0), -110, "the scale's floor")
			assert_nil(rrmscan.rcpi_to_dbm(nil), "absent RCPI stays absent")
		end
	},
	{
		name = "rrmscan: a reported channel maps to a band and a frequency",
		fn = function()
			assert_eq(rrmscan.band_of_channel(11), "ng", "2.4 GHz")
			assert_eq(rrmscan.band_of_channel(44), "na", "5 GHz")
			assert_eq(rrmscan.freq_of_channel(11), 2462, "ch 11")
			assert_eq(rrmscan.freq_of_channel(14), 2484, "ch 14 is the exception")
			assert_eq(rrmscan.freq_of_channel(44), 5220, "ch 44")
			-- Channels 15..31 exist in no band openUF reports; guessing one
			-- would file a neighbour under the wrong radio.
			assert_nil(rrmscan.band_of_channel(20), "no band for ch 20")
		end
	},
	{
		name = "rrmscan: only clients that can actually go and look are asked",
		fn = function()
			with_popen(read_fixture("ubus_get_clients_rrm.txt"), function()
				local stas = rrmscan.capable_stations("phy0-ap0")
				local set = {}
				for _, m in ipairs(stas) do set[m] = true end
				-- rrm=115 (passive+active+table) and rrm=50 (passive+active).
				assert_true(set["00:00:5e:00:53:10"], "full RRM client asked")
				assert_true(set["00:00:5e:00:53:1b"], "passive+active client asked")
				-- rrm=75 is beacon-TABLE only: acked every real request and
				-- answered none, and hostapd refuses a passive request for it
				-- outright. Asking it is pure airtime for no data.
				assert_false(set["00:00:5e:00:53:22"],
					"beacon-table-only client is NOT asked")
				-- rrm=0 -- most clients on a real network.
				assert_false(set["00:00:5e:00:53:18"], "non-802.11k client is not asked")
				assert_eq(#stas, 2, "exactly the two capable ones")
			end)
		end
	},
	{
		name = "rrmscan: harvest parses real notifications and drops the junk",
		fn = function()
			with_events(read_fixture("ubus_beacon_report.txt"), function()
				local n = rrmscan.harvest()
				local m = by_bssid(n)
				assert_eq(m["00:00:5e:00:53:11"].channel, 1, "2.4 GHz neighbour")
				assert_eq(m["00:00:5e:00:53:11"].band, "ng", "banded from the channel")
				assert_eq(m["00:00:5e:00:53:11"].signal, -73, "rcpi 74 -> -73 dBm")
				assert_eq(m["00:00:5e:00:53:15"].band, "na", "5 GHz neighbour")
				-- The captured rep-mode 4 report ("refused / incapable")
				-- carries an all-zero BSSID on channel 0. Both the BSSID
				-- guard and the rep-mode guard reject it, so this assertion
				-- alone does not prove the rep-mode one works -- see the next
				-- test for that.
				assert_nil(m["00:00:00:00:00:00"], "refused measurement dropped")
				-- Two clients both reported 00:00:5e:00:53:15.
				local count = 0
				for _, e in ipairs(n) do
					if e.bssid == "00:00:5e:00:53:15" then count = count + 1 end
				end
				assert_eq(count, 1, "a BSS seen by two clients is carried once")
				-- `probe` and `link-measurement-report` share the stream and
				-- are not neighbours.
				assert_nil(m["ff:ff:ff:ff:ff:ff"], "probe events are not neighbours")
			end)
		end
	},
	{
		name = "rrmscan: a non-zero rep-mode is dropped even with a real BSSID",
		fn = function()
			-- SYNTHETIC, unlike the other fixtures here: every captured
			-- refusal happened to also carry an all-zero BSSID, so the
			-- capture cannot distinguish the rep-mode guard from the BSSID
			-- guard. rep-mode is a bitfield (incapable / refused / late), and
			-- a client may set it while still naming the BSS it failed to
			-- measure properly -- which must not be published as a sighting.
			local ev =
				'{ "beacon-report": {"channel":11,"rcpi":80,' ..
				'"bssid":"aa:bb:cc:dd:ee:0f","rep-mode":2} }\n' ..
				'{ "beacon-report": {"channel":11,"rcpi":80,' ..
				'"bssid":"aa:bb:cc:dd:ee:10","rep-mode":0} }\n'
			with_events(ev, function()
				local m = by_bssid(rrmscan.harvest())
				assert_nil(m["aa:bb:cc:dd:ee:0f"],
					"refused measurement dropped despite a valid BSSID")
				assert_not_nil(m["aa:bb:cc:dd:ee:10"],
					"the accepted measurement beside it still lands")
			end)
		end
	},
	{
		name = "rrmscan: harvest survives a 64-bit start-time it cannot represent",
		fn = function()
			-- Real clients emit a raw TSF that overflows a double
			-- (-7160986498777481216 was captured). Parsing the payload as JSON
			-- is what made this a hazard; the fields we use are matched
			-- directly, so the report still lands.
			with_events(read_fixture("ubus_beacon_report.txt"), function()
				local m = by_bssid(rrmscan.harvest())
				assert_not_nil(m["00:00:5e:00:53:15"],
					"report with an out-of-range start-time still parsed")
			end)
		end
	},
	{
		name = "rrmscan: harvest drains the file so a report is never counted twice",
		fn = function()
			with_events(read_fixture("ubus_beacon_report.txt"), function()
				assert_true(#rrmscan.harvest() > 0, "first drain returns reports")
				assert_eq(#rrmscan.harvest(), 0, "second drain is empty")
			end)
		end
	},
	{
		name = "rrmscan: merge only adds new BSSIDs, on the matching band",
		fn = function()
			local passive = {
				{bssid = "00:00:5e:00:53:14", essid = "Home LAN",
				 security = "wpa2", channel = 6, bw = 40},
			}
			local neigh = {
				-- already known passively, with a richer record
				{bssid = "00:00:5e:00:53:14", channel = 6, band = "ng", signal = -48, seen_at = 100},
				-- new, same band
				{bssid = "00:00:5e:00:53:11", channel = 1, band = "ng", signal = -73, seen_at = 100},
				-- new, WRONG band for this radio
				{bssid = "00:00:5e:00:53:17", channel = 48, band = "na", signal = -80, seen_at = 100},
			}
			local out = rrmscan.merge_into(passive, neigh,
				{band = "ng", radio = "ng", radio_name = "radio0", now = 105})
			local m = by_bssid(out)
			assert_eq(#out, 2, "one appended, nothing duplicated or cross-banded")
			assert_eq(m["00:00:5e:00:53:14"].essid, "Home LAN",
				"the passive cache's richer record wins")
			assert_eq(m["00:00:5e:00:53:14"].bw, 40, "and keeps its real width")
			assert_nil(m["00:00:5e:00:53:17"], "other band not merged into this radio")
			local added = m["00:00:5e:00:53:11"]
			assert_eq(added.channel, 1, "channel carried")
			assert_eq(added.freq, 2412, "frequency derived")
			assert_eq(added.signal, -73, "signal carried")
			assert_eq(added.age, 5, "age is time since the client reported it")
			assert_eq(added.bw, 20, "width defaulted -- the Ch. Width cell "
				.. "renders nothing for a falsy value")
			-- The Environment tab filters on `band` upstream of every visible
			-- filter; an entry without it disappears with no error and no
			-- visible cause. Same trap inform.lua documents for scan_table.
			assert_eq(added.band, "ng", "band set, or the row silently vanishes")
			-- Defaulting this to "open" told the operator that four WPA2
			-- neighbours were unencrypted. A beacon report measures no
			-- security mode, so the field must be absent, not guessed.
			assert_nil(added.security, "security is never invented")
			assert_nil(added.essid, "SSID is never invented either")
			assert_eq(added.radio_name, "radio0", "attributed to the radio")
		end
	},
	{
		name = "rrmscan: merge drops sightings the controller would discard",
		fn = function()
			-- The controller's rogue-AP ingestion silently drops any entry
			-- with age >= 30. Carrying one past that is payload nobody reads.
			local neigh = {
				{bssid = "00:00:5e:00:53:11", channel = 1, band = "ng", signal = -73, seen_at = 100},
			}
			local fresh = rrmscan.merge_into({}, neigh,
				{band = "ng", now = 129, max_age = 30})
			assert_eq(#fresh, 1, "29 s old is still reportable")
			local stale = rrmscan.merge_into({}, neigh,
				{band = "ng", now = 130, max_age = 30})
			assert_eq(#stale, 0, "30 s old is dropped")
		end
	},
	{
		name = "rrmscan: the collector is started only when it is not running",
		fn = function()
			local orig_script = rrmscan.COLLECTOR_SCRIPT
			rrmscan.COLLECTOR_SCRIPT = os.tmpname()
			local ok, err = pcall(function()
				with_popen(function(cmd)
					if cmd:find("pgrep", 1, true) then return "" end   -- not running
					if cmd:find("ubus list", 1, true) then
						return "hostapd.phy0-ap0\nhostapd.phy1-ap0\nnetwork.wireless\n"
					end
					return ""
				end, function()
					with_exec(function(cmds)
						assert_true(rrmscan.collector_ensure(), "starts when absent")
						local all = table.concat(cmds, "\n")
						assert_true(all:find("sh " .. rrmscan.COLLECTOR_SCRIPT
							.. " hostapd.phy0-ap0 hostapd.phy1-ap0", 1, true) ~= nil,
							"runs the script over every hostapd BSS at once")
						assert_true(all:find("&") ~= nil, "runs in the background")
						local script = rrmscan._read_file(rrmscan.COLLECTOR_SCRIPT)
						-- `ubus listen` catches broadcast events and receives
						-- NOTHING here; only subscribe gets hostapd's per-object
						-- notifications. Confirmed live.
						assert_true(script:find('ubus subscribe "$@"', 1, true) ~= nil,
							"the script subscribes to the objects it is given")
						assert_false(script:find("ubus listen", 1, true) ~= nil,
							"never uses listen, which sees no beacon reports")
						-- So collector_running keeps matching the live process.
						assert_true(("ubus subscribe hostapd.phy0-ap0"):find("ubus subscribe hostapd", 1, true) ~= nil,
							"the spawned process still matches the liveness pattern")
					end)
				end)

				-- Running, and it is this script unchanged: left alone.
				with_popen(function(cmd)
					if cmd:find("pgrep", 1, true) then return "4711\n" end  -- running
					return ""
				end, function()
					with_exec(function(cmds)
						assert_false(rrmscan.collector_ensure(), "no-op while running")
						assert_eq(#cmds, 0, "spawns no second collector")
					end)
				end)
			end)
			os.remove(rrmscan.COLLECTOR_SCRIPT)
			rrmscan.COLLECTOR_SCRIPT = orig_script
			if not ok then error(err, 0) end
		end
	},
	{
		-- A collector is reparented to init, so it survives an openUF upgrade
		-- and a config change. One from an older openUF writes untimestamped
		-- lines; one without the on_auth hook leaves stale set evidence in
		-- place. Either must be replaced, not merely found alive.
		name = "rrmscan: a running collector that is not the wanted script is replaced",
		fn = function()
			local orig_script = rrmscan.COLLECTOR_SCRIPT
			rrmscan.COLLECTOR_SCRIPT = os.tmpname()
			local ok, err = pcall(function()
				local answers = function(cmd)
					if cmd:find("pgrep", 1, true) then return "4711\n" end
					if cmd:find("ubus list", 1, true) then return "hostapd.phy0-ap0\n" end
					return ""
				end
				-- Old-style collector: ubus subscribe is alive, no script file.
				os.remove(rrmscan.COLLECTOR_SCRIPT)
				with_popen(answers, function()
					with_exec(function(cmds)
						assert_true(rrmscan.collector_ensure(), "replaced")
						local all = table.concat(cmds, "\n")
						assert_true(all:find("kill $(pgrep", 1, true) ~= nil, "the old one is stopped")
						assert_true(all:find("sh " .. rrmscan.COLLECTOR_SCRIPT, 1, true) ~= nil,
							"and the script started")
					end)
				end)
				-- Same script but a hook is now wanted: replaced again.
				with_popen(answers, function()
					with_exec(function(cmds)
						assert_true(rrmscan.collector_ensure({on_auth = "true"}), "replaced on opts change")
					end)
				end)
				-- And left alone once it matches.
				with_popen(answers, function()
					with_exec(function(cmds)
						assert_false(rrmscan.collector_ensure({on_auth = "true"}), "kept when unchanged")
						assert_eq(#cmds, 0, "nothing spawned or killed")
					end)
				end)
			end)
			os.remove(rrmscan.COLLECTOR_SCRIPT)
			rrmscan.COLLECTOR_SCRIPT = orig_script
			if not ok then error(err, 0) end
		end
	},
	{
		name = "rrmscan: harvest takes a blob drained once for several consumers",
		fn = function()
			local blob = read_fixture("ubus_beacon_report.txt")
			with_events("", function()
				assert_true(#rrmscan.harvest(blob) > 0, "parses the blob it is given")
			end)
			-- Timestamp prefixes added by the collector do not disturb it.
			local stamped = blob:gsub("([^\n]+)", "5905613.20 %1")
			with_events("", function()
				assert_eq(#rrmscan.harvest(stamped), #rrmscan.harvest(blob), "prefix-agnostic")
			end)
		end
	},
	{
		-- The collector is a detached `ubus subscribe` child reparented to
		-- init, so it outlives the daemon. It has to be killed explicitly, and
		-- the notification file has to go with it: harvest() is the only thing
		-- that truncates it, so a file left behind with no reader grows without
		-- bound on a RAM-disk /tmp.
		name = "rrmscan: collector_stop kills the subscriber and removes the event file",
		fn = function()
			with_exec(function(cmds)
				rrmscan.collector_stop()
				local all = table.concat(cmds, "\n")
				assert_true(all:find("kill $(pgrep -f '[u]bus subscribe hostapd')", 1, true) ~= nil,
					"kills the subscriber by the pattern collector_ensure spawns")
				-- busybox on the Archer C5 (OpenWrt 25.12) has no pkill
				-- applet: a pkill here is a no-op on real hardware.
				assert_false(all:find("pkill", 1, true) ~= nil, "does not rely on pkill")
				assert_true(all:find("rm -f " .. rrmscan.EVENT_FILE, 1, true) ~= nil,
					"removes the notification file it was appending to")
			end)
		end
	},
	{
		name = "rrmscan: a request asks for an ACTIVE all-channel measurement",
		fn = function()
			with_exec(function(cmds)
				rrmscan.request("phy1-ap0", "00:00:5e:00:53:10")
				local c = table.concat(cmds, "\n")
				assert_true(c:find("hostapd.phy1%-ap0 rrm_beacon_req") ~= nil,
					"goes to the right BSS object")
				assert_true(c:find('"addr":"00:00:5e:00:53:10"', 1, true) ~= nil,
					"names the station")
				-- mode 1 is active measurement: the client probes rather than
				-- only listening, which is what makes it report BSSes on
				-- channels it is not sitting on. mode 2 (beacon table) reports
				-- from a cache that may be empty.
				assert_true(c:find('"mode":1', 1, true) ~= nil, "active measurement")
				-- 255 means every channel in the operating class; a single
				-- channel would report only what the radio already knows.
				assert_true(c:find('"channel":255', 1, true) ~= nil, "sweeps all channels")
			end)
		end
	},
	{
		name = "rrmscan: harvest names the stations that actually answered",
		fn = function()
			-- A station's RRM capability bits are not a promise: one can
			-- advertise passive, active AND table measurement and answer every
			-- variant with report mode 0x02, "incapable". hostapd notifies
			-- over ubus only when a report BODY arrived, so a bodiless refusal
			-- never reaches this file and its ABSENCE is the only signal the
			-- caller has. Returned alongside the neighbours so the caller can
			-- stop asking a station that never reports.
			with_events(read_fixture("ubus_beacon_report.txt"), function()
				local _, reporters = rrmscan.harvest()
				assert_true(reporters["00:00:5e:00:53:10"] == true,
					"the station whose reports carried bodies is a reporter")
				assert_true(reporters["00:00:5e:00:53:1b"] == true, "and so is the second one")
			end)

			-- A bodied refusal is a station declining too, and must not count
			-- as an answer.
			with_events('{ "beacon-report": {"address":"aa:bb:cc:dd:ee:ff","op-class":115,'
				.. '"channel":0,"rcpi":0,"bssid":"00:00:00:00:00:00","rep-mode":4} }\n',
				function()
					local out, reporters = rrmscan.harvest()
					assert_eq(#out, 0, "and reports no neighbour")
					assert_nil(reporters["aa:bb:cc:dd:ee:ff"], "a refusal is not an answer")
				end)
		end
	},
}
