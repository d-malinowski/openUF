-- Tests for openuf/assoctrack.lua (STA_ASSOC_TRACKER connection notifs).
-- Run from project root: lua tests/run_tests.lua
--
-- tests/fixtures/ubus_assoc_events.txt is a real capture (2026-10-09, Archer
-- C5, OpenWrt 25.12) of one phone being deauthenticated and reconnecting, as
-- rrmscan's collector writes it: /proc/uptime, then the ubus notification.
-- MACs are mapped to documentation placeholders.

local at = dofile("openuf/assoctrack.lua")

local STA  = "00:00:5e:00:53:01"
local IF   = "phy1-ap0"
local VAP  = "openuf_radio1_home_lan"

local function read_fixture(name)
	local f = assert(io.open("tests/fixtures/" .. name, "r"))
	local s = f:read("*a")
	f:close()
	return s
end

local function reset()
	at._stas, at._queue = {}, {}
	at._here, at._roamed, at._kicks, at._roam_queue = {}, {}, {}, {}
end

-- Roam reports: a second BSS on this AP, and the collector's lines for them.
local IF2  = "phy0-ap0"
local VAP2 = "openuf_radio0_home_lan"
local MAP  = {[IF] = VAP, [IF2] = VAP2}
local function line(t, ev, body) return string.format('%.2f { "%s": {%s} }', t, ev, body) end
local function assoc(t, ifname, sig)
	return line(t, "assoc", string.format('"address":"%s","ifname":"%s","signal":%d', STA, ifname, sig))
end
local function authorized(t, ifname, alg)
	return line(t, "sta-authorized", string.format('"address":"%s","ifname":"%s","auth-alg":"%s"', STA, ifname, alg))
end
local function disassoc(t, ifname)
	return line(t, "disassoc", string.format('"address":"%s","ifname":"%s"', STA, ifname))
end
-- As the collector's fdb half writes them, from `bridge monitor fdb` on the
-- Archer C5 (swconfig) and the AX3000T (DSA), 2026-10-14.
local function fdb(t, port) return string.format("%.2f fdb %s dev %s master br-lan ", t, STA, port) end
local function roams(lines, map)
	return at.roam_ingest(at.parse_events(table.concat(lines, "\n")), map or MAP)
end

-- One connection from the fixture: auth 13.20, assoc 13.25, authorized 13.32.
local T_AUTH = 5905613.20

local function ingest_fixture()
	reset()
	at.ingest(at.parse_events(read_fixture("ubus_assoc_events.txt")))
end

-- sets[name] = {mac = {t = uptime, n = packets}} as parse_sets returns.
local function ctx(now, sets)
	return {now = now, epoch = 1791580000, sets = sets or {},
		vap_by_ifname = {[IF] = VAP}}
end

local function ev(t, n) return {[STA] = {t = t, n = n or 1}} end

return {
	{
		name = "assoctrack: parse_events keeps the four connection events, timestamped",
		fn = function()
			local evs = at.parse_events(read_fixture("ubus_assoc_events.txt"))
			assert_eq(#evs, 4, "probe and link-measurement lines are not events")
			assert_eq(evs[1].ev, "disassoc", "disassoc")
			assert_eq(evs[2].ev, "auth", "auth")
			assert_eq(evs[2].t, 5905613.20, "uptime prefix is the event time")
			assert_eq(evs[2].signal, -64, "auth carries the signal")
			assert_eq(evs[2].ifname, IF, "and the BSS netdev")
			assert_eq(evs[3].ev, "assoc", "assoc")
			assert_eq(evs[4].ev, "sta-authorized", "sta-authorized")
			assert_eq(evs[4].alg, "open", "auth-alg is read")
			assert_eq(evs[4].mac, STA, "address")
		end
	},
	{
		-- A collector started by an older openUF writes bare lines. Without a
		-- time there are no deltas, so they are not events at all.
		name = "assoctrack: lines without the uptime prefix are ignored",
		fn = function()
			local bare = '{ "auth": {"address":"00:00:5e:00:53:01","ifname":"phy1-ap0","signal":-64} }\n'
			assert_eq(#at.parse_events(bare), 0, "no timestamp, no event")
		end
	},
	{
		name = "assoctrack: nft durations parse to the millisecond",
		fn = function()
			assert_eq(at.parse_duration("1m58s694ms"), 118.694, "m s ms")
			assert_eq(at.parse_duration("2m"), 120, "minutes alone")
			assert_eq(at.parse_duration("694ms"), 0.694, "ms alone")
			assert_eq(at.parse_duration("1h2m3s"), 3723, "hours")
			assert_eq(at.parse_duration("soon"), nil, "garbage")
		end
	},
	{
		-- Shape copied from `nft list table` on nftables 1.0.9 (lab) with a
		-- counter-carrying dynamic set. JSON output rounds expires to whole
		-- seconds, which is why the text is parsed.
		name = "assoctrack: parse_sets recovers first-seen time and packet count",
		fn = function()
			local text = table.concat({
				"table bridge openuf_assoc {",
				"\tset dns_resp {",
				"\t\ttype ether_addr",
				"\t\tsize 65535",
				"\t\tflags dynamic,timeout",
				"\t\tcounter",
				"\t\ttimeout 2m",
				"\t\telements = { 00:00:5e:00:53:01 counter packets 4 bytes 112 expires 1m52s974ms,",
				"\t\t\t     00:00:5e:00:53:02 counter packets 1 bytes 28 expires 5s }",
				"\t}",
				"\tset dhcp_req {",
				"\t\ttype ether_addr",
				"\t\tflags dynamic,timeout",
				"\t\tcounter",
				"\t\ttimeout 2m",
				"\t}",
				"}",
			}, "\n")
			local sets = at.parse_sets(text, 1000)
			local e = sets.dns_resp[STA]
			assert_true(e ~= nil, "element found")
			assert_true(math.abs(e.t - (1000 - (120 - 112.974))) < 1e-6, "first seen = now - (timeout - expires)")
			assert_eq(e.n, 4, "packet counter")
			assert_true(sets.dns_resp["00:00:5e:00:53:02"] ~= nil, "second element on a continuation line")
			assert_true(sets.dhcp_req ~= nil and next(sets.dhcp_req) == nil, "an empty set parses as empty")
		end
	},
	{
		name = "assoctrack: the nft table is idempotent and needs no bridge meta",
		fn = function()
			local s = at.nft_script()
			assert_true(s:find("^table bridge openuf_assoc\ndelete table bridge openuf_assoc\n") ~= nil,
				"create-delete-create: a re-run replaces instead of appending rules")
			for _, name in ipairs(at.SETS) do
				assert_true(s:find("set " .. name .. " { type ether_addr; flags dynamic,timeout; timeout 120s; counter; }", 1, true) ~= nil,
					name .. " is a timed, counting dynamic set")
			end
			-- `add`, never `update`: update refreshes the element and the
			-- first-seen time would be lost.
			assert_false(s:find("update @", 1, true) ~= nil, "no update")
			assert_false(s:find("meta ", 1, true) ~= nil, "no nft_meta_bridge dependency (see bcfilter.lua)")
			assert_true(s:find("hook forward", 1, true) ~= nil, "forward hook")
		end
	},
	{
		name = "assoctrack: the collector's auth hook destroys every set's element",
		fn = function()
			local sh = at.forget_shell("m")
			for _, name in ipairs(at.SETS) do
				assert_true(sh:find("destroy element bridge openuf_assoc " .. name .. " { $m }", 1, true) ~= nil,
					name .. " cleared")
			end
			assert_eq(select(2, sh:gsub("nft ", "")), 1, "one nft process, one transaction")
		end
	},
	{
		name = "assoctrack: a full connection becomes one success with cumulative deltas",
		fn = function()
			ingest_fixture()
			local sets = {
				dhcp_req = ev(5905613.60),
				dhcp_ack = ev(5905613.95),
				ip_seen  = ev(5905614.00),
				dns_q    = ev(5905614.10),
				dns_resp = ev(5905614.15, 3),
			}
			local out = at.poll(ctx(5905620, sets))
			assert_eq(#out, 1, "one event")
			local p = out[1]
			assert_eq(p.message_type, "STA_ASSOC_TRACKER", "dispatch key")
			assert_eq(p.event_type, "success", "success")
			assert_eq(p.mac, STA, "station")
			assert_eq(p.vap, VAP, "vap_table name, not the netdev")
			assert_eq(p.assoc_delta, 50, "assoc 50 ms after auth")
			assert_eq(p.wpa_auth_delta, 120, "authorized 120 ms after auth")
			assert_eq(p.ip_assign_type, "dhcp", "DHCP was seen")
			assert_eq(p.ip_delta, 750, "lease from the ACK, cumulative from auth")
			assert_eq(p.traffic_delta, 950, "first DNS response, cumulative")
			assert_eq(p.dns_resp_seen, "yes", "dns")
			assert_eq(p.dns_responses, 3, "counted")
			assert_eq(p.auth_rssi, -62, "assoc signal supersedes auth's")
			assert_eq(p.auth_algo, "open", "algorithm")
			-- auth_ts: epoch at the auth, i.e. 6.8 s before the poll's epoch.
			assert_true(math.abs(p.auth_ts - (1791580000 - 6.8)) < 0.011, "auth_ts in epoch seconds")
			assert_eq(#at._queue, 1, "queued for sending")
			assert_true(next(at._stas) == nil, "attempt closed")
		end
	},
	{
		-- The controller's metrics handler reads every one of these with
		-- getLong/getInt; one absent key throws and the event is lost.
		name = "assoctrack: every numeric field the controller reads is present",
		fn = function()
			ingest_fixture()
			local p = at.poll(ctx(5905620, {dns_resp = ev(5905614.15)}))[1]
			for _, k in ipairs({"assoc_delta", "auth_delta", "wpa_auth_delta", "ip_delta",
				"traffic_delta", "assoc_failures", "auth_failures", "wpa_auth_failures",
				"ip_failures", "dns_timeouts", "traffic_failures", "dns_responses", "auth_ts"}) do
				assert_eq(type(p[k]), "number", k)
			end
			for _, k in ipairs({"event_id", "event_type", "mac", "vap", "ip_assign_type",
				"dns_resp_seen", "arp_reply_gw_seen"}) do
				assert_eq(type(p[k]), "string", k)
			end
			-- Success under supportTrafficStaTrackerEvents needs both > 0.
			assert_true(p.traffic_delta > 0 and p.dns_responses > 0, "success is recognisable as such")
		end
	},
	{
		-- Evidence older than this attempt (a set element the collector's
		-- hook did not clear) must not be credited to it.
		name = "assoctrack: set evidence from before the auth is not this attempt's",
		fn = function()
			ingest_fixture()
			local out = at.poll(ctx(5905620, {dns_resp = ev(5905600), dns_q = ev(5905600)}))
			assert_eq(#out, 0, "not yet decided: no evidence, window still open")
			out = at.poll(ctx(5905613.32 + at.WINDOW + 1, {dns_resp = ev(5905600), dns_q = ev(5905600)}))
			assert_eq(#out, 0, "and no event at all once it closes: nothing to judge")
		end
	},
	{
		name = "assoctrack: a DHCP request that never gets a lease is an ip failure",
		fn = function()
			ingest_fixture()
			local out = at.poll(ctx(5905613.32 + at.WINDOW + 1, {dhcp_req = ev(5905613.60, 4)}))
			assert_eq(#out, 1, "decided at window close")
			assert_eq(out[1].event_type, "failure", "failure")
			assert_eq(out[1].ip_failures, 1, "DHCP stage")
			assert_eq(out[1].ip_assign_type, "dhcp", "dhcp")
		end
	},
	{
		name = "assoctrack: DNS queries with no answer are a DNS failure",
		fn = function()
			ingest_fixture()
			local out = at.poll(ctx(5905613.32 + at.WINDOW + 1, {
				dhcp_req = ev(5905613.60), dhcp_ack = ev(5905613.90), dns_q = ev(5905614.0, 6),
			}))
			assert_eq(#out, 1, "one event")
			assert_eq(out[1].event_type, "failure", "failure")
			assert_eq(out[1].dns_resp_seen, "no", "no response seen")
			assert_eq(out[1].dns_timeouts, 1, "counted as a timeout")
			assert_eq(out[1].ip_delta, 700, "the DHCP stage it did pass is still reported")
		end
	},
	{
		name = "assoctrack: a station that leaves mid-window is decided at once",
		fn = function()
			ingest_fixture()
			at.ingest(at.parse_events('5905615.00 { "disassoc": {"address":"00:00:5e:00:53:01","ifname":"phy1-ap0"} }\n'))
			local out = at.poll(ctx(5905616, {dhcp_req = ev(5905613.60)}))
			assert_eq(#out, 1, "no waiting out the window")
			assert_eq(out[1].ip_failures, 1, "left without a lease")
		end
	},
	{
		-- A wrong passphrase: associated, never authorized.
		name = "assoctrack: associated but never authorized is a WPA failure",
		fn = function()
			reset()
			at.ingest(at.parse_events(table.concat({
				'100.00 { "auth": {"address":"00:00:5e:00:53:01","ifname":"phy1-ap0","signal":-60} }',
				'100.05 { "assoc": {"address":"00:00:5e:00:53:01","ifname":"phy1-ap0","signal":-60} }',
				'104.00 { "disassoc": {"address":"00:00:5e:00:53:01","ifname":"phy1-ap0"} }',
			}, "\n")))
			local out = at.poll(ctx(105))
			assert_eq(#out, 1, "one event")
			assert_eq(out[1].event_type, "failure", "failure")
			assert_eq(out[1].wpa_auth_failures, 1, "handshake stage")
			assert_eq(out[1].assoc_delta, 50, "the stage it passed")
		end
	},
	{
		name = "assoctrack: an auth that never associates is not reported",
		fn = function()
			reset()
			at.ingest(at.parse_events('100.00 { "auth": {"address":"00:00:5e:00:53:01","ifname":"phy1-ap0","signal":-60} }\n'))
			assert_eq(#at.poll(ctx(100 + at.AUTH_WINDOW - 1)), 0, "still pending")
			assert_eq(#at.poll(ctx(100 + at.AUTH_WINDOW + 1)), 0, "expired silently")
			assert_true(next(at._stas) == nil, "and forgotten")
		end
	},
	{
		-- The controller counts "soft failure" + ip_assign_type "roam" as a
		-- successful connection: a fast roam keeps its lease.
		name = "assoctrack: a quiet fast roam is a soft failure of type roam",
		fn = function()
			reset()
			at.ingest(at.parse_events(table.concat({
				'200.00 { "auth": {"address":"00:00:5e:00:53:01","ifname":"phy1-ap0","signal":-55} }',
				'200.02 { "assoc": {"address":"00:00:5e:00:53:01","ifname":"phy1-ap0","signal":-55} }',
				'200.03 { "sta-authorized": {"address":"00:00:5e:00:53:01","ifname":"phy1-ap0","auth-alg":"ft"} }',
			}, "\n")))
			local out = at.poll(ctx(200.03 + at.WINDOW + 1))
			assert_eq(#out, 1, "one event")
			assert_eq(out[1].event_type, "soft failure", "soft failure")
			assert_eq(out[1].ip_assign_type, "roam", "roam")
			assert_eq(out[1].auth_algo, "ft", "ft")
		end
	},
	{
		name = "assoctrack: an attempt on a BSS with no vap_table entry is dropped",
		fn = function()
			ingest_fixture()
			local c = ctx(5905620, {dns_resp = ev(5905614.15)})
			c.vap_by_ifname = {}
			assert_eq(#at.poll(c), 0, "no band or WLAN to file it under")
			assert_eq(#at._queue, 0, "nothing queued")
		end
	},
	{
		name = "assoctrack: the queue is bounded and requeue keeps order",
		fn = function()
			reset()
			for i = 1, at.MAX_QUEUE + 5 do at._queue[#at._queue + 1] = {i = i} end
			at.requeue({})
			assert_eq(#at._queue, at.MAX_QUEUE, "capped")
			assert_eq(at._queue[1].i, 6, "oldest dropped first")
			local first = at.take(3)
			assert_eq(#first, 3, "take")
			assert_eq(first[1].i, 6, "oldest first")
			at.requeue({first[2], first[3]})
			assert_eq(at._queue[1].i, 7, "unsent go back to the front, in order")
			assert_eq(at._queue[2].i, 8, "in order")
		end
	},
	{
		name = "assoctrack: ensure_table installs only when the table is missing",
		fn = function()
			local o = at._exec
			local cmds = {}
			at._exec = function(cmd) cmds[#cmds + 1] = cmd; return 0 end  -- Lua 5.1 shape
			local ok1 = at.ensure_table()
			at._exec = function(cmd)
				cmds[#cmds + 1] = cmd
				if cmd:find("nft list table", 1, true) then return 1 end
				return 0
			end
			local before = #cmds
			local ok2 = at.ensure_table()
			at._exec = o
			assert_true(ok1, "present")
			assert_eq(before, 1, "present: only listed, never rebuilt (that would empty the sets)")
			assert_true(ok2, "installed")
			assert_true(cmds[#cmds]:find("^nft %-f ") ~= nil, "missing: loaded from a script")
		end
	},
	{
		-- OpenWrt's Lua 5.1 carries the LNUM patch: string.format's %d goes
		-- through a 32-bit integer and raises "integer expected, got number"
		-- above 2^31. Stock Lua does not, so this emulates it. The first
		-- deploy lost every connection to exactly this, in event_id.
		name = "assoctrack: no %d is fed a value beyond 32 bits (OpenWrt LNUM Lua)",
		fn = function()
			local real = string.format
			string.format = function(fmt, ...)
				local args, i = {...}, 0
				for spec in fmt:gmatch("%%[-+ #0]*%d*%.?%d*(%a)") do
					i = i + 1
					local v = args[i]
					if (spec == "d" or spec == "i") and type(v) == "number" and math.abs(v) > 2147483647 then
						error("bad argument #" .. (i + 1) .. " to 'format' (integer expected, got number)")
					end
				end
				return real(fmt, ...)
			end
			ingest_fixture()
			local ok, out = pcall(at.poll, ctx(5905620, {dns_resp = ev(5905614.15)}))
			string.format = real
			assert_true(ok, "poll survives: " .. tostring(out))
			assert_eq(#out, 1, "and decides")
			assert_true(out[1].event_id:match("^00005e005301%-%d+$") ~= nil, "event_id is mac-millis: " .. out[1].event_id)
		end
	},
	{
		name = "assoctrack: parse_events reads learned fdb entries, not ageing, switch or own ones",
		fn = function()
			local blob = table.concat({
				"6305912.12 fdb 00:00:5e:00:53:01 dev eth1 master br-lan ",
				"6305912.12 fdb 00:00:5e:00:53:01 dev eth1 vlan 1 master br-lan ",
				"222911.60 fdb 00:00:5e:00:53:02 dev wan self ",
				"6305913.13 fdb Deleted 00:00:5e:00:53:01 dev eth1 master br-lan ",
				"6305913.20 fdb 00:00:5e:00:53:10 dev br-lan master br-lan permanent",
				"6305913.30 fdb 00:00:5E:00:53:03 dev phy1-ap0 master br-lan ",
			}, "\n")
			local evs = at.parse_events(blob)
			assert_eq(#evs, 3, "two learned lines for .01 (plain and vlan) and one for .03")
			assert_eq(evs[1].ev, "fdb", "fdb event")
			assert_eq(evs[1].port, "eth1", "port")
			assert_eq(evs[1].t, 6305912.12, "uptime prefix")
			assert_eq(evs[3].mac, "00:00:5e:00:53:03", "lower-cased")
			assert_eq(evs[3].port, "phy1-ap0", "a BSS port is kept; roam_ingest judges it")
		end
	},
	{
		name = "assoctrack: an authorized station is announced once, with auth_rssi and auth_algo",
		fn = function()
			reset()
			local out = roams({assoc(100.10, IF, -61), authorized(100.22, IF, "ft")})
			assert_eq(#out, 1, "one association")
			local p = out[1]
			assert_eq(p.message_type, "STA_ASSOC_TRACKER", "message_type")
			assert_eq(p.event_type, "association", "event_type")
			assert_eq(p.mac, STA, "mac")
			assert_eq(p.vap, VAP, "vap_table name of the BSS")
			assert_eq(p.auth_rssi, -61, "signal of the association request")
			assert_eq(p.auth_algo, "ft", "hostapd's auth-alg: ft marks Fast Roaming")
			assert_eq(#at._roam_queue, 1, "queued for sending")
			out = roams({authorized(130.0, IF, "ft")})
			assert_eq(#out, 0, "a re-key is not a second arrival")
		end
	},
	{
		name = "assoctrack: no association without a signal or a known BSS",
		fn = function()
			reset()
			assert_eq(#roams({authorized(100.22, IF, "sae")}), 0, "authorized with no assoc seen: no auth_rssi")
			reset()
			assert_eq(#roams({assoc(100.10, "phy9-ap0", -61), authorized(100.22, "phy9-ap0", "sae")}), 0,
				"BSS without a vap_table entry")
		end
	},
	{
		name = "assoctrack: a disassociation is a sta_leave with avg_rssi, last_seen and why",
		fn = function()
			reset()
			roams({assoc(100.10, IF, -61), authorized(100.22, IF, "sae")})
			at._roam_queue = {}
			at.observe({{mac = STA, ifname = IF, signal = -72, inactive_ms = 1500}}, 200)
			local out = roams({disassoc(205.40, IF)})
			assert_eq(#out, 1, "one leave")
			local p = out[1]
			assert_eq(p.event_type, "sta_leave", "event_type")
			assert_eq(p.vap, VAP, "vap")
			assert_eq(p.avg_rssi, -72, "the latest heartbeat's signal")
			assert_eq(p.last_seen, 205, "whole seconds of uptime at the event")
			assert_eq(p.assoc_status, 0, "nobody sent it away")
			assert_eq(math.type and math.type(p.last_seen) or "integer", "integer", "an integer for getLong")
			assert_nil(at._here[STA], "no longer here")
			assert_eq(#roams({disassoc(206.0, IF)}), 0, "a second disassoc is not a second leave")
		end
	},
	{
		name = "assoctrack: a failed handshake is no departure",
		fn = function()
			reset()
			assert_eq(#roams({assoc(100.10, IF, -61), disassoc(102.0, IF)}), 0, "never authorized")
		end
	},
	{
		name = "assoctrack: kicks set assoc_status bits: 16 Minimum RSSI, 8192 Roaming Assistant",
		fn = function()
			local o_time = at._time
			local now = 5000
			at._time = function() return now end
			local ok, err = pcall(function()
				reset()
				roams({assoc(100.10, IF, -80), authorized(100.22, IF, "sae")})
				at.note_kick(STA, at.KICK_MIN_RSSI)
				local p = roams({disassoc(130.0, IF)})[1]
				assert_eq(p.assoc_status, 16, "Minimum RSSI kick")
				assert_nil(at._kicks[STA], "the ledger entry is spent")

				reset()
				roams({assoc(100.10, IF, -80), authorized(100.22, IF, "sae")})
				at.note_kick(STA, at.KICK_ROAM_ASSIST)
				now = now + 10
				at.note_kick(string.upper(STA), at.KICK_MIN_RSSI)
				p = roams({disassoc(130.0, IF)})[1]
				assert_eq(p.assoc_status, 8208, "both, OR'd")

				reset()
				roams({assoc(100.10, IF, -80), authorized(100.22, IF, "sae")})
				at.note_kick(STA, at.KICK_ROAM_ASSIST)
				now = now + at.KICK_TTL + 1
				p = roams({disassoc(130.0, IF)})[1]
				assert_eq(p.assoc_status, 0, "a kick older than KICK_TTL explains nothing")
			end)
			at._time = o_time
			if not ok then error(err, 0) end
		end
	},
	{
		-- Seen live 2026-10-14 (Pixel-9): the phone FT-roamed to the other AP
		-- at 11:18:44; this AP's bridge learned it on its uplink in that
		-- second, while hostapd here listed it until 11:18:50.
		name = "assoctrack: the address moving to the uplink while associated is a sta_roam",
		fn = function()
			local o_time = at._time
			at._time = function() return 5000 end
			local ok, err = pcall(function()
				reset()
				roams({assoc(100.10, IF, -61), authorized(100.22, IF, "sae")})
				at._roam_queue = {}
				at.observe({{mac = STA, ifname = IF, signal = -74, inactive_ms = 300}}, 300)
				at.note_kick(STA, at.KICK_ROAM_ASSIST)
				local out = roams({fdb(304.66, "eth1"), fdb(304.66, "eth1")})
				assert_eq(#out, 1, "one roam, though the vlan line repeats the move")
				local p = out[1]
				assert_eq(p.event_type, "sta_roam", "event_type")
				assert_eq(p.vap, VAP, "the BSS it left")
				assert_eq(p.avg_rssi, -74, "avg_rssi")
				assert_eq(p.last_seen, 299, "last frame heard, from the heartbeat")
				assert_eq(p.assoc_status, 8192, "Roaming Assistant's BTM request moved it")
				assert_eq(#roams({disassoc(310.0, IF)}), 0, "hostapd's late drop is not reported again")
				-- hostapd still lists it until then; the heartbeat must not take it back.
				reset()
				roams({assoc(100.10, IF, -61), authorized(100.22, IF, "sae")})
				roams({fdb(304.66, "eth1")})
				at.observe({{mac = STA, ifname = IF, signal = -90, inactive_ms = 4000}}, 306)
				assert_nil(at._here[STA], "roamed: not here again")
				at.observe({}, 316)
				assert_nil(at._roamed[STA], "hostapd dropped it: mark gone")
			end)
			at._time = o_time
			if not ok then error(err, 0) end
		end
	},
	{
		name = "assoctrack: fdb moves within this AP, or before the BSS map is known, are not roams",
		fn = function()
			reset()
			roams({assoc(100.10, IF, -61), authorized(100.22, IF, "sae")})
			assert_eq(#roams({fdb(101.0, IF)}), 0, "learned on its own BSS")
			assert_eq(#roams({fdb(102.0, IF2)}), 0, "moved to a sibling BSS of this AP")
			assert_eq(#roams({fdb(103.0, "eth1")}, {}), 0, "no BSS map yet")
			assert_true(at._here[STA] ~= nil, "still here after all three")
			reset()
			assert_eq(#roams({fdb(103.0, "eth1")}), 0, "a station that is not here")
			reset()
			roams({assoc(100.10, IF, -61)})
			assert_eq(#roams({fdb(103.0, "eth1")}), 0, "associated, not authorized")
		end
	},
	{
		-- A band change on this AP: the association on the new BSS comes
		-- first, the old BSS lets go after.
		name = "assoctrack: leaving one BSS of this AP for another is no sta_leave",
		fn = function()
			reset()
			roams({assoc(100.10, IF, -61), authorized(100.22, IF, "sae")})
			local out = roams({assoc(200.0, IF2, -55), authorized(200.1, IF2, "ft"), disassoc(200.5, IF)})
			assert_eq(#out, 1, "only the association")
			assert_eq(out[1].event_type, "association", "association")
			assert_eq(out[1].vap, VAP2, "on the new BSS")
		end
	},
	{
		name = "assoctrack: observe picks up stations associated before the collector saw them",
		fn = function()
			reset()
			at.observe({{mac = string.upper(STA), ifname = IF, signal = -66, inactive_ms = 2000}}, 500)
			local h = at._here[STA]
			assert_true(h ~= nil, "known")
			assert_eq(h.seen, 498, "last heard: uptime less inactive time")
			local out = roams({disassoc(520.0, IF)})
			assert_eq(#out, 1, "its departure is reported")
			assert_eq(out[1].avg_rssi, -66, "with the heartbeat's signal")
			at.observe({{mac = STA, ifname = IF, signal = -66}}, 600)
			at.observe({}, 610)
			assert_nil(at._here[STA], "gone from the dump: forgotten")
		end
	},
	{
		name = "assoctrack: a roamed station is away until hostapd drops it or it is heard here again",
		fn = function()
			reset()
			roams({assoc(100.10, IF, -61), authorized(100.22, IF, "sae")})
			roams({fdb(104.0, "eth1")})
			assert_true(at.roamed_away(STA, 110, 6000), "silent since the move: away")
			assert_true(at.roamed_away(string.upper(STA), 200, 96000), "case-insensitive, still away")
			at.observe({{mac = STA, ifname = IF, signal = -60, inactive_ms = 96000}}, 200)
			assert_nil(at._here[STA], "observe does not take it back")
			assert_false(at.roamed_away(STA, 210, 500), "a frame 2.5 s after the move: it is here")
			assert_nil(at._roamed[STA], "mark lifted")
			assert_false(at.roamed_away("00:00:5e:00:53:09", 210, 0), "never roamed")
			assert_false(at.roamed_away(nil, 210, 0), "no mac")
		end
	},
	{
		name = "assoctrack: roam queue is capped and requeues in order",
		fn = function()
			reset()
			for i = 1, at.MAX_ROAMS + 3 do
				at.requeue_roams({})
				at._roam_queue[#at._roam_queue + 1] = {i = i}
			end
			at.requeue_roams({})
			assert_eq(#at._roam_queue, at.MAX_ROAMS, "capped")
			local first = at.take_roams(2)
			assert_eq(first[1].i, 4, "oldest dropped first")
			at.requeue_roams(first)
			assert_eq(at._roam_queue[1].i, 4, "back at the front")
			assert_eq(at._roam_queue[2].i, 5, "in order")
		end
	},
	{
		name = "assoctrack: teardown forgets the roam state",
		fn = function()
			local o = at._exec
			at._exec = function() return 0 end
			at._here, at._roamed, at._kicks, at._roam_queue = {x = {}}, {x = 1}, {x = {}}, {{}}
			at.teardown()
			at._exec = o
			assert_nil(next(at._here), "here")
			assert_nil(next(at._roamed), "roamed")
			assert_nil(next(at._kicks), "kicks")
			assert_eq(#at._roam_queue, 0, "queue")
		end
	},
}
