--[[
	Client connection tracking for the controller's WiFi Connectivity view
	(Insights -> AirView -> Connectivity: Association / Authentication / DHCP /
	DNS / Success, and "Initial WiFi Connections (N)").

	The controller builds that funnel from nothing it can see itself. A UniFi
	AP reports each connection attempt as a separate "notif inform" carrying a
	STA_ASSOC_TRACKER payload (see PROTOCOL-VALIDATION.md, "Connection
	tracking notifs"). Without them the view reads 0% on every stage with
	"Initial WiFi Connections (0)" -- not failures, an empty dataset.

	Where each stage comes from:

	  auth / assoc / authorized -- hostapd's ubus notifications ("auth",
	      "assoc", "sta-authorized", "disassoc"), received by rrmscan's
	      `ubus subscribe` collector, which prefixes every line with
	      /proc/uptime so the deltas are real (10 ms resolution). Captured
	      on the Archer C5: auth -> assoc 40 ms -> sta-authorized 120 ms,
	      sta-authorized arriving after the 4-way handshake with "auth-alg".
	  DHCP / DNS -- hostapd knows nothing past the handshake, so a bridge
	      table watches the station's own frames. Dynamic sets keyed on the
	      station's MAC are filled with `add`, which never refreshes an
	      element: its remaining `expires` dates the FIRST matching frame to
	      the millisecond, and a per-element counter counts the rest. Both
	      properties verified against real nft with real frames.

	Nothing here is inferred. A stage with no evidence either way is left
	out of the verdict: a station that never sends a DNS query in the window
	produces no event at all, because the controller's Success rule needs DNS
	responses and inventing a "yes" or a timeout would both be lies.
]]--

local M = {}

M._exec      = function(cmd) return os.execute(cmd) end
M._popen     = function(cmd)
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

-- 5.1 returns the raw exit status (0 and 1 are both truthy); 5.4 returns
-- true/nil. Normalise before branching.
local function exec_ok(status)
	if status == nil or status == false then return false end
	if type(status) == "number" then return status == 0 end
	return true
end

M.NFT_FAMILY = "bridge"
M.NFT_NAME   = "openuf_assoc"
M.NFT_TABLE  = M.NFT_FAMILY .. " " .. M.NFT_NAME

-- Set element lifetime. Only has to outlive one poll after the window
-- closes; first-seen times are recovered from it, so it is also the
-- reference the parser subtracts `expires` from.
M.SET_TIMEOUT = 120

-- How long a station has after association to finish the handshake.
M.AUTH_WINDOW = 10
-- How long a station has after authorization to show DHCP/DNS evidence.
M.WINDOW      = 30
-- Pending notifs are dropped beyond this, oldest first.
M.MAX_QUEUE   = 64

M.SETS = {"dhcp_req", "dhcp_ack", "ip_seen", "dns_q", "dns_resp"}

-- Every station frame of interest crosses the bridge's forward hook: the
-- station's own traffic heads for the uplink, the server's replies head for
-- the VAP. Nothing here needs nft_meta_bridge (see bcfilter.lua).
function M.nft_script()
	local t = M.SET_TIMEOUT
	local lines = {
		-- Create-then-delete-then-create: idempotent whether or not the
		-- table exists, in one transaction. A bare `-f` of the body alone
		-- appends a second copy of every rule on each run.
		"table " .. M.NFT_TABLE,
		"delete table " .. M.NFT_TABLE,
		"table " .. M.NFT_TABLE .. " {",
	}
	for _, s in ipairs(M.SETS) do
		lines[#lines + 1] = string.format(
			"  set %s { type ether_addr; flags dynamic,timeout; timeout %ds; counter; }", s, t)
	end
	local rules = {
		-- Client -> server: the station asked for a lease.
		"udp sport 68 udp dport 67 add @dhcp_req { ether saddr }",
		-- Server -> client, unicast to the station's MAC: the usual ACK
		-- (dnsmasq and the UniFi gateway unicast unless the client sets the
		-- broadcast flag).
		"udp sport 67 udp dport 68 add @dhcp_ack { ether daddr }",
		-- The station's first frame from a real source address: the lease
		-- is in use. Covers the broadcast-ACK case above cannot see.
		"ip saddr != 0.0.0.0 add @ip_seen { ether saddr }",
		"udp dport 53 add @dns_q { ether saddr }",
		"tcp dport 53 add @dns_q { ether saddr }",
		"udp sport 53 add @dns_resp { ether daddr }",
		"tcp sport 53 add @dns_resp { ether daddr }",
	}
	lines[#lines + 1] = "  chain track {"
	lines[#lines + 1] = "    type filter hook forward priority filter + 10; policy accept;"
	for _, r in ipairs(rules) do lines[#lines + 1] = "    " .. r end
	lines[#lines + 1] = "  }"
	lines[#lines + 1] = "}"
	return table.concat(lines, "\n") .. "\n"
end

M.SCRIPT_PATH = "/tmp/openuf-assoc.nft"

-- Install the table if it is not there. Checked rather than rebuilt every
-- cycle: a rebuild empties the sets, which would erase the evidence of any
-- connection in flight.
function M.ensure_table()
	if exec_ok(M._exec("nft list table " .. M.NFT_TABLE .. " >/dev/null 2>&1")) then
		return true
	end
	local f = io.open(M.SCRIPT_PATH, "w")
	if not f then return false end
	f:write(M.nft_script())
	f:close()
	local ok = exec_ok(M._exec("nft -f " .. M.SCRIPT_PATH .. " 2>/dev/null"))
	os.remove(M.SCRIPT_PATH)
	if not ok then
		io.stderr:write("openuf: assoctrack: could not install nft table " .. M.NFT_TABLE
			.. " -- DHCP/DNS stages will not be reported\n")
	end
	return ok
end

function M.teardown()
	M._exec("nft delete table " .. M.NFT_TABLE .. " >/dev/null 2>&1")
	M._stas, M._queue = {}, {}
end

-- A new attempt starts from a clean slate: anything the sets hold for the
-- station predates it, and `add` would never overwrite that first-seen time.
-- This has to run when hostapd reports the 802.11 authentication, not when
-- openUF next drains the collector: a phone reconnected in 0.7 s on the
-- Archer C5, so a deletion ten seconds later would erase the very attempt it
-- was meant to prepare for. It is therefore a shell fragment run by the
-- collector itself (rrmscan.collector_ensure) on each "auth" line, with the
-- station's MAC in the named shell variable. The race it then has to win is
-- the handshake: 802.1X keeps the station's data frames off the bridge until
-- sta-authorized, ~120 ms after auth on the C5.
--
-- `destroy`, not `delete`: one transaction, and a missing element -- the
-- common case -- is not an error. Needs nft >= 1.0.8 on kernel >= 6.3;
-- OpenWrt 24.10 and 25.12 both qualify (25.12 C5: nft 1.1.6, 6.12.94).
function M.forget_shell(var)
	local parts = {}
	for _, s in ipairs(M.SETS) do
		parts[#parts + 1] = string.format("destroy element %s %s { $%s }", M.NFT_TABLE, s, var)
	end
	return 'nft "' .. table.concat(parts, "; ") .. '" >/dev/null 2>&1'
end

-- "1m58s694ms" -> 118.694. Units nft prints: d h m s ms.
function M.parse_duration(s)
	if type(s) ~= "string" or s == "" then return nil end
	-- Summed in integer milliseconds and divided once, so "694ms" is exactly
	-- the double 0.694 rather than 0.694 plus float noise.
	local total, matched = 0, false
	for n, unit in s:gmatch("(%d+)(%a+)") do
		local k = ({d = 86400000, h = 3600000, m = 60000, s = 1000, ms = 1})[unit]
		if not k then return nil end
		total, matched = total + tonumber(n) * k, true
	end
	return matched and total / 1000 or nil
end

-- Parse `nft list table` text into {set = {mac = {t = uptime, n = packets}}}.
-- `now` is /proc/uptime at the moment of listing. Text, not -j: the JSON
-- output rounds `expires` to whole seconds.
function M.parse_sets(text, now)
	local out = {}
	if type(text) ~= "string" then return out end
	for name, body in text:gmatch("set%s+([%w_]+)%s*(%b{})") do
		local els = body:match("elements%s*=%s*(%b{})")
		local set = {}
		if els then
			els = els:sub(2, -2) .. ","
			for item in els:gmatch("([^,]+),") do
				local mac = item:match("(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
				local exp = M.parse_duration(item:match("expires%s+(%S+)"))
				if mac and exp then
					set[mac:lower()] = {
						t = now - (M.SET_TIMEOUT - exp),
						n = tonumber(item:match("packets%s+(%d+)")) or 1,
					}
				end
			end
		end
		out[name] = set
	end
	return out
end

function M.read_sets(now)
	local text = M._popen("nft list table " .. M.NFT_TABLE .. " 2>/dev/null")
	return M.parse_sets(text, now)
end

-- Collector lines: "<uptime> { \"<event>\": {...} }". Only the four events
-- this module consumes are parsed; probes are the bulk of the file.
local WANTED = {auth = true, assoc = true, ["sta-authorized"] = true, disassoc = true}

function M.parse_events(blob)
	local out = {}
	if type(blob) ~= "string" then return out end
	for line in blob:gmatch("[^\n]+") do
		local t, ev, body = line:match('^(%d+%.?%d*)%s+{%s*"([%w%-]+)":%s*(%b{})')
		if t and WANTED[ev] then
			local mac = body:match('"address":"(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)"')
			if mac then
				out[#out + 1] = {
					t      = tonumber(t),
					ev     = ev,
					mac    = mac:lower(),
					ifname = body:match('"ifname":"([^"]+)"'),
					signal = tonumber(body:match('"signal":(%-?%d+)')),
					alg    = body:match('"auth%-alg":"([^"]+)"'),
				}
			end
		end
	end
	return out
end

M._stas  = {}
M._queue = {}

-- Fold hostapd events into per-station attempts.
function M.ingest(events)
	for _, e in ipairs(events or {}) do
		local s = M._stas[e.mac]
		if e.ev == "auth" then
			-- A fresh 802.11 authentication is a new attempt, whatever the
			-- previous one was doing. The collector has already cleared its
			-- set evidence (forget_shell); anything older than t_auth that
			-- survived is ignored by poll() anyway.
			M._stas[e.mac] = {ifname = e.ifname, t_auth = e.t, rssi = e.signal}
		elseif e.ev == "assoc" then
			if not s or s.t_authz then
				-- No auth seen (FT over the DS, or the collector restarted):
				-- the association starts the attempt.
				s = {ifname = e.ifname, t_auth = e.t}
				M._stas[e.mac] = s
			end
			s.t_assoc = e.t
			s.ifname  = e.ifname or s.ifname
			s.rssi    = e.signal or s.rssi
		elseif e.ev == "sta-authorized" then
			if not s or s.t_authz then
				s = {ifname = e.ifname, t_auth = e.t, t_assoc = e.t}
				M._stas[e.mac] = s
			end
			s.t_authz = e.t
			s.alg     = e.alg
			s.ifname  = e.ifname or s.ifname
		elseif e.ev == "disassoc" then
			if s then s.t_gone = s.t_gone or e.t end
		end
	end
end

local function ms(a, b)
	if not a or not b then return 0 end
	local d = math.floor((a - b) * 1000 + 0.5)
	return d > 0 and d or 0
end

-- The payload for one attempt. Deltas are cumulative from auth_ts: the
-- controller derives each stage's latency by subtracting its predecessor
-- (authentication = wpa_auth_delta - assoc_delta, dhcp = ip_delta -
-- wpa_auth_delta, total = traffic_delta), confirmed by the lab's funnel.
-- Every numeric key is always present: the metrics handler reads them with
-- getLong/getInt, which do not tolerate absence.
local function payload(mac, s, ctx, f)
	local auth_epoch = ctx.epoch - (ctx.now - s.t_auth)
	return {
		message_type      = "STA_ASSOC_TRACKER",
		event_type        = f.event_type,
		-- %.0f, not %d: OpenWrt's Lua (LNUM patch) formats %d through a
		-- 32-bit integer and raises on an epoch in milliseconds (~1.8e12).
		-- Stock 5.1 and 5.4 accept it, so only the APs showed it.
		event_id          = string.format("%s-%.0f", (mac:gsub(":", "")), math.floor(auth_epoch * 1000)),
		mac               = mac,
		vap               = f.vap,
		auth_ts           = math.floor(auth_epoch * 100 + 0.5) / 100,
		auth_rssi         = s.rssi,
		auth_algo         = s.alg,
		-- hostapd notifies auth on receipt and answers in the same pass:
		-- below this collector's 10 ms resolution.
		auth_delta        = 0,
		assoc_delta       = ms(s.t_assoc, s.t_auth),
		wpa_auth_delta    = ms(s.t_authz, s.t_auth),
		ip_assign_type    = f.ip_assign_type or "N/A",
		ip_delta          = f.ip_delta or 0,
		traffic_delta     = f.traffic_delta or 0,
		dns_resp_seen     = f.dns_resp_seen or "N/A",
		dns_responses     = f.dns_responses or 0,
		arp_reply_gw_seen = "N/A",
		assoc_failures    = 0,
		auth_failures     = 0,
		wpa_auth_failures = f.wpa_auth_failures or 0,
		ip_failures       = f.ip_failures or 0,
		dns_timeouts      = f.dns_timeouts or 0,
		traffic_failures  = 0,
	}
end

-- Decide every attempt that has enough evidence, or has run out of time.
-- ctx = {now = uptime, epoch = os.time(), sets = parse_sets(...),
--        vap_by_ifname = {phy1-ap0 = "<vap_table name>"}}.
-- Returns the payloads decided this pass (also appended to M._queue).
function M.poll(ctx)
	local out = {}
	local sets = ctx.sets or {}
	local function seen(name, mac, after)
		local e = sets[name] and sets[name][mac]
		if e and e.t >= after - 0.05 then return e end
		return nil
	end
	for mac, s in pairs(M._stas) do
		local vap = ctx.vap_by_ifname and ctx.vap_by_ifname[s.ifname]
		local f, done = nil, false
		if not s.t_authz then
			-- Associated but never authorized: the handshake failed (a wrong
			-- passphrase looks exactly like this) once the station leaves or
			-- the window closes. An auth with no assoc is not an attempt the
			-- controller counts; drop it.
			local expired = ctx.now - (s.t_assoc or s.t_auth) > M.AUTH_WINDOW
			if s.t_gone or expired then
				done = true
				if s.t_assoc then
					f = {event_type = "failure", wpa_auth_failures = 1}
				end
			end
		else
			local dreq  = seen("dhcp_req", mac, s.t_auth)
			local dack  = seen("dhcp_ack", mac, s.t_auth)
			local ip    = seen("ip_seen", mac, s.t_auth)
			local q     = seen("dns_q", mac, s.t_auth)
			local resp  = seen("dns_resp", mac, s.t_auth)
			local t_ip
			if dack then t_ip = dack.t
			elseif ip and (not dreq or ip.t >= dreq.t) then t_ip = ip.t end
			local assign = dreq and "dhcp" or (s.alg == "ft" and "roam" or nil)
			local closed = s.t_gone or (ctx.now - s.t_authz > M.WINDOW)
			if resp then
				done = true
				f = {
					event_type     = "success",
					ip_assign_type = assign or "static",
					ip_delta       = (dreq and t_ip) and ms(t_ip, s.t_auth) or 0,
					traffic_delta  = math.max(ms(resp.t, s.t_auth), 1),
					dns_resp_seen  = "yes",
					dns_responses  = resp.n,
				}
			elseif closed then
				done = true
				if dreq and not t_ip then
					f = {event_type = "failure", ip_assign_type = "dhcp", ip_failures = 1}
				elseif q then
					f = {
						event_type     = "failure",
						ip_assign_type = assign or "static",
						ip_delta       = (dreq and t_ip) and ms(t_ip, s.t_auth) or 0,
						dns_resp_seen  = "no",
						dns_timeouts   = 1,
					}
				elseif s.alg == "ft" then
					-- A fast roam keeps its lease and need not touch DNS. The
					-- controller's own rule counts "soft failure" + "roam" as a
					-- successful connection; that is the event for it.
					f = {event_type = "soft failure", ip_assign_type = "roam"}
				end
				-- Otherwise: no DHCP, no DNS -- nothing to judge. No event.
			end
		end
		if done then
			M._stas[mac] = nil
			-- No vap_table entry for this BSS means no band and no WLAN to
			-- attribute it to; the controller would file it under 2.4 GHz.
			if f and vap then
				f.vap = vap
				local p = payload(mac, s, ctx, f)
				out[#out + 1] = p
				M._queue[#M._queue + 1] = p
			end
		end
	end
	while #M._queue > M.MAX_QUEUE do table.remove(M._queue, 1) end
	return out
end

-- Up to n queued payloads, oldest first, removed from the queue.
function M.take(n)
	local out = {}
	while #out < n and #M._queue > 0 do
		out[#out + 1] = table.remove(M._queue, 1)
	end
	return out
end

-- Put back what could not be sent, ahead of anything newer.
function M.requeue(list)
	for i = #list, 1, -1 do table.insert(M._queue, 1, list[i]) end
	while #M._queue > M.MAX_QUEUE do table.remove(M._queue, 1) end
end

return M
