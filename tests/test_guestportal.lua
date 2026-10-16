-- Tests for openuf/guestportal.lua (the guest portal's ebtables rules in nft,
-- and the HTTP answer that sends a guest to the portal).
-- Run from project root: lua tests/run_tests.lua

OPENUF_TEST_MODE = true
local gp = dofile("openuf/guestportal.lua")

-- The guest ruleset as the 10.4.57 lab pushed it (2026-10-09, C0), in push
-- order, with the controller's address mapped to 192.0.2.2. ath0/ath1 are
-- the guest WLAN's two VAPs.
local CTL = "192.0.2.2"
local CAPTURE = table.concat({
	"redirector.status=enabled",
	"redirector.https.status=enabled",
	"redirector.url=http://" .. CTL .. ":8880/guest/s/default/",
	"redirector.url_https=http://" .. CTL .. ":8880/guest/s/default/",
	"redirector.redirect_pattern=http://" .. CTL .. ":8882",
	"ebtables.status=enabled",
	"ebtables.1.cmd=-t nat -A PREROUTING --in-interface ath0 -d BGA -j DROP",
	"ebtables.5.cmd=-t nat -N GUESTIN -P DROP",
	"ebtables.6.cmd=-t nat -N GUESTOUT -P ACCEPT",
	"ebtables.7.cmd=-t nat -A PREROUTING --in-interface ath0 -j GUESTIN",
	"ebtables.8.cmd=-t nat -A POSTROUTING --out-interface ath0 -j GUESTOUT",
	"ebtables.9.cmd=-t nat -A GUESTIN --in-interface ath0 --proto 0x888e -j ACCEPT",
	"ebtables.10.cmd=-t nat -A PREROUTING --in-interface ath1 -j GUESTIN",
	"ebtables.11.cmd=-t nat -A POSTROUTING --out-interface ath1 -j GUESTOUT",
	"ebtables.12.cmd=-t nat -A GUESTIN --in-interface ath1 --proto 0x888e -j ACCEPT",
	"ebtables.13.cmd=-t nat -A GUESTIN -p 0x800 --pkttype-type broadcast --ip-proto 17 --ip-sport 68 --ip-dport 67 -j ACCEPT",
	"ebtables.14.cmd=-t nat -A GUESTIN -p arp -j ACCEPT",
	"ebtables.15.cmd=-t nat -N GUEST_DNS -P DROP",
	"ebtables.16.cmd=-t nat -A GUESTIN -p 0x800 --ip-proto 17 --ip-dport 53 -j GUEST_DNS",
	"ebtables.17.cmd=-t nat -A GUESTIN -p 0x800 --ip-proto 6 --ip-dport 53 -j GUEST_DNS",
	"ebtables.18.cmd=-t nat -A GUESTIN -p 0x86dd -j DROP",
	"ebtables.19.cmd=-t nat -A GUESTIN --pkttype-type broadcast -j DROP",
	"ebtables.20.cmd=-t nat -A GUESTOUT -p 0x800 --pkttype-type broadcast --ip-proto 17 --ip-sport 67 --ip-dport 68 -j ACCEPT",
	"ebtables.21.cmd=-t nat -A GUESTOUT -p arp -j ACCEPT",
	"ebtables.22.cmd=-t nat -A GUESTOUT -p 0x86dd -j DROP",
	"ebtables.23.cmd=-t nat -A GUESTOUT --pkttype-type broadcast -j DROP",
	"ebtables.24.cmd=-t nat -A GUESTIN -p 0x800 --ip-proto 6 --ip-dport 8880 --ip-dst " .. CTL .. " -j ACCEPT",
	"ebtables.25.cmd=-t nat -A GUESTIN -p 0x800 --ip-proto 6 --ip-dport 8843 --ip-dst " .. CTL .. " -j ACCEPT",
	"ebtables.26.cmd=-t nat -N CAPTIVE_PORTAL -P RETURN",
	"ebtables.27.cmd=-t nat -A GUESTIN -p 0x800 --ip-proto 6 --ip-dport 443 -j CAPTIVE_PORTAL",
	"ebtables.28.cmd=-t nat -A GUESTIN -p 0x800 --ip-dst 224.0.0.0/4 -j DROP",
	"ebtables.29.cmd=-t nat -A GUESTOUT -p 0x800 --ip-dst 224.0.0.0/4 -j DROP",
	"ebtables.30.cmd=-t nat -A GUESTIN -p 0x800 --ip-dst 192.168.0.0/16 -j DROP",
	"ebtables.31.cmd=-t nat -A GUESTIN -p 0x800 --ip-dst 10.0.0.0/8 -j DROP",
	"ebtables.32.cmd=-t nat -A GUESTIN -p 0x800 --ip-dst 172.16.0.0/12 -j DROP",
	"ebtables.33.cmd=-t nat -N REDIRECT_HTTP",
	"ebtables.34.cmd=-t nat -A REDIRECT_HTTP -j mark --mark-or 0x40000000 --mark-target CONTINUE",
	"ebtables.35.cmd=-t nat -A REDIRECT_HTTP -j redirect",
	"ebtables.36.cmd=-t nat -N REDIRECT_HTTPS",
	"ebtables.37.cmd=-t nat -A REDIRECT_HTTPS -j mark --mark-or 0x80000000 --mark-target CONTINUE",
	"ebtables.38.cmd=-t nat -A REDIRECT_HTTPS -j redirect",
	"ebtables.39.cmd=-t nat -N AUTHORIZED_GUESTS -P RETURN",
	"ebtables.40.cmd=-t nat -A GUESTIN -p 0x800 --pkttype-type otherhost -j AUTHORIZED_GUESTS",
	"ebtables.41.cmd=-t nat -A GUESTIN -p 0x800 --ip-proto 6 --ip-dport 80 -j REDIRECT_HTTP",
	"ebtables.42.cmd=-t nat -A GUESTIN -p 0x800 --ip-proto 6 --ip-dport 443 -j REDIRECT_HTTPS",
	"ebtables.43.cmd=-t nat -N REDIRECT_DNS",
	"ebtables.44.cmd=-t nat -A REDIRECT_DNS -j mark --mark-or 0x40000000 --mark-target CONTINUE",
	"ebtables.45.cmd=-t nat -A REDIRECT_DNS -j redirect",
	"ebtables.46.cmd=-t nat -A GUEST_DNS -p 0x800 --ip-proto 17 --ip-dport 53 -j AUTHORIZED_GUESTS",
	"ebtables.47.cmd=-t nat -A GUEST_DNS -p 0x800 --ip-proto 6 --ip-dport 53 -j AUTHORIZED_GUESTS",
	"ebtables.48.cmd=-t nat -A GUEST_DNS -p 0x800 --ip-proto 17 --ip-dport 53 -j REDIRECT_DNS",
	"ebtables.49.cmd=-t nat -A GUEST_DNS -p 0x800 --ip-proto 6 --ip-dport 53 -j REDIRECT_DNS",
	"ebtables.50.cmd=-t nat -I GUESTIN -p 0x800 --ip-dst " .. CTL .. " --ip-proto 6 --ip-dport 8882 -j REDIRECT_HTTP",
	"ebtables.51.cmd=-t nat -I GUESTIN -p 0x800 --ip-dst " .. CTL .. " --ip-proto 6 --ip-dport 8881 -j ACCEPT",
	"ebtables.52.cmd=-t broute -A BROUTING -i ath0 -p 802_1Q -j DROP",
}, "\n") .. "\n"

-- The nft statements that took effect (see fake_nft), and the fake itself.
local function with_capture(fn, fail_pattern)
	local orig = gp._exec
	local exec, r = fake_nft(fail_pattern and function(l) return l:find(fail_pattern, 1, true) end)
	gp._exec = exec
	local ok, err = pcall(fn, r.cmds)
	gp._exec = orig
	if not ok then error(err, 0) end
	return r.cmds, r
end

local function with_stderr(fn)
	local buf, real = {}, io.stderr
	io.stderr = {write = function(_, s) buf[#buf + 1] = s end}
	local ok, err = pcall(fn)
	io.stderr = real
	if not ok then error(err, 0) end
	return table.concat(buf)
end

-- Index of the first command containing s, or nil.
local function find(cmds, s)
	for i, c in ipairs(cmds) do
		if c:find(s, 1, true) then return i end
	end
	return nil
end

local VAPS = {
	{ifname = "phy0-ap1", bridge_mac = "02:00:00:00:00:aa"},
	{ifname = "phy1-ap1", bridge_mac = "02:00:00:00:00:aa"},
}

-- A connected client for serve_one: lines to read, everything sent.
local function fake_client(lines, peer)
	local c = {sent = {}, closed = false}
	local i = 0
	function c:settimeout() end
	function c:getpeername() return peer end
	function c:receive()
		i = i + 1
		return lines[i]
	end
	function c:send(s) self.sent[#self.sent + 1] = s; return #s end
	function c:close() self.closed = true end
	return c
end

local ARP = table.concat({
	"IP address       HW type     Flags       HW address            Mask     Device",
	"198.51.100.50    0x1         0x2         DE:AD:BE:EF:00:03     *        br-lan",
	"198.51.100.51    0x1         0x0         00:00:00:00:00:00     *        br-lan",
	"198.51.100.52    0x1         0x6         00:00:5e:00:53:01     *        br-lan",
}, "\n") .. "\n"

return {
	{
		name = "guestportal: the lab capture parses to the portal's facts, every shape known",
		fn = function()
			local s = gp.parse(CAPTURE)
			assert_true(s.enabled, "portal on")
			assert_eq(s.url, "http://" .. CTL .. ":8880/guest/s/default/", "redirector.url")
			assert_eq(#s.unknown, 0, "no guest rule left unrecognised")
			assert_eq(table.concat(s.devs, ","), "ath0,ath1", "the GUESTIN hooks")
			local acc = {}
			for _, a in ipairs(s.accept) do acc[#acc + 1] = a.ip .. ":" .. a.port end
			assert_eq(table.concat(acc, ","), CTL .. ":8880," .. CTL .. ":8843," .. CTL .. ":8881",
				"the portal ports a guest may always reach")
			assert_eq(#s.intercept, 1, "one -I ... -j REDIRECT_HTTP")
			assert_eq(s.intercept[1].port, 8882, "the redirect_pattern port")
			assert_eq(table.concat(s.restrict, ","), "224.0.0.0/4,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12",
				"inbound drops in push order")
			assert_eq(table.concat(s.restrict_out, ","), "224.0.0.0/4", "outbound multicast drop")
		end
	},
	{
		name = "guestportal: off, partial or unusable pushes",
		fn = function()
			local off = gp.parse(CAPTURE:gsub("redirector%.status=enabled", "redirector.status=disabled"))
			assert_false(off.enabled, "redirector.status=disabled is off")
			assert_eq(gp.parse("radio.1.channel=6\n"), nil, "no redirector.status: a partial push says nothing")
			local hdr = gp.parse(CAPTURE:gsub("redirector%.url=[^\n]*",
				'redirector.url=http://' .. CTL .. '/a"b'))
			assert_eq(hdr.url, nil, "a URL that cannot go into a Location header is refused")
			assert_false(hdr.enabled, "and without a URL the portal is not enforced")
			local nohook = gp.parse("redirector.status=enabled\nredirector.url=http://" .. CTL .. "/\n")
			assert_false(nohook.enabled, "no GUESTIN hook: nothing to enforce on")
			local odd = gp.parse(CAPTURE .. "ebtables.60.cmd=-t nat -A GUESTIN -p 0x800 --ip-dst 300.1.1.1/8 -j DROP\n"
				.. "ebtables.61.cmd=-t nat -A GUESTIN -p 0x800 --ip-proto 6 --ip-dport 99999 --ip-dst " .. CTL .. " -j ACCEPT\n"
				.. "ebtables.62.cmd=-t nat -A GUESTIN -j CAPTIVE_PORTAL --something new\n")
			assert_eq(#odd.unknown, 3, "a bad address, a bad port and a new shape are reported, not spliced")
			assert_eq(#odd.restrict, 4, "the bad subnet was not taken")
		end
	},
	{
		name = "guestportal: is_guest_rule tells the portal's rules from l2guard's",
		fn = function()
			assert_true(gp.is_guest_rule("-t nat -A PREROUTING --in-interface ath0 -j GUESTIN"), "hook")
			assert_true(gp.is_guest_rule("-t nat -N AUTHORIZED_GUESTS -P RETURN"), "chain declaration")
			assert_false(gp.is_guest_rule("-t nat -A PREROUTING --in-interface ath0 -d BGA -j DROP"), "BPDU drop")
			assert_false(gp.is_guest_rule("-t broute -A BROUTING -i ath0 -p 802_1Q -j DROP"), "tag drop")
			assert_false(gp.is_guest_rule("-t nat -A X -j GUESTINX"), "a longer name is not a guest chain")
		end
	},
	{
		name = "guestportal: reconcile builds the chains in the controller's order",
		fn = function()
			local spec = gp.parse(CAPTURE)
			local cmds, r = with_capture(function()
				assert_eq(gp.reconcile(spec, VAPS, {"de:ad:be:ef:00:02"}, true), 31,
					"every rule counted (30 in the lab with one bridged VAP)")
			end)
			assert_eq(r.runs, 1, "both tables in one nft run")
			assert_nil(find(cmds, "rate_"), "rate limits are the shaper's (per-client tc classes)")
			assert_eq(cmds[2], "nft delete table bridge openuf_guest", "starts from scratch")
			assert_eq(cmds[4], "nft delete table ip openuf_guest", "both tables")
			assert_not_nil(find(cmds, [[iifname { "phy0-ap1", "phy1-ap1" } jump guestin]]), "ingress hook on both VAPs")
			assert_not_nil(find(cmds, [[oifname { "phy0-ap1", "phy1-ap1" } jump guestout]]), "egress hook")
			local intercept = find(cmds, "ip daddr " .. CTL .. " tcp dport 8882 jump redirect_http")
			local portal = find(cmds, "ip daddr " .. CTL .. " tcp dport 8880 accept")
			local dns = find(cmds, "ether type ip udp dport 53 accept")
			local v6 = find(cmds, "ether type ip6 drop")
			local rfc1918 = find(cmds, "guestin ip daddr 10.0.0.0/8 drop")
			local authorized = find(cmds, "ether saddr @authorized meta pkttype other accept")
			local http = find(cmds, "guestin tcp dport 80 jump redirect_http")
			local last = find(cmds, "guestin drop")
			assert_true(intercept < portal and portal < rfc1918, "the portal is reachable before any drop")
			assert_true(dns < rfc1918, "DNS to a private resolver passes")
			assert_true(v6 < authorized, "IPv6 is dropped even for an authorized guest")
			assert_true(rfc1918 < authorized, "restricted subnets hold for an authorized guest")
			assert_true(authorized < http and http < last, "authorized passes; the rest of :80 is answered locally")
			local selfrun = find(cmds, "guestin jump selfrun")
			assert_true(authorized < selfrun and selfrun < http, "selfrun after the authorized accept, before :80")
			assert_not_nil(find(cmds, "selfrun meta pkttype other accept"), "selfrun applied")
			assert_not_nil(find(cmds, [[iifname "phy0-ap1" ether daddr set 02:00:00:00:00:aa meta pkttype set host accept]]),
				"marked frames go up to the bridge")
			assert_not_nil(find(cmds, "guestout ip daddr 224.0.0.0/4 drop"), "outbound multicast")
			assert_not_nil(find(cmds, "add element bridge openuf_guest authorized { de:ad:be:ef:00:02 }"), "the ledger")
			assert_not_nil(find(cmds, "meta mark and 0xc0000000 == 0x40000000 meta l4proto tcp redirect to :8820"),
				"NAT to the answer's port")
			assert_eq(find(cmds, "443"), nil, "no HTTPS answer: 443 falls to the drop")
		end
	},
	{
		name = "guestportal: reconcile with nothing to do leaves no tables",
		fn = function()
			local spec = gp.parse(CAPTURE)
			local off = with_capture(function() assert_eq(gp.reconcile(nil, VAPS), 0, "off") end)
			assert_eq(#off, 4, "off: the two deletes only (each after an add, so neither can fail)")
			local none
			local err = with_stderr(function()
				none = with_capture(function() assert_eq(gp.reconcile(spec, {}), 0, "no VAPs") end)
			end)
			assert_eq(#none, 4, "no guest interface: the two deletes only")
			assert_true(err:find("deferred", 1, true) ~= nil, "says why")
			local odd = with_capture(function()
				with_stderr(function() gp.reconcile(spec, {{ifname = "x; reboot"}, {ifname = "phy0-ap1"}}) end)
			end)
			assert_eq(find(odd, "reboot"), nil, "an odd interface name never reaches a command line")
		end
	},
	{
		name = "guestportal: an unbridged VAP is still blocked, and a rejected rule is said",
		fn = function()
			local spec = gp.parse(CAPTURE)
			local cmds, err
			err = with_stderr(function()
				cmds = with_capture(function() gp.reconcile(spec, {{ifname = "phy0-ap1"}}) end, "pkttype other")
			end)
			assert_not_nil(find(cmds, "guestin drop"), "the drop is there")
			assert_eq(find(cmds, "ether daddr set"), nil, "no bridge MAC to hand frames to")
			assert_true(err:find("not bridged", 1, true) ~= nil, "unbridged reported")
			assert_true(err:find("NOT fully enforced", 1, true) ~= nil, "a rejected rule reported")
			assert_true(err:find('nft rejected "ether saddr @authorized meta pkttype other accept"', 1, true) ~= nil,
				"and named")
		end
	},
	{
		name = "guestportal: a rejected NAT redirect is said, and the filter still stands",
		fn = function()
			local spec = gp.parse(CAPTURE)
			local n, cmds
			local err = with_stderr(function()
				cmds = with_capture(function() n = gp.reconcile(spec, VAPS, {}, false) end, "redirect to")
			end)
			assert_eq(n, 30, "every rule but the redirect")
			assert_not_nil(find(cmds, "guestin drop"), "guests are still blocked")
			assert_true(err:find("NAT redirect", 1, true) ~= nil, "the missing portal answer is reported")
		end
	},
	{
		name = "guestportal: set_authorized refills the set in one transaction, malformed MACs skipped",
		fn = function()
			local macs = {"x; reboot"}
			for i = 1, 65 do macs[#macs + 1] = ("02:00:00:00:00:%02X"):format(i) end
			local cmds, r = with_capture(function() gp.set_authorized(macs) end)
			assert_eq(r.runs, 1, "flush and refill together: no moment with the set empty")
			assert_eq(cmds[1], "nft flush set bridge openuf_guest authorized", "flush first")
			assert_eq(#cmds, 2, "65 MACs: one add element statement")
			assert_true(cmds[2]:find("02:00:00:00:00:0a", 1, true) ~= nil, "lowercased")
			assert_eq(find(cmds, "reboot"), nil, "malformed never spliced")
			local none = with_capture(function()
				assert_false(gp.set_authorized({"02:00:00:00:00:01"}), "no table: nothing to fill")
			end, "flush set")
			assert_eq(#none, 0, "a failed flush applies nothing")
		end
	},
	{
		name = "guestportal: set_selfrun opens the portal to other hosts, and closes it",
		fn = function()
			local open = with_capture(function() assert_true(gp.set_selfrun(true), "applied") end)
			assert_eq(open[1], "nft flush chain bridge openuf_guest selfrun", "flush first")
			assert_eq(#open, 2, "one rule")
			assert_true(open[2]:find("selfrun meta pkttype other accept", 1, true) ~= nil,
				"other hosts only: the AP itself stays behind the portal's rules")
			local closed = with_capture(function() assert_true(gp.set_selfrun(false), "closed") end)
			assert_eq(#closed, 1, "closed: the flush only")
			local none = with_capture(function()
				assert_false(gp.set_selfrun(true), "no table")
			end, "flush chain")
			assert_eq(#none, 0, "a failed flush applies nothing")
		end
	},
	{
		name = "guestportal: bridge_mac reads the master's address",
		fn = function()
			local orig = gp._read
			local asked
			gp._read = function(p) asked = p; return "02:00:00:00:00:AA\n" end
			local mac = gp.bridge_mac("phy0-ap1")
			local odd = gp.bridge_mac("../../x")
			gp._read = function() return nil end
			local unbridged = gp.bridge_mac("phy0-ap1")
			gp._read = orig
			assert_eq(asked, "/sys/class/net/phy0-ap1/master/address", "through the master link")
			assert_eq(mac, "02:00:00:00:00:aa", "lowercased")
			assert_eq(odd, nil, "odd name refused")
			assert_eq(unbridged, nil, "not enslaved")
		end
	},
	{
		name = "guestportal: arp_mac takes complete entries only",
		fn = function()
			assert_eq(gp.arp_mac("198.51.100.50", ARP), "de:ad:be:ef:00:03", "complete, lowercased")
			assert_eq(gp.arp_mac("198.51.100.51", ARP), nil, "incomplete")
			assert_eq(gp.arp_mac("198.51.100.52", ARP), "00:00:5e:00:53:01", "complete + permanent flags")
			assert_eq(gp.arp_mac("198.51.100.5", ARP), nil, "a prefix of another address is not a match")
		end
	},
	{
		name = "guestportal: location carries id, ap, t, url and ssid, encoded",
		fn = function()
			local ctx = {url = "http://" .. CTL .. ":8880/guest/s/default/", ap = "00:00:5e:00:53:02"}
			local loc = gp.location(ctx, "de:ad:be:ef:00:03", "http://example.com/a?b=1&c", "Lab Guest", 1791583472)
			assert_eq(loc, "http://" .. CTL .. ":8880/guest/s/default/?id=de%3Aad%3Abe%3Aef%3A00%3A03"
				.. "&ap=00%3A00%3A5e%3A00%3A53%3A02&t=1791583472"
				.. "&url=http%3A%2F%2Fexample.com%2Fa%3Fb%3D1%26c&ssid=Lab%20Guest", "the controller's parameters")
			ctx.url = "http://" .. CTL .. "/p?x=1"
			assert_true(gp.location(ctx, "de:ad:be:ef:00:03", nil, nil, 1):find("/p?x=1&id=", 1, true) ~= nil,
				"appends to a URL that has a query")
		end
	},
	{
		name = "guestportal: serve_one answers a guest with the portal, a stranger with 503",
		fn = function()
			local ctx = {url = "http://" .. CTL .. ":8880/guest/s/default/", ap = "00:00:5e:00:53:02",
				arp = function() return ARP end, now = function() return 100 end,
				ssid_for = function() return "Lab Guest" end}
			local guest = fake_client({"GET /generate_204 HTTP/1.1", "Host: connectivitycheck.example", "", }, "198.51.100.50")
			local server = {accept = function() return guest end}
			assert_true(gp.serve_one(server, ctx), "answered")
			local resp = table.concat(guest.sent)
			assert_true(resp:find("^HTTP/1.1 302 Found\r\n") ~= nil, "a redirect")
			assert_true(resp:find("id=de%3Aad%3Abe%3Aef%3A00%3A03", 1, true) ~= nil, "the guest's MAC")
			assert_true(resp:find("url=http%3A%2F%2Fconnectivitycheck.example%2Fgenerate_204", 1, true) ~= nil,
				"where it was going")
			assert_true(resp:find("&t=100&", 1, true) ~= nil, "the AP's clock")
			assert_true(guest.closed, "closed")
			local stranger = fake_client({"GET / HTTP/1.1", ""}, "198.51.100.99")
			assert_true(gp.serve_one({accept = function() return stranger end}, ctx), "answered")
			assert_true(table.concat(stranger.sent):find("^HTTP/1.1 503") ~= nil, "no MAC: try again")
			assert_false(gp.serve_one({accept = function() return nil end}, ctx), "nothing waiting")
		end
	},
	{
		name = "guestportal: serve_one reads a bounded request",
		fn = function()
			local lines = {"GET / HTTP/1.1"}
			for i = 1, 100 do lines[#lines + 1] = "X-Pad-" .. i .. ": y" end
			local c = fake_client(lines, "198.51.100.50")
			local read = 0
			local recv = c.receive
			c.receive = function(self) read = read + 1; return recv(self) end
			gp.serve_one({accept = function() return c end}, {url = "http://" .. CTL .. "/", ap = "",
				arp = function() return ARP end, now = function() return 1 end})
			assert_eq(read, 32, "stops after 32 lines")
			assert_true(table.concat(c.sent):find("302", 1, true) ~= nil, "still answers")
			assert_eq(table.concat(c.sent):find("url=", 1, true), nil, "no Host: no url=")
		end
	},
}
