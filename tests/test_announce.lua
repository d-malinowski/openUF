-- Tests for openuf/announce.lua (packet building and length-field fix).
-- Run from project root: lua tests/run_tests.lua

OPENUF_TEST_MODE = true				-- suppress main loop
dofile("openuf/lib/lib.lua")		-- sets global ufpkt
local announce = dofile("openuf/announce.lua")

-- Minimal config for packet building (fixed values for deterministic tests)
local function sample_cfg(overrides)
	local cfg = {
		mac           = {0x24, 0xa4, 0x3c, 0x00, 0xd3, 0xad},
		ip            = {192, 168, 1, 1},
		hostname      = "openUF",
		platform      = "U6IW",
		fw_pre        = "U6IW.",
		fw_ver        = "6.6.55",
		fw_buildtime  = "230801.1200",
		fw_factoryver = "6.5.28",
		version_suffix = "-openUF-0.1",
		uptime        = 100,
		counter       = 1,
	}
	if overrides then
		for k, v in pairs(overrides) do cfg[k] = v end
	end
	return cfg
end

-- Parse a TLV from a binary string at the given byte offset (1-based).
-- Returns type (number), value (binary string), next_offset.
local function parse_tlv(pkt, offset)
	local tlv_type = string.byte(pkt, offset)
	local len_hi   = string.byte(pkt, offset + 1)
	local len_lo   = string.byte(pkt, offset + 2)
	local len      = len_hi * 256 + len_lo
	local value    = pkt:sub(offset + 3, offset + 3 + len - 1)
	return tlv_type, value, offset + 3 + len
end

-- Find a TLV of a given type in the packet body (starting at offset 5)
local function find_tlv(pkt, want_type)
	local offset = 5  -- skip 4-byte outer header
	while offset <= #pkt do
		local tlv_type, value, next = parse_tlv(pkt, offset)
		if tlv_type == want_type then return value end
		if next <= offset then break end  -- guard against infinite loop
		offset = next
	end
	return nil
end

-- /proc/net/dev of a swconfig board whose LAN trunk is eth0 (header as the
-- kernel prints it; eth0.1 in br-lan, eth0.10 in a VLAN bridge).
local PROC_NET_DEV = table.concat({
	"Inter-|   Receive                                                |  Transmit",
	" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed",
	"    lo:  424520    2474    0    0    0     0          0         0   424520    2474    0    0    0     0       0          0",
	"  eth0:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0",
	"eth0.1:    1200      10    0    0    0     0          0         0     1300      11    0    0    0     0       0          0",
	"br-lan:    1200      10    0    0    0     0          0         0     1300      11    0    0    0     0       0          0",
	"eth0.10:      0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0",
	"  eth00:      0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0",
	"",
}, "\n")

return {
	{
		name = "announce: packet starts with 0x02 0x06 header",
		fn = function()
			local pkt = announce.build_packet(sample_cfg())
			assert_eq(string.byte(pkt, 1), 0x02, "byte 1 = 0x02")
			assert_eq(string.byte(pkt, 2), 0x06, "byte 2 = 0x06")
		end
	},
	{
		name = "announce: length field (bytes 3-4) encodes full 16-bit big-endian length",
		fn = function()
			local pkt = announce.build_packet(sample_cfg())
			local len_hi = string.byte(pkt, 3)
			local len_lo = string.byte(pkt, 4)
			local encoded_len = len_hi * 256 + len_lo
			-- Payload length is total minus the 4-byte header
			assert_eq(encoded_len, #pkt - 4, "encoded length matches actual payload")
		end
	},
	{
		name = "announce: length field high byte is actually used for a >= 256-byte payload",
		fn = function()
			-- The one test that genuinely guards the historical 2-byte-length
			-- regression. The default sample packet is ~154 bytes, so its high
			-- byte is legitimately 0 and the identity `hi*256+lo == #pkt-4`
			-- held even under the original low-byte-only bug -- the previous
			-- version of this test could never catch it. Force the payload
			-- past 256 with a long hostname and pin a NON-ZERO high byte.
			local pkt = announce.build_packet(sample_cfg({
				hostname = string.rep("a", 210),
			}))
			local payload_len = #pkt - 4
			assert_true(payload_len >= 256,
				"fixture sanity: payload crosses the 8-bit boundary (got " .. payload_len .. ")")
			local len_hi = string.byte(pkt, 3)
			local len_lo = string.byte(pkt, 4)
			assert_true(len_hi ~= 0, "high byte non-zero (the original bug zeroed it)")
			assert_eq(len_hi * 256 + len_lo, payload_len,
				"full 16-bit length correctly encoded")
		end
	},
	{
		name = "announce: TLV 0x02 (IP_ADDR) contains MAC then IP bytes",
		fn = function()
			local cfg = sample_cfg()
			local pkt = announce.build_packet(cfg)
			local val = find_tlv(pkt, 0x02)
			assert_not_nil(val, "TLV 0x02 present")
			assert_eq(#val, 10, "TLV 0x02 value = 6 MAC + 4 IP bytes")
			for i = 1, 6 do
				assert_eq(string.byte(val, i), cfg.mac[i], "MAC byte " .. i)
			end
			for i = 1, 4 do
				assert_eq(string.byte(val, 6 + i), cfg.ip[i], "IP byte " .. i)
			end
		end
	},
	{
		name = "announce: TLV 0x01 (HW_ADDR) contains the MAC",
		fn = function()
			local cfg = sample_cfg()
			local pkt = announce.build_packet(cfg)
			local val = find_tlv(pkt, 0x01)
			assert_not_nil(val, "TLV 0x01 present")
			assert_eq(#val, 6, "6-byte MAC")
			for i = 1, 6 do
				assert_eq(string.byte(val, i), cfg.mac[i], "MAC byte " .. i)
			end
		end
	},
	{
		name = "announce: TLV 0x0c (PLATFORM) contains the platform string",
		fn = function()
			local cfg = sample_cfg()
			local pkt = announce.build_packet(cfg)
			local val = find_tlv(pkt, 0x0c)
			assert_not_nil(val, "TLV 0x0c present")
			assert_eq(val, "U6IW", "platform string")
		end
	},
	{
		name = "announce: TLV 0x0b (HOSTNAME) contains the hostname",
		fn = function()
			local pkt = announce.build_packet(sample_cfg())
			local val = find_tlv(pkt, 0x0b)
			assert_not_nil(val, "TLV 0x0b present")
			assert_eq(val, "openUF", "hostname")
		end
	},
	{
		name = "announce: TLV 0x0a (UPTIME) is 4-byte big-endian",
		fn = function()
			local cfg = sample_cfg({uptime = 0x00012345})
			local pkt = announce.build_packet(cfg)
			local val = find_tlv(pkt, 0x0a)
			assert_not_nil(val, "TLV 0x0a present")
			assert_eq(#val, 4, "uptime is 4 bytes")
			assert_eq(string.byte(val, 1), 0x00, "uptime byte 1")
			assert_eq(string.byte(val, 2), 0x01, "uptime byte 2")
			assert_eq(string.byte(val, 3), 0x23, "uptime byte 3")
			assert_eq(string.byte(val, 4), 0x45, "uptime byte 4")
		end
	},
	{
		name = "announce: TLV 0x12 (counter) reflects the counter value",
		fn = function()
			local cfg = sample_cfg({counter = 7})
			local pkt = announce.build_packet(cfg)
			local val = find_tlv(pkt, 0x12)
			assert_not_nil(val, "TLV 0x12 present")
			assert_eq(#val, 4, "counter is 4 bytes")
			assert_eq(string.byte(val, 4), 7, "counter low byte = 7")
		end
	},
	{
		name = "announce: TLV 0x03 (FWVER_VERBOSE) contains platform prefix and version",
		fn = function()
			local pkt = announce.build_packet(sample_cfg())
			local val = find_tlv(pkt, 0x03)
			assert_not_nil(val, "TLV 0x03 present")
			assert_contains(val, "U6IW.", "fw prefix in verbose ver")
			assert_contains(val, "6.6.55", "fw version in verbose ver")
		end
	},
	{
		name = "announce: TLV 0x1b (FWVER_FACTORY) contains factory version string",
		fn = function()
			local pkt = announce.build_packet(sample_cfg())
			local val = find_tlv(pkt, 0x1b)
			assert_not_nil(val, "TLV 0x1b present")
			assert_eq(val, "6.5.28", "factory version string")
		end
	},
	{
		name = "announce: TLV 0x17 (IsDefault) is 1 when not adopted",
		fn = function()
			local pkt = announce.build_packet(sample_cfg({adopted = false}))
			local val = find_tlv(pkt, 0x17)
			assert_not_nil(val, "TLV 0x17 present")
			assert_eq(string.byte(val, 1), 0x01, "IsDefault=1 when not adopted")
		end
	},
	{
		name = "announce: TLV 0x17 (IsDefault) is 0 when adopted",
		fn = function()
			local pkt = announce.build_packet(sample_cfg({adopted = true}))
			local val = find_tlv(pkt, 0x17)
			assert_not_nil(val, "TLV 0x17 present")
			assert_eq(string.byte(val, 1), 0x00, "IsDefault=0 when adopted")
		end
	},
	{
		name = "announce: get_hostname returns the trimmed first line of `hostname`",
		fn = function()
			-- Both sources must be stubbed. get_hostname reads
			-- /proc/sys/kernel/hostname first (OpenWrt has no `hostname`
			-- applet), and on any Linux host -- notably CI -- that file
			-- really exists, so stubbing only _popen tests nothing and the
			-- assertion fails against the runner's own hostname.
			local orig_popen, orig_read = announce._popen, announce._read_file
			announce._read_file = function() return nil end
			announce._popen = function() return "myap\n" end
			local got = announce.get_hostname()

			-- /proc wins when present, and is trimmed the same way.
			announce._read_file = function() return "procap\n" end
			local from_proc = announce.get_hostname()

			announce._popen, announce._read_file = orig_popen, orig_read
			assert_eq(got, "myap", "falls back to `hostname` when /proc has none")
			assert_eq(from_proc, "procap", "/proc/sys/kernel/hostname preferred")
		end
	},
	{
		name = "announce: get_hostname returns nil for empty or failed output",
		fn = function()
			-- Same reason as above: /proc must be stubbed away too, or a
			-- Linux host answers before the empty _popen is ever reached.
			local orig_popen, orig_read = announce._popen, announce._read_file
			announce._read_file = function() return nil end
			announce._popen = function() return "" end
			local empty = announce.get_hostname()
			announce._popen = function() return "   \n" end
			local blank = announce.get_hostname()
			announce._read_file = function() return "  \n" end
			announce._popen = function() return "" end
			local blank_proc = announce.get_hostname()
			announce._popen, announce._read_file = orig_popen, orig_read
			assert_nil(blank_proc, "whitespace-only /proc -> nil, not a blank hostname")
			assert_nil(empty, "empty output -> nil (caller falls back to openUF)")
			assert_nil(blank, "whitespace-only output -> nil")
		end
	},
	{
		name = "announce: get_hostname reads /proc, not just the `hostname` command",
		fn = function()
			-- OpenWrt builds do not necessarily ship a `hostname` applet --
			-- confirmed absent on a real Archer C5 running 25.12.5 -- and the
			-- command-only version then reported every such device to the
			-- controller as "openUF" rather than its real hostname.
			local orig_read, orig_popen = announce._read_file, announce._popen
			local popen_called = false
			announce._read_file = function(path)
				if path == "/proc/sys/kernel/hostname" then return "livingroom-ap\n" end
				return nil
			end
			announce._popen = function() popen_called = true; return "" end
			local got = announce.get_hostname()
			announce._read_file, announce._popen = orig_read, orig_popen
			assert_eq(got, "livingroom-ap", "hostname read from /proc and trimmed")
			assert_false(popen_called, "no process spawned when /proc answers")
		end
	},
	{
		name = "announce: get_hostname falls back to the command, then to nil",
		fn = function()
			local orig_read, orig_popen = announce._read_file, announce._popen
			announce._read_file = function() return nil end
			announce._popen = function() return "fallback-name\n" end
			local via_cmd = announce.get_hostname()
			announce._popen = function() return "" end
			local none = announce.get_hostname()
			announce._read_file, announce._popen = orig_read, orig_popen
			assert_eq(via_cmd, "fallback-name", "command used when /proc is unreadable")
			assert_nil(none, "neither source -> nil, caller falls back to openUF")
		end
	},
	{
		name = "announce: get_ip reads the address off the interface itself",
		fn = function()
			announce._holder = nil
			local orig, seen = announce._popen, {}
			announce._popen = function(cmd)
				seen[#seen + 1] = cmd
				if cmd:match("addr show dev eth1") then
					return "    inet 192.0.2.3/24 brd 192.0.2.255 scope global eth1\n"
				end
				return ""
			end
			local ip = announce.get_ip("eth1")
			announce._popen = orig
			assert_not_nil(ip, "address found")
			assert_eq(table.concat(ip, "."), "192.0.2.3", "octets parsed")
			assert_eq(#seen, 1, "no bridge lookup when the port has its own address")
		end
	},
	{
		name = "announce: get_ip falls back to the bridge when the port has no address",
		fn = function()
			announce._holder = nil
			-- The real target layout: lan_cpueth names eth1, but eth1 is a
			-- br-lan member and carries no address -- without the fallback,
			-- announce broadcasts 192.168.1.1 and inform reports "0.0.0.0".
			local orig, orig_read = announce._popen, announce._read_file
			announce._popen = function(cmd)
				if cmd:match("addr show dev eth1") then return "" end
				if cmd:match("addr show dev br%-lan") then
					return "    inet 192.0.2.3/24 brd 192.0.2.255 scope global br-lan\n"
				end
				return ""
			end
			announce._read_file = function(path)
				if path == "/sys/class/net/eth1/master/uevent" then
					return "DEVTYPE=bridge\nINTERFACE=br-lan\nIFINDEX=5\n"
				end
				return nil
			end
			local ip = announce.get_ip("eth1")
			announce._popen, announce._read_file = orig, orig_read
			assert_not_nil(ip, "bridge address found via the port's master")
			assert_eq(table.concat(ip, "."), "192.0.2.3", "bridge octets parsed")
		end
	},
	{
		name = "announce: get_ip follows a VLAN trunk through its tagged child to the bridge",
		fn = function()
			-- The normal swconfig layout: eth0 (trunk) -> eth0.1 (tagged) ->
			-- br-lan (address). lan_cpueth has to name the TRUNK so a pushed
			-- VLAN 20 becomes eth0.20 and not eth0.1.20 -- so the trunk itself
			-- is neither addressed nor bridged. Confirmed on a real
			-- TL-WDR3500, where this reported ip 0.0.0.0 on every inform.
			local orig, orig_read = announce._popen, announce._read_file
			announce._popen = function(cmd)
				if cmd:match("addr show dev eth0%.1") or cmd:match("addr show dev eth0 ") then
					return ""   -- neither the trunk nor the tagged child is addressed
				end
				if cmd:match("addr show dev br%-lan") then
					return "    inet 192.0.2.2/24 brd 192.0.2.255 scope global br-lan\n"
				end
				return ""
			end
			-- eth0 has no master/ at all; only the tagged child is enslaved.
			announce._read_file = function(path)
				if path == "/sys/class/net/eth0.1/master/uevent" then
					return "DEVTYPE=bridge\nINTERFACE=br-lan\nIFINDEX=5\n"
				end
				if path == "/proc/net/dev" then return PROC_NET_DEV end
				return nil
			end
			announce._holder = nil
			local ip = announce.get_ip("eth0")
			announce._popen, announce._read_file = orig, orig_read
			assert_not_nil(ip, "address found two hops away")
			assert_eq(table.concat(ip, "."), "192.0.2.2", "trunk -> tagged child -> bridge")
		end
	},
	{
		name = "announce: steady ticks ask one `ip` for the netdev that held the address",
		fn = function()
			-- The trunk layout costs four forks to walk (port, tagged child,
			-- bridge, and the `ls` that found the child). announce asks every
			-- 10 s, and the answer only moves on a reprovision.
			local orig, orig_read, orig_now = announce._popen, announce._read_file, announce._now
			local asked, reads, now = {}, 0, 1000
			announce._popen = function(cmd)
				asked[#asked + 1] = cmd
				if cmd:match("addr show dev br%-lan") then
					return "    inet 192.0.2.2/24 brd 192.0.2.255 scope global br-lan\n"
				end
				return ""
			end
			announce._read_file = function(path)
				reads = reads + 1
				if path == "/sys/class/net/eth0.1/master/uevent" then return "INTERFACE=br-lan\n" end
				if path == "/proc/net/dev" then return PROC_NET_DEV end
				return nil
			end
			announce._now = function() return now end
			announce._holder = nil
			announce.get_ip("eth0")
			assert_eq(#asked, 3, "the first call walks eth0, eth0.1, br-lan")
			asked, reads = {}, 0
			for _ = 1, 5 do
				now = now + 10
				assert_eq(table.concat(announce.get_ip("eth0"), "."), "192.0.2.2", "same address")
			end
			assert_eq(#asked, 5, "one fork per tick")
			for _, c in ipairs(asked) do
				assert_true(c:match("^ip %-4 addr show dev br%-lan$") ~= nil, "only the bridge is asked: " .. c)
			end
			assert_eq(reads, 0, "and no sysfs or /proc reads")
			-- Past the TTL the chain is walked again, so a layout change is
			-- found even while the old holder keeps an address.
			asked, now = {}, now + announce.HOLDER_TTL
			announce.get_ip("eth0")
			assert_eq(#asked, 3, "re-resolved after HOLDER_TTL")
			-- A clock stepped backwards does not pin the cache.
			asked, now = {}, now - 3600
			announce.get_ip("eth0")
			assert_eq(#asked, 3, "re-resolved after a backwards clock step")
			-- Another interface is not answered from eth0's holder.
			asked = {}
			assert_nil(announce.get_ip("eth1"), "eth1 has no address")
			assert_eq(asked[1], "ip -4 addr show dev eth1", "eth1 is asked itself")
			announce._popen, announce._read_file, announce._now = orig, orig_read, orig_now
			announce._holder = nil
		end
	},
	{
		name = "announce: when the remembered netdev loses its address the chain is walked at once",
		fn = function()
			local orig, orig_read = announce._popen, announce._read_file
			local on = "br-lan"
			announce._popen = function(cmd)
				if cmd == "ip -4 addr show dev " .. on then
					return "    inet 192.0.2.2/24 brd 192.0.2.255 scope global " .. on .. "\n"
				end
				return ""
			end
			announce._read_file = function(path)
				if path == "/sys/class/net/eth0.1/master/uevent" then return "INTERFACE=br-lan\n" end
				if path == "/proc/net/dev" then return PROC_NET_DEV end
				return nil
			end
			announce._holder = nil
			assert_eq(table.concat(announce.get_ip("eth0"), "."), "192.0.2.2", "on the bridge")
			on = "eth0.1"
			local ip = announce.get_ip("eth0")
			announce._popen, announce._read_file = orig, orig_read
			assert_not_nil(ip, "found in the same call, not a tick later")
			assert_eq(announce._holder and announce._holder.dev, "eth0.1", "the new holder is remembered")
			announce._holder = nil
		end
	},
	{
		name = "announce: get_ip returns nil when neither port nor bridge has an address",
		fn = function()
			announce._holder = nil
			local orig, orig_read = announce._popen, announce._read_file
			local asked = {}
			announce._popen = function(cmd)
				asked[#asked + 1] = cmd
				return ""
			end
			announce._read_file = function() return nil end
			local unbridged = announce.get_ip("eth1")
			announce._read_file = function(path)
				if path == "/sys/class/net/eth1/master/uevent" then
					return "INTERFACE=br-lan\n"
				end
				return nil
			end
			asked = {}
			local bridged = announce.get_ip("eth1")
			announce._popen, announce._read_file = orig, orig_read
			local asked_bridge = false
			for _, c in ipairs(asked) do
				if c:match("addr show dev br%-lan") then asked_bridge = true end
			end
			assert_true(asked_bridge, "the bridge was asked")
			assert_nil(unbridged, "no address and no bridge -> nil")
			assert_nil(bridged, "bridge exists but has no address -> nil")
		end
	},
	{
		name = "announce: the IsDefault byte follows the adopted flag",
		fn = function()
			-- 0x17 is IsDefault: 1 = unadopted (factory default), 0 = adopted.
			-- The entry point never passed `adopted`, so this byte said
			-- "factory default" for the life of the process however long ago
			-- the device was adopted, and the controller's Discover list said
			-- so too. _refresh now re-reads it from state.json each tick.
			local un = announce.build_packet(sample_cfg())
			local ad = announce.build_packet(sample_cfg({adopted = true}))
			assert_eq(find_tlv(un, 0x17), string.char(0x01), "unadopted -> 1")
			assert_eq(find_tlv(ad, 0x17), string.char(0x00), "adopted -> 0")
		end
	},
	{
		name = "announce: _refresh re-reads uptime, ip and the adopted flag each tick",
		fn = function()
			announce._holder = nil
			-- Everything the packet carries that can change while the
			-- broadcaster runs. Before this the packet was frozen at the
			-- values read at startup: uptime counted seconds since the DAEMON
			-- started rather than since boot, and the IP stayed whatever the
			-- interface had at boot -- wrong after a DHCP renewal or a
			-- controller-pushed static address.
			local orig_read, orig_popen, orig_state =
				announce._read_file, announce._popen, announce._state
			announce._read_file = function(path)
				if path == "/proc/uptime" then return "864000.42 1700000.00\n" end
				if path == "/proc/sys/kernel/hostname" then return "ap2\n" end
				if path == "/sys/class/net/lan1/address" then return "aa:bb:cc:dd:ee:ff\n" end
				return nil
			end
			announce._popen = function(cmd)
				if cmd:find("^ip ") then return "inet 10.0.9.7/24 brd 10.0.9.255 scope global lan1\n" end
				return ""
			end
			announce._state = {load = function() return {adopted = true} end}

			local cfg = sample_cfg({iface = "lan1", uptime = 30, adopted = false})
			announce._refresh(cfg)
			announce._read_file, announce._popen, announce._state =
				orig_read, orig_popen, orig_state

			assert_eq(cfg.uptime, 864000, "uptime is seconds since BOOT, not since daemon start")
			assert_eq(cfg.hostname, "ap2", "hostname is re-read")
			assert_true(cfg.adopted, "the adopted flag is re-read from state.json")
			assert_eq(table.concat(cfg.ip, "."), "10.0.9.7", "the live address wins over the boot one")
		end
	},
	{
		name = "announce: _refresh keeps the previous value when a source cannot be read",
		fn = function()
			announce._holder = nil
			-- A proc file that is missing, or a state module that cannot be
			-- found, must not blank a field that was correct a second ago.
			local orig_read, orig_popen, orig_state =
				announce._read_file, announce._popen, announce._state
			announce._read_file = function() return nil end
			announce._popen = function() return "" end
			announce._state = {load = function() error("no state file") end}

			local cfg = sample_cfg({iface = "lan1", uptime = 30, adopted = true,
				hostname = "ap2", ip = {10, 0, 9, 7}})
			announce._refresh(cfg)
			announce._read_file, announce._popen, announce._state =
				orig_read, orig_popen, orig_state

			assert_eq(cfg.uptime, 30, "uptime keeps the counted value")
			assert_eq(cfg.hostname, "ap2", "hostname is kept")
			assert_true(cfg.adopted, "the adopted flag is kept, not reset to false")
			assert_eq(table.concat(cfg.ip, "."), "10.0.9.7", "the ip is kept")
		end
	},
	{
		name = "announce: the version suffix has exactly one definition",
		fn = function()
			-- It used to be written out in build_packet and again in the entry
			-- point, so the short/verbose strings could drift from what the
			-- daemon actually announced.
			local cfg = sample_cfg()
			cfg.version_suffix = nil     -- pairs() cannot deliver a nil override
			local pkt = announce.build_packet(cfg)
			assert_true(find_tlv(pkt, 0x16):find(announce.VERSION_SUFFIX, 1, true) ~= nil,
				"the default suffix is M.VERSION_SUFFIX")
		end
	},
	{
		name = "announce: a v1 discovery request is answered with header 01 00 and the announce TLVs",
		fn = function()
			local cfg = sample_cfg()
			local reply = announce.reply_for(string.char(1, 0, 0, 0), cfg)
			assert_true(reply ~= nil, "v1 request answered")
			assert_eq(reply:byte(1), 1, "version")
			assert_eq(reply:byte(2), 0, "command")
			local plen = reply:byte(3) * 256 + reply:byte(4)
			assert_eq(plen, #reply - 4, "length field covers the body")
			assert_eq(find_tlv(reply, 0x0b), "openUF", "hostname TLV")
			assert_eq(find_tlv(reply, 0x01), string.char(0x24, 0xa4, 0x3c, 0x00, 0xd3, 0xad), "hw TLV")
			-- Same body as the broadcast, only the header differs.
			assert_eq(reply:sub(3), announce.build_packet(cfg):sub(3), "body equals the announce body")
		end
	},
	{
		name = "announce: a v2 discovery request is answered with header 02 09",
		fn = function()
			local reply = announce.reply_for(string.char(2, 8, 0, 0), sample_cfg())
			assert_true(reply ~= nil, "v2 request answered")
			assert_eq(reply:byte(1), 2, "version")
			assert_eq(reply:byte(2), 9, "command")
		end
	},
	{
		name = "announce: a targeted v1 request is answered only for our own MAC",
		fn = function()
			local cfg = sample_cfg()
			local mine  = string.char(1, 4, 0, 6, 0x24, 0xa4, 0x3c, 0x00, 0xd3, 0xad)
			local other = string.char(1, 4, 0, 6, 0x24, 0xa4, 0x3c, 0x00, 0xd3, 0xae)
			local reply = announce.reply_for(mine, cfg)
			assert_true(reply ~= nil, "own MAC answered")
			assert_eq(reply:byte(2), 4, "reply command 4")
			assert_eq(announce.reply_for(other, cfg), nil, "another MAC is not ours")
			assert_eq(announce.reply_for(string.char(1, 4, 0, 6, 0x24, 0xa4), cfg), nil, "truncated MAC")
		end
	},
	{
		name = "announce: anything that is not a request gets no reply",
		fn = function()
			local cfg = sample_cfg()
			assert_eq(announce.reply_for(announce.build_packet(cfg), cfg), nil, "our own broadcast echoed back")
			assert_eq(announce.reply_for(string.char(2, 6, 0, 0), cfg), nil, "02 06 with no body")
			assert_eq(announce.reply_for(string.char(1, 0, 0, 1, 0), cfg), nil, "v1 with a nonzero length")
			assert_eq(announce.reply_for(string.char(1, 0, 1, 0), cfg), nil, "length high byte set")
			assert_eq(announce.reply_for(string.char(3, 0, 0, 0), cfg), nil, "unknown version")
			assert_eq(announce.reply_for(string.char(2, 9, 0, 0), cfg), nil, "a reply is not a request")
			assert_eq(announce.reply_for("", cfg), nil, "empty")
			assert_eq(announce.reply_for(nil, cfg), nil, "nil")
		end
	},
	{
		name = "announce: _serve_requests replies to the asker's address and port, once per request type per gap",
		fn = function()
			local now = 0
			local queue = {
				{string.char(1, 0, 0, 0), "192.0.2.50", 40001},
				{string.char(1, 0, 0, 0), "192.0.2.50", 40002},   -- same asker, same request, too soon
				{string.char(2, 8, 0, 0), "192.0.2.50", 40001},   -- same asker, the app's other probe: answered
				{announce.build_packet(sample_cfg()), "192.0.2.9", 10001},   -- not a request
				{string.char(2, 8, 0, 0), "192.0.2.51", 40003},
			}
			local sent = {}
			local udpl = {
				receivefrom = function() local q = table.remove(queue, 1); return q[1], q[2], q[3] end,
				sendto = function(_, data, ip, port) sent[#sent + 1] = {data, ip, port}; return 1 end,
			}
			local fake = {
				gettime = function() now = now + 0.01; return now end,
				select = function() if #queue > 0 then return {udpl} end; now = now + 100; return {} end,
			}
			local saved_refresh, saved_last = announce._refresh, announce._last_reply
			announce._refresh = function(c) return c end
			announce._last_reply = {}
			announce._serve_requests(udpl, sample_cfg(), 10, fake)
			announce._refresh, announce._last_reply = saved_refresh, saved_last
			assert_eq(#sent, 3, "three replies: the repeat and the non-request are skipped")
			assert_eq(sent[1][2], "192.0.2.50", "first asker")
			assert_eq(sent[1][3], 40001, "to the asker's own port")
			assert_eq(sent[1][1]:byte(2), 0, "v1 reply")
			assert_eq(sent[2][2], "192.0.2.50", "the same asker's v2 probe is answered too")
			assert_eq(sent[2][1]:byte(2), 9, "v2 reply")
			assert_eq(sent[3][2], "192.0.2.51", "second asker")
			assert_eq(sent[3][1]:byte(2), 9, "v2 reply")
		end
	},
	{
		name = "announce: the discovery multicast group is joined on the LAN address, once, and again when the address moves",
		fn = function()
			local calls = {}
			local fail = false
			local udpl = {setoption = function(_, opt, v)
				calls[#calls + 1] = opt .. " " .. v.multiaddr .. " " .. v.interface
				if fail and opt == "ip-add-membership" then return nil, "no such device" end
				return 1
			end}
			local saved_j, saved_e = announce._joined, announce._join_err
			announce._joined, announce._join_err = nil, nil
			announce._join_multicast(udpl, {ip = {192, 0, 2, 7}})
			announce._join_multicast(udpl, {ip = {192, 0, 2, 7}})
			assert_eq(#calls, 1, "a second call with the same address does nothing")
			assert_eq(calls[1], "ip-add-membership 233.89.188.1 192.0.2.7", "joined on the LAN address")
			announce._join_multicast(udpl, {ip = {192, 0, 2, 8}})
			assert_eq(calls[2], "ip-drop-membership 233.89.188.1 192.0.2.7", "the old membership is dropped")
			assert_eq(calls[3], "ip-add-membership 233.89.188.1 192.0.2.8", "and the new address joined")
			-- A failed join is retried on the next call, not remembered as done.
			announce._joined, announce._join_err = nil, nil
			calls = {}
			fail = true
			announce._join_multicast(udpl, {ip = {192, 0, 2, 9}})
			announce._join_multicast(udpl, {ip = {192, 0, 2, 9}})
			assert_eq(#calls, 2, "a failed join is attempted again")
			assert_eq(announce._joined, nil, "and not recorded as joined")
			fail = false
			announce._join_multicast(udpl, {ip = {192, 0, 2, 9}})
			assert_eq(announce._joined, "192.0.2.9", "recorded once it works")
			announce._joined, announce._join_err = saved_j, saved_e
		end
	},
	{
		name = "announce: build_packet's default header is still 02 06",
		fn = function()
			local pkt = announce.build_packet(sample_cfg())
			assert_eq(pkt:byte(1), 2, "version")
			assert_eq(pkt:byte(2), 6, "command")
		end
	},
}
