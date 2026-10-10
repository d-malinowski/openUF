-- Tests for openuf/stun.lua: the STUN wake-up client's packets and timing.
-- Run from project root: lua tests/run_tests.lua

local stun = dofile("openuf/stun.lua")

local function hex(s)
	return (s:gsub(".", function(c) return ("%02x"):format(c:byte()) end))
end
local function unhex(h)
	return (h:gsub("%s", ""):gsub("%x%x", function(b) return string.char(tonumber(b, 16)) end))
end

-- A Binding Response as the controller's jstun server builds it:
-- MAPPED-ADDRESS, CHANGED-ADDRESS, SOURCE-ADDRESS, each family 1.
local function response(ip, port, first)
	local a, b, c, d = ip:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
	local mapped = "0001 0008 0001" .. ("%04x"):format(port)
		.. ("%02x%02x%02x%02x"):format(a, b, c, d)
	local other = "0005 0008 0001 0d96 c0000201" .. "0004 0008 0001 0d96 c0000201"
	local attrs = first == "mapped_last" and (other .. mapped) or (mapped .. other)
	return unhex("0101 0024" .. string.rep("00", 16) .. attrs)
end

local WAKE = unhex("8888 0000" .. string.rep("00", 16))

-- LuaSocket double: one UDP socket with a receive queue.
local function fake_socket(opts)
	opts = opts or {}
	local f = {sent = {}, queue = {}, opened = 0, closed = 0}
	f.dns = {toip = function(host)
		f.resolved = (f.resolved or 0) + 1
		if opts.no_dns then return nil, "host not found" end
		return host == "ctrl.example" and "192.0.2.10" or host
	end}
	f.udp = function()
		f.opened = f.opened + 1
		local s = {}
		function s:setsockname(addr, port) f.bound = addr .. ":" .. port; return 1 end
		function s:settimeout(t) f.timeout = t end
		function s:sendto(data, ip, port)
			if opts.send_fails then return nil, "network unreachable" end
			f.sent[#f.sent + 1] = {data = data, to = ip .. ":" .. port}
			return #data
		end
		function s:receive()
			local p = table.remove(f.queue, 1)
			if p == nil then return nil, "timeout" end
			if type(p) == "table" then return nil, p.err end
			return p
		end
		function s:close() f.closed = f.closed + 1 end
		return s
	end
	return f
end

return {
	{
		name = "stun: stun_url names the server, 3478 when it names no port",
		fn = function()
			local h, p = stun.parse_url("stun://192.0.2.4:3478/")
			assert_eq(h, "192.0.2.4", "host")
			assert_eq(p, 3478, "port")
			h, p = stun.parse_url("stun://ctrl.example:3479")
			assert_eq(h, "ctrl.example", "a name")
			assert_eq(p, 3479, "its port")
			h, p = stun.parse_url("stun://192.0.2.4/")
			assert_eq(p, 3478, "default port")
			assert_eq(stun.parse_url("http://192.0.2.4:3478/"), nil, "not stun://")
			assert_eq(stun.parse_url("stun://192.0.2.4:0/"), nil, "port 0")
			assert_eq(stun.parse_url("stun://192.0.2.4:70000/"), nil, "port out of range")
			assert_eq(stun.parse_url(""), nil, "empty")
			assert_eq(stun.parse_url(nil), nil, "absent")
		end
	},
	{
		name = "stun: the Binding Request is the firmware's 28 bytes",
		fn = function()
			-- mcad stun_send: type 1, length 8, zero transaction id,
			-- CHANGE-REQUEST (3) length 4 value 0. The controller rejects a
			-- request without CHANGE-REQUEST.
			assert_eq(hex(stun.request()),
				"00010008" .. string.rep("00", 16) .. "0003000400000000", "bytes")
		end
	},
	{
		name = "stun: a 0x8888 packet is a connection request",
		fn = function()
			assert_eq(stun.parse(WAKE), "wake", "the controller's 20 bytes")
			-- The simulator variant carries a MAC at offset 4; same type.
			local sim = unhex("8888 0000 00005e005302" .. string.rep("00", 10))
			assert_eq(stun.parse(sim), "wake", "with a MAC")
			assert_eq(stun.parse(unhex("8888 0000" .. string.rep("00", 15))), nil, "19 bytes is too short")
		end
	},
	{
		name = "stun: a Binding Response yields its MAPPED-ADDRESS",
		fn = function()
			local kind, ip, port = stun.parse(response("192.0.2.3", 41234))
			assert_eq(kind, "mapped", "kind")
			assert_eq(ip, "192.0.2.3", "ip")
			assert_eq(port, 41234, "port")
			kind, ip, port = stun.parse(response("198.51.100.7", 3, "mapped_last"))
			assert_eq(kind, "mapped", "found after other attributes")
			assert_eq(ip .. ":" .. port, "198.51.100.7:3", "and read from the right one")
			-- Truncated: the attribute runs past the datagram.
			local r = response("192.0.2.3", 41234)
			assert_eq(stun.parse(r:sub(1, 26)), nil, "truncated attribute")
			-- IPv6 family on this IPv4 socket.
			local v6 = unhex("0101 0018" .. string.rep("00", 16) .. "0001 0014 0002 a012"
				.. string.rep("00", 16))
			assert_eq(stun.parse(v6), nil, "family 2")
			-- A Binding Request (or anything else) is not ours to act on.
			assert_eq(stun.parse(stun.request()), nil, "a request")
			assert_eq(stun.parse("short"), nil, "under 20 bytes")
			assert_eq(stun.parse(response("192.0.2.3", 0)), nil, "port 0")
		end
	},
	{
		name = "stun: the client binds an ephemeral port and sends every 30 s",
		fn = function()
			local f = fake_socket()
			local c = stun.new(f)
			assert_true(stun.sync(c, "stun://ctrl.example:3478/", true), "opened")
			assert_eq(f.bound, "*:0", "0.0.0.0, ephemeral port")
			assert_eq(f.timeout, 0, "non-blocking")
			assert_true(stun.send_due(c, 100), "first send at once")
			assert_eq(f.sent[1].to, "192.0.2.10:3478", "to the resolved server")
			assert_eq(f.sent[1].data, stun.request(), "the request")
			assert_false(stun.send_due(c, 129), "not before 30 s")
			assert_true(stun.send_due(c, 130), "at 30 s")
			assert_eq(#f.sent, 2, "two sent")
			assert_eq(f.resolved, 1, "resolved once")
			-- Same URL again: the same socket.
			stun.sync(c, "stun://ctrl.example:3478/", true)
			assert_eq(f.opened, 1, "no reopen")
		end
	},
	{
		name = "stun: a failed send or resolve retries in 5 s and re-resolves",
		fn = function()
			local f = fake_socket({send_fails = true})
			local c = stun.new(f)
			stun.sync(c, "stun://ctrl.example:3478/", true)
			local ok, err = stun.send_due(c, 100)
			assert_false(ok, "failed")
			assert_eq(err, "network unreachable", "says why")
			assert_false(stun.send_due(c, 104), "waits 5 s")
			stun.send_due(c, 105)
			assert_eq(f.resolved, 2, "re-resolved after the failure")
			f = fake_socket({no_dns = true})
			c = stun.new(f)
			stun.sync(c, "stun://ctrl.example:3478/", true)
			ok, err = stun.send_due(c, 100)
			assert_false(ok, "no address")
			assert_true(err:find("ctrl.example", 1, true) ~= nil, "names the host")
			assert_eq(#f.sent, 0, "nothing sent")
			assert_eq(c.next_send, 105, "retry in 5 s")
		end
	},
	{
		name = "stun: a response sets the fields and wakes once per change",
		fn = function()
			local f = fake_socket()
			local c = stun.new(f)
			stun.sync(c, "stun://192.0.2.4:3478/", true)
			assert_eq(stun.fields(c), nil, "nothing before a response")
			assert_false(stun.receive(c), "nothing queued")
			f.queue = {response("192.0.2.3", 41234)}
			assert_true(stun.receive(c), "a new mapping wakes")
			local ip, port = stun.fields(c)
			assert_eq(ip, "192.0.2.3", "connect_request_ip")
			assert_eq(port, "41234", "connect_request_port, a string as the firmware sends it")
			f.queue = {response("192.0.2.3", 41234)}
			assert_false(stun.receive(c), "the same mapping does not")
			f.queue = {response("192.0.2.3", 41235)}
			assert_true(stun.receive(c), "a changed port does")
			f.queue = {WAKE}
			assert_true(stun.receive(c), "a connection request does")
			f.queue = {unhex("0111 0000" .. string.rep("00", 16))}
			assert_false(stun.receive(c), "an error response does not")
			-- Many at once are drained in one read: one inform, not many.
			f.queue = {}
			for i = 1, 10 do f.queue[i] = WAKE end
			assert_true(stun.receive(c), "a burst")
			assert_eq(#f.queue, 0, "drained")
		end
	},
	{
		name = "stun: a socket error, no URL or not managed closes it",
		fn = function()
			local f = fake_socket()
			local c = stun.new(f)
			stun.sync(c, "stun://192.0.2.4:3478/", true)
			f.queue = {response("192.0.2.3", 41234)}
			stun.receive(c)
			f.queue = {{err = "connection refused"}}
			assert_false(stun.receive(c), "no wake")
			assert_eq(f.closed, 1, "closed")
			assert_eq(stun.fields(c), nil, "fields gone with it")
			stun.sync(c, "stun://192.0.2.4:3478/", true)
			assert_eq(f.opened, 2, "reopened on the next tick")
			stun.sync(c, "stun://192.0.2.5:3478/", true)
			assert_eq(f.opened, 3, "a new URL, a new socket")
			assert_eq(f.closed, 2, "the old one closed")
			stun.sync(c, "stun://192.0.2.5:3478/", false)
			assert_eq(f.closed, 3, "not managed: closed")
			assert_eq(c.sock, nil, "no socket")
			stun.sync(c, "stun://192.0.2.5:3478/", true)
			stun.sync(c, nil, true)
			assert_eq(c.sock, nil, "no URL: closed")
			assert_false(stun.send_due(c, 1000), "and nothing sent")
			assert_eq(stun.fields(nil), nil, "no client at all")
		end
	},
}
