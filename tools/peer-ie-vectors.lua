--[[
	Sibling-AP element vectors for sysinfo.peer_match_ucode().

	The element matcher is ucode, which neither CI nor the Docker lab has, so the
	Lua tests can only pin its text. This writes a ucode script that runs the
	real generated matcher against fixed element bodies and prints "ok" or
	"FAIL" per vector. Run it from the project root, then in an OpenWrt rootfs
	image, which has ucode:

	  eval $(luarocks path --local)
	  mkdir -p /tmp/uc && lua tools/peer-ie-vectors.lua /tmp/uc/t.uc
	  docker run --rm -v /tmp/uc:/uc openwrt/rootfs:x86-64-25.12.0 ucode /uc/t.uc

	Bodies are the element data after "dd <len>", as hex. The UniFi ones follow
	the firmware layout (PROTOCOL-VALIDATION.md, "The UniFi AP's own element");
	tag 0x89 is one current firmware adds after 0x81.
]]

OPENUF_TEST_MODE = true
package.path = "openuf/?.lua;" .. package.path
local sysinfo = require("sysinfo")

local vectors = {
	-- openUF's own element
	{"026f556f55460100005e005320", "00:00:5e:00:53:20"},
	{"026f556f55460100005e00532099", "null"},              -- wrong length
	-- UniFi AP, 4.0.15 shape
	{"00156d00010100010293a6810600005e005321", "00:00:5e:00:53:21"},
	-- an unknown tag before 0x81 must be walked over
	{"00156d00010140010293a6890400112233810600005e005322", "00:00:5e:00:53:22"},
	-- current firmware: 0x89 after 0x81 (truncated here)
	{"00156d00010140010293a6810600005e005323892430", "00:00:5e:00:53:23"},
	{"00156d00010000010293a6810600005e005324", "null"},    -- not a UniFi AP (00 01 00)
	{"00156d00010100010293a6810600005e", "null"},          -- 0x81 cut short
	{"00156d00010100010293a6810500005e005325", "null"},    -- 0x81 of the wrong length
	{"00276d00010100010293a6810600005e005326", "null"},    -- another OUI
	{"00156d0001010001", "null"},                          -- shorter than the fixed head
	{"00156d00010100010293a6", "null"},                    -- no TLVs
	{"00156d00010100010293a6ff", "null"},                  -- a tag with no length byte
}

local out = {sysinfo.peer_match_ucode()}
out[#out + 1] = 'function hx(h){let s="";for(let i=0;i<length(h);i+=2)s+=chr(hex(substr(h,i,2)));return s;}'
for i, v in ipairs(vectors) do
	out[#out + 1] = string.format(
		'{let r=pm(hx("%s"));print(%d," ",(r??"null")=="%s"?"ok":"FAIL "+r,"\\n");}',
		v[1], i, v[2])
end
local f = assert(io.open(assert(arg[1], "usage: lua tools/peer-ie-vectors.lua <out.uc>"), "w"))
f:write(table.concat(out, "\n"), "\n")
f:close()
