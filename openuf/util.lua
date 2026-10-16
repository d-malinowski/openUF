--[[
	Small helpers the modules share: file and command reads, the 5.1-safe exit
	status test, MAC/ifname validation, the bit-operations shim, and the two
	sysfs questions openUF asks of every netdev (which bridge it sits in, which
	driver runs it).

	Loaded once per process. A module loads it with

	    local util = package.loaded["openuf.util"]
	        or assert(loadfile("util.lua") or loadfile("openuf/util.lua"))()

	-- a path, like every sibling, and never a bare require("util"), which
	package.path would resolve to whatever "util" comes first (the lesson of
	crypto.lua's require clash). Each module keeps its own injectable seams
	(M._read_file, M._popen, ...) and points them at these defaults, so tests
	still mock per module.
]]--

local M = {}

-- A file's whole contents, or nil.
function M.read_file(path)
	local f = io.open(path, "r")
	if not f then return nil end
	local s = f:read("*a")
	f:close()
	return s
end

-- A command's stdout with stderr discarded; "" when it could not be run.
function M.capture(cmd)
	local h = io.popen(cmd .. " 2>/dev/null")
	if not h then return "" end
	local s = h:read("*a")
	h:close()
	return s or ""
end

-- A command's stdout as is (stderr reaches the daemon's log); nil when it
-- could not be run.
function M.popen(cmd)
	local h = io.popen(cmd)
	if not h then return nil end
	local s = h:read("*a")
	h:close()
	return s
end

-- Whether os.execute's result means success. 5.1 returns the raw exit status
-- (0 and 1 are both truthy); 5.2+ returns true or nil.
function M.exec_ok(status)
	if status == nil or status == false then return false end
	if type(status) == "number" then return status == 0 end
	return true
end

-- Exactly "aa:bb:cc:dd:ee:ff", either case. Anything spliced into an nft rule
-- or a shell command passes this first.
function M.is_mac(s)
	return type(s) == "string" and s:match("^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$") ~= nil
end

-- A netdev name safe to splice into a command: IFNAMSIZ allows 15 characters.
function M.valid_ifname(s)
	return type(s) == "string" and #s <= 15 and s:match("^[%w%-%._]+$") ~= nil
end

-- band/bor/bxor/lshift/rshift: LuaBitOp, bit32, or 5.3+ integer operators.
-- Built on first use, so a module that never needs it does not fail to load
-- on a Lua that has none of the three.
local _bit
function M.bit()
	if _bit then return _bit end
	local ok, b = pcall(require, "bit")
	if not ok then ok, b = pcall(require, "bit32") end
	if not ok then
		local _l = load or loadstring
		local function _f(e) return _l("return function(a,b) return " .. e .. " end")() end
		b = {
			band   = _f("a&b"),
			bor    = _l("return function(...) local r=0 for i=1,select('#',...)do r=r|select(i,...)end return r end")(),
			bxor   = _f("a~b"),
			lshift = _f("a<<b"),
			rshift = _f("a>>b"),
		}
	end
	_bit = b
	return b
end

-- One KEY=value line of a sysfs uevent file.
local function uevent(path, key, read)
	local s = (read or M.read_file)(path)
	return type(s) == "string" and ("\n" .. s):match("\n" .. key .. "=([^\n]+)") or nil
end

-- The device a netdev is enslaved to (a bridge, a bond), or nil. Reads
-- /sys/class/net/<if>/master/uevent's INTERFACE= instead of forking `readlink`
-- for the symlink's target: both name the same netdev on every interface of
-- both reference boards. read is the caller's file-read seam.
function M.master_of(ifname, read)
	if type(ifname) ~= "string" or ifname == "" then return nil end
	local m = uevent("/sys/class/net/" .. ifname .. "/master/uevent", "INTERFACE", read)
	if m ~= ifname then return m end
	return nil
end

-- The kernel driver behind a netdev ("ath9k", "ath10k_pci", "mt798x-wmac"),
-- or nil for a virtual one: /sys/class/net/<if>/device/uevent's DRIVER=.
function M.driver_of(ifname, read)
	if type(ifname) ~= "string" or ifname == "" then return nil end
	return uevent("/sys/class/net/" .. ifname .. "/device/uevent", "DRIVER", read)
end

package.loaded["openuf.util"] = M
return M
