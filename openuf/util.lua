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

-- Run an nft script (`nft -f`) through exec, the caller's os.execute seam.
-- quiet discards nft's error text. True when nft accepted all of it.
function M.nft_run(script, exec, quiet)
	local path = os.tmpname()
	local f = io.open(path, "w")
	if not f then return false end
	f:write(script)
	f:close()
	local ok = M.exec_ok((exec or os.execute)("nft -f " .. path .. (quiet and " 2>/dev/null" or "")))
	os.remove(path)
	return ok
end

--[[
	Replace the nft table(s) tables (a name such as "bridge openuf", or a list
	of them) with fresh ones holding stmts: nft commands without the leading
	`nft` and without shell quoting ("add rule bridge openuf block ether saddr
	@blocked_macs drop"). nil stmts only deletes. exec is the caller's
	os.execute seam.

	One `nft -f`, one transaction: the old table goes and the new one comes in
	the same commit, so the traffic it filters never sees a gap with no
	table, and one fork replaces one per command. `add table` before `delete
	table` makes the delete succeed whether or not the table exists.

	The transaction is all or nothing, and the modules want what they have
	always had when a rule cannot be installed (on an image without
	kmod-nft-bridge, typically): every other rule in place, and a warning
	naming the one that is not. So when the batch fails, the statements are
	re-run one at a time, with nft's own error text going to the log.
	Returns ok, failed: failed[i] is true for each rejected stmts[i].
]]--
function M.nft_apply(tables, stmts, exec)
	if type(tables) ~= "table" then tables = {tables} end
	local clear, create = {}, {}
	for _, t in ipairs(tables) do
		clear[#clear + 1] = "add table " .. t .. "\ndelete table " .. t .. "\n"
		create[#create + 1] = "add table " .. t .. "\n"
	end
	clear, create = table.concat(clear), table.concat(create)
	if not stmts then return M.nft_run(clear, exec, true), {} end
	local body = #stmts > 0 and table.concat(stmts, "\n") .. "\n" or ""
	if M.nft_run(clear .. create .. body, exec, true) then return true, {} end
	M.nft_run(clear, exec, true)
	M.nft_run(create, exec)
	local ok, failed = true, {}
	for i, s in ipairs(stmts) do
		if not M.nft_run(s .. "\n", exec) then
			ok = false
			failed[i] = true
		end
	end
	return ok, failed
end

package.loaded["openuf.util"] = M
return M
