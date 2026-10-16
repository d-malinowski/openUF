-- Tests for openuf/util.lua (helpers the modules share).
-- Run from project root: lua tests/run_tests.lua

local util = dofile("openuf/util.lua")

-- A read seam serving canned sysfs files; anything else does not exist.
local function sysfs(files)
	return function(path) return files[path] end
end

return {
	{
		name = "util: master_of names the enslaving netdev from sysfs, without a fork",
		fn = function()
			-- What /sys/class/net/<if>/master/uevent holds for a bridge port
			-- (both reference boards, 2026-10-16).
			local read = sysfs({
				["/sys/class/net/lan3/master/uevent"] = "DEVTYPE=bridge\nINTERFACE=br-lan\nIFINDEX=7\n",
				["/sys/class/net/eth1.10/master/uevent"] = "DEVTYPE=bridge\nINTERFACE=br-openuf10\nIFINDEX=9\n",
				["/sys/class/net/odd/master/uevent"] = "SUBINTERFACE=br-x\nIFINDEX=3\n",
				["/sys/class/net/self/master/uevent"] = "INTERFACE=self\n",
			})
			assert_eq(util.master_of("lan3", read), "br-lan", "a socket in br-lan")
			assert_eq(util.master_of("eth1.10", read), "br-openuf10", "a tagged child in a VLAN bridge")
			assert_nil(util.master_of("eth0", read), "no master/: not enslaved")
			assert_nil(util.master_of("odd", read), "only a whole INTERFACE= line counts")
			assert_nil(util.master_of("self", read), "a netdev is never its own master")
			assert_nil(util.master_of(nil, read), "no ifname")
			assert_nil(util.master_of("", read), "empty ifname")
		end
	},
	{
		name = "util: driver_of names the netdev's driver from sysfs",
		fn = function()
			local read = sysfs({
				["/sys/class/net/phy0-ap0/device/uevent"] = "DRIVER=ath10k_pci\nPCI_CLASS=28000\n",
				["/sys/class/net/phy1-ap0/device/uevent"] = "OF_NAME=wifi\nDRIVER=mt798x-wmac\n",
				["/sys/class/net/blank/device/uevent"] = "DRIVER=\n",
			})
			assert_eq(util.driver_of("phy0-ap0", read), "ath10k_pci", "first line")
			assert_eq(util.driver_of("phy1-ap0", read), "mt798x-wmac", "a later line")
			assert_nil(util.driver_of("br-lan", read), "a virtual netdev has no device/")
			assert_nil(util.driver_of("blank", read), "an empty value is no driver")
		end
	},
	{
		name = "util: master_of falls back to reading the real file",
		fn = function()
			local path = os.tmpname()
			local f = assert(io.open(path, "w"))
			f:write("x=1\n")
			f:close()
			assert_eq(util.read_file(path), "x=1\n", "read_file returns the contents")
			os.remove(path)
			assert_nil(util.read_file(path), "and nil once it is gone")
			assert_nil(util.master_of("openuf-no-such-netdev"), "the default seam is read_file")
		end
	},
	{
		name = "util: exec_ok reads both 5.1 and 5.2+ os.execute results",
		fn = function()
			assert_true(util.exec_ok(0), "5.1 success")
			assert_true(util.exec_ok(true), "5.2+ success")
			assert_false(util.exec_ok(1), "5.1 failure is truthy but not success")
			assert_false(util.exec_ok(256), "5.1 raw wait status")
			assert_false(util.exec_ok(nil), "5.2+ failure")
			assert_false(util.exec_ok(false), "false")
		end
	},
	{
		name = "util: is_mac and valid_ifname admit only what is safe to splice",
		fn = function()
			assert_true(util.is_mac("00:00:5e:00:53:0A"), "either case")
			assert_false(util.is_mac("00:00:5e:00:53"), "short")
			assert_false(util.is_mac("00:00:5e:00:53:01;x"), "trailing junk")
			assert_false(util.is_mac(nil), "nil")
			assert_true(util.valid_ifname("phy1-ap0.sta1"), "dash, dot, digits")
			assert_true(util.valid_ifname(string.rep("a", 15)), "15 characters fit IFNAMSIZ")
			assert_false(util.valid_ifname(string.rep("a", 16)), "16 do not")
			assert_false(util.valid_ifname("wlan0 && reboot"), "no shell")
			assert_false(util.valid_ifname(""), "empty")
		end
	},
	{
		name = "util: capture drops stderr, popen keeps the raw command",
		fn = function()
			assert_eq(util.capture("sh -c 'echo out; echo err >&2'"), "out\n", "stdout only")
			assert_eq(util.popen("echo out"), "out\n", "popen returns stdout")
		end
	},
	{
		name = "util: bit() gives the operations inform and announce use",
		fn = function()
			local bit = util.bit()
			assert_eq(bit.band(0x1234, 0xff), 0x34, "band")
			assert_eq(bit.bor(0x10, 0x01, 0x100), 0x111, "bor takes any number of args")
			assert_eq(bit.bxor(0xff, 0x0f), 0xf0, "bxor")
			assert_eq(bit.lshift(1, 8), 256, "lshift")
			assert_eq(bit.rshift(0x1200, 8), 0x12, "rshift")
			assert_true(util.bit() == bit, "built once")
		end
	},
	{
		name = "util: nft_apply replaces a table in one transaction",
		fn = function()
			local exec, r = fake_nft()
			local ok, failed = util.nft_apply("bridge t", {"add chain bridge t c", "add rule bridge t c drop"}, exec)
			assert_true(ok, "accepted")
			assert_nil(next(failed), "nothing rejected")
			assert_eq(r.runs, 1, "one nft run")
			assert_eq(table.concat(r.cmds, "\n"), table.concat({
				-- The add makes the delete succeed when there is no table yet.
				"nft add table bridge t", "nft delete table bridge t",
				"nft add table bridge t", "nft add chain bridge t c", "nft add rule bridge t c drop",
			}, "\n"), "the old table goes in the commit that builds the new one")
		end
	},
	{
		name = "util: nft_apply with no statements only deletes, every table in one run",
		fn = function()
			local exec, r = fake_nft()
			assert_true(util.nft_apply({"bridge a", "ip b"}, nil, exec), "deleted")
			assert_eq(r.runs, 1, "one nft run")
			assert_eq(table.concat(r.cmds, "\n"), "nft add table bridge a\nnft delete table bridge a\n"
				.. "nft add table ip b\nnft delete table ip b", "both tables, nothing recreated")
		end
	},
	{
		name = "util: nft_apply names a rejected statement and keeps the rest",
		fn = function()
			-- An image without kmod-nft-bridge rejects one rule; the batch is
			-- all or nothing, so it is re-run a statement at a time.
			local exec, r = fake_nft(function(l) return l:find("meta", 1, true) end)
			local stmts = {"add set bridge t s { type ether_addr; }", "add rule bridge t c meta pkttype host drop",
				"add rule bridge t c drop"}
			local ok, failed = util.nft_apply("bridge t", stmts, exec)
			assert_false(ok, "not all of it went in")
			assert_true(failed[2], "the meta rule is named")
			assert_nil(failed[1], "the set is not")
			assert_nil(failed[3], "nor the other rule")
			local joined = table.concat(r.cmds, "\n")
			assert_contains(joined, "nft add set bridge t s", "the set is installed")
			assert_contains(joined, "nft add rule bridge t c drop", "and the other rule")
			assert_true(joined:find("meta", 1, true) == nil, "the rejected one is not")
			assert_eq(r.runs, 6, "the batch, a clear, a create, then one run per statement")
		end
	},
	{
		name = "util: nft_run leaves no script behind and reads 5.1's exit status",
		fn = function()
			local path
			local ok = util.nft_run("add table bridge t\n", function(cmd)
				path = cmd:match("^nft %-f (%S+)")
				return 1
			end)
			assert_false(ok, "exit status 1 is a failure, though truthy")
			assert_not_nil(path, "ran nft -f on a file")
			assert_nil(io.open(path), "the file is removed")
			assert_true(util.nft_run("x\n", function() return 0 end), "exit status 0 is success")
		end
	},
	{
		name = "util: every module shares the one loaded copy",
		fn = function()
			-- Loading a module must not dofile util.lua again: one copy per
			-- process, found through package.loaded.
			local shared = package.loaded["openuf.util"]
			assert_not_nil(shared, "registered on load")
			local sysinfo = dofile("openuf/sysinfo.lua")
			local ucihelper = dofile("openuf/ucihelper.lua")
			assert_true(package.loaded["openuf.util"] == shared, "still the same table")
			assert_true(sysinfo._read_file == shared.read_file, "sysinfo's seam defaults to it")
			assert_true(ucihelper._read_file == shared.read_file, "and so does ucihelper's")
		end
	},
}
