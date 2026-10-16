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
