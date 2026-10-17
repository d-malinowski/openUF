-- Tests for openuf/firewall.lua (client block/unblock enforcement).
-- Run from project root: lua tests/run_tests.lua

local firewall = dofile("openuf/firewall.lua")

local function with_capture(fn)
	local cmds = {}
	local orig = firewall._exec
	firewall._exec = function(cmd)
		cmds[#cmds + 1] = cmd
		return true
	end
	fn(cmds)
	firewall._exec = orig
end

-- A hostapd for deny_sync: per BSS, what `deny_acl SHOW` prints (absent =
-- no control socket, so hostapd_cli fails), the grep of the hostapd
-- configs, and the deny files. Captures the script read and every exec.
local function fake_hostapd(shows, confs, files)
	local r = {execs = {}, script = ""}
	local orig = {firewall._read, firewall._exec, firewall._read_file}
	firewall._read = function(cmd)
		r.script = cmd
		local out = {}
		for b in cmd:gmatch("echo '@ ([^']+)'") do
			out[#out + 1] = "@ " .. b
			out[#out + 1] = shows[b] or "FAIL"
		end
		out[#out + 1] = "@"
		out[#out + 1] = confs or ""
		return table.concat(out, "\n")
	end
	firewall._exec = function(cmd) r.execs[#r.execs + 1] = cmd; return true end
	firewall._read_file = function(path) return (files or {})[path] end
	function r.restore() firewall._read, firewall._exec, firewall._read_file = orig[1], orig[2], orig[3] end
	function r.cmds()
		local out = {}
		for _, e in ipairs(r.execs) do
			for c in e:gmatch("hostapd_cli [^;}]-%x%x:%x%x:%x%x:%x%x:%x%x:%x%x") do out[#out + 1] = c end
		end
		return out
	end
	return r
end

return {
	{
		name = "firewall: reconcile replaces the table, set and chain in one nft transaction",
		fn = function()
			local exec, r = fake_nft()
			local orig = firewall._exec
			firewall._exec = exec
			firewall.reconcile({})
			firewall._exec = orig
			assert_eq(r.runs, 1, "one nft run, not one per command")
			assert_eq(table.concat(r.cmds, "\n"), table.concat({
				"nft add table bridge openuf",
				"nft delete table bridge openuf",
				"nft add table bridge openuf",
				"nft add set bridge openuf blocked_macs { type ether_addr; }",
				"nft add chain bridge openuf block { type filter hook forward priority 0; }",
				"nft add rule bridge openuf block ether saddr @blocked_macs drop",
				"nft add rule bridge openuf block ether daddr @blocked_macs drop",
			}, "\n"), "the old table goes in the same transaction that builds the new one")
		end
	},
	{
		name = "firewall: reconcile adds an element per blocked MAC",
		fn = function()
			local exec, r = fake_nft()
			local orig = firewall._exec
			firewall._exec = exec
			firewall.reconcile({"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"})
			firewall._exec = orig
			local joined = table.concat(r.cmds, "\n")
			assert_contains(joined, "nft add element bridge openuf blocked_macs { aa:bb:cc:dd:ee:01 }",
				"first MAC added as a set element")
			assert_contains(joined, "nft add element bridge openuf blocked_macs { aa:bb:cc:dd:ee:02 }",
				"second MAC added as a set element")
			assert_eq(r.runs, 1, "still one nft run")
		end
	},
	{
		name = "firewall: a rejected statement leaves the rest in place",
		fn = function()
			-- The batch is all or nothing; util.nft_apply re-runs it one
			-- statement at a time so one bad rule costs only itself.
			local exec, r = fake_nft(function(l) return l:find("daddr", 1, true) end)
			local orig = firewall._exec
			firewall._exec = exec
			firewall.reconcile({"aa:bb:cc:dd:ee:01"})
			firewall._exec = orig
			local joined = table.concat(r.cmds, "\n")
			assert_contains(joined, "ether saddr @blocked_macs drop", "the other rule is installed")
			assert_contains(joined, "blocked_macs { aa:bb:cc:dd:ee:01 }", "and the element")
			assert_true(joined:find("daddr", 1, true) == nil, "only the rejected one is missing")
		end
	},
	{
		name = "firewall: deauth issues hostapd_cli per interface",
		fn = function()
			with_capture(function(cmds)
				firewall.deauth("aa:bb:cc:dd:ee:01", {"wlan0", "wlan1"})
				assert_eq(#cmds, 2, "one hostapd_cli call per interface")
				assert_contains(cmds[1], "hostapd_cli -i wlan0 deauthenticate aa:bb:cc:dd:ee:01",
					"deauth on the first radio")
				assert_contains(cmds[2], "hostapd_cli -i wlan1 deauthenticate aa:bb:cc:dd:ee:01",
					"deauth on the second radio")
			end)
		end
	},
	{
		name = "firewall: deauth is a safe no-op with no interfaces",
		fn = function()
			with_capture(function(cmds)
				firewall.deauth("aa:bb:cc:dd:ee:01", {})
				assert_eq(#cmds, 0, "no commands issued")
			end)
			with_capture(function(cmds)
				firewall.deauth("aa:bb:cc:dd:ee:01", nil)
				assert_eq(#cmds, 0, "no commands issued for nil ifnames")
			end)
		end
	},
	{
		name = "firewall: a malformed MAC never reaches the nft command line",
		fn = function()
			-- blocked_stas comes from the controller by way of state.json,
			-- which is hand-editable too, and every entry is spliced straight
			-- into a shell command. Before adoption the inform channel is
			-- plain HTTP under the well-known default key, so a forged
			-- block-sta is within reach of anyone on the path.
			local orig_exec, orig_stderr = firewall._exec, io.stderr
			local logged = {}
			local exec, r = fake_nft()
			local cmds = r.other
			firewall._exec = function(c)
				exec(c)
				for _, l in ipairs(r.cmds) do cmds[#cmds + 1] = l end
				r.cmds = {}
				return 0
			end
			io.stderr = {write = function(_, ...)
				for _, v in ipairs({...}) do logged[#logged + 1] = tostring(v) end
			end}
			firewall.reconcile({
				"aa:bb:cc:dd:ee:ff",
				"aa:bb:cc:dd:ee:ff }; touch /tmp/pwned; nft add element x y '{ 1",
				"not-a-mac",
			})
			local ok_deauth = firewall.deauth("$(id)", {"wlan0"})
			firewall._exec, io.stderr = orig_exec, orig_stderr

			local all = table.concat(cmds, "\n")
			assert_true(all:find("aa:bb:cc:dd:ee:ff", 1, true) ~= nil, "the real MAC is added")
			assert_true(all:find("touch", 1, true) == nil, "the injected command never runs")
			assert_true(all:find("not%-a%-mac") == nil, "and neither does the junk entry")
			assert_true(all:find("hostapd_cli") == nil, "deauth refuses a non-MAC outright")
			assert_false(ok_deauth, "and says so")
			assert_true(table.concat(logged):find("malformed") ~= nil, "each drop is logged")
		end
	},
	{
		name = "firewall: hostapd_sockets names each hostapd control socket by its inode, without a fork",
		fn = function()
			-- /proc/net/unix as both reference boards print it (2026-10-17):
			-- 32-bit on the ath79, 64-bit on the filogic, one socket of
			-- another daemon.
			local orig = firewall._read_file
			firewall._read_file = function(path)
				assert_eq(path, "/proc/net/unix", "one file")
				return "Num       RefCount Protocol Flags    Type St Inode Path\n"
					.. "6e6e66c9: 00000003 00000000 00000000 0001 03 125358599 /var/run/hostapd/phy1-ap1\n"
					.. "722ee422: 00000002 00000000 00000000 0001 03 65409346 /var/run/hostapd/global\n"
					.. "000000000b05b42b: 00000002 00000000 00010000 0001 01  1666 /var/run/ubus/ubus.sock\n"
					.. "000000000ed6ee61: 00000003 00000000 00000000 0002 03 2749890 /var/run/hostapd/phy0-ap0\n"
					.. "0000000012345678: 00000003 00000000 00000000 0001 03 4242\n"
			end
			local got = firewall.hostapd_sockets()
			firewall._read_file = orig
			assert_eq(got, "/var/run/hostapd/global=65409346 /var/run/hostapd/phy0-ap0=2749890 "
				.. "/var/run/hostapd/phy1-ap1=125358599", "hostapd's only, sorted, whole inodes")
			firewall._read_file = function() return nil end
			assert_eq(firewall.hostapd_sockets(), "", "unreadable: none")
			firewall._read_file = orig
		end
	},
	{
		name = "firewall: deny_sync adds each blocked MAC to every BSS's hostapd deny list",
		fn = function()
			local r = fake_hostapd({["phy0-ap0"] = "", ["phy1-ap0"] = "aa:bb:cc:dd:ee:01 VLAN_ID=0\n"})
			local again = firewall.deny_sync({"AA:BB:CC:DD:EE:01", "aa:bb:cc:dd:ee:02", "junk"},
				{"phy0-ap0", "phy1-ap0"})
			r.restore()
			assert_eq(#r.execs, 1, "every change in one shell")
			local cmds = r.cmds()
			assert_eq(table.concat(cmds, "\n"), table.concat({
				"hostapd_cli -i phy0-ap0 deny_acl ADD_MAC aa:bb:cc:dd:ee:01",
				"hostapd_cli -i phy0-ap0 deny_acl ADD_MAC aa:bb:cc:dd:ee:02",
				"hostapd_cli -i phy1-ap0 deny_acl ADD_MAC aa:bb:cc:dd:ee:02",
			}, "\n"), "lowercased; only what each BSS lacks")
			assert_true(r.execs[1]:find("junk", 1, true) == nil, "the junk entry never reaches the shell")
			assert_true(again, "a change was made: look again next time")
		end
	},
	{
		name = "firewall: deny_sync changes nothing when hostapd already has the list",
		fn = function()
			local r = fake_hostapd({["phy0-ap0"] = "aa:bb:cc:dd:ee:01 VLAN_ID=0\n"})
			local again = firewall.deny_sync({"aa:bb:cc:dd:ee:01"}, {"phy0-ap0"})
			r.restore()
			assert_eq(#r.execs, 0, "nothing to run")
			assert_false(again, "nothing to look at again")
		end
	},
	{
		name = "firewall: deny_sync removes an unblocked MAC but keeps the BSS's own MAC filter entries",
		fn = function()
			-- phy0-ap0 runs the controller's MAC filter in deny mode: its
			-- file lists :03, which an unblock must not take off. phy1-ap0
			-- has no deny file, so its :03 is openUF's and goes. The file
			-- of another BSS protects nothing here.
			local r = fake_hostapd({
				["phy0-ap0"] = "aa:bb:cc:dd:ee:01 VLAN_ID=0\naa:bb:cc:dd:ee:03 VLAN_ID=0\n",
				["phy1-ap0"] = "aa:bb:cc:dd:ee:01 VLAN_ID=0\naa:bb:cc:dd:ee:03 VLAN_ID=0\n",
			}, "interface=phy0-ap0\ndeny_mac_file=/var/run/hostapd-phy0-ap0.maclist\n"
				.. "interface=phy1-ap0\nbss=phy1-ap1\ndeny_mac_file=/var/run/hostapd-phy1-ap1.maclist\n",
				{["/var/run/hostapd-phy0-ap0.maclist"] = "AA:BB:CC:DD:EE:03\n",
				 ["/var/run/hostapd-phy1-ap1.maclist"] = "aa:bb:cc:dd:ee:03\n"})
			local again = firewall.deny_sync({}, {"phy0-ap0", "phy1-ap0"})
			r.restore()
			assert_eq(table.concat(r.cmds(), "\n"), table.concat({
				"hostapd_cli -i phy0-ap0 deny_acl DEL_MAC aa:bb:cc:dd:ee:01",
				"hostapd_cli -i phy1-ap0 deny_acl DEL_MAC aa:bb:cc:dd:ee:01",
				"hostapd_cli -i phy1-ap0 deny_acl DEL_MAC aa:bb:cc:dd:ee:03",
			}, "\n"), "only runtime entries the BSS's own config file doesn't list")
			assert_true(again, "read back next time")
		end
	},
	{
		name = "firewall: deny_sync skips a BSS hostapd doesn't answer for and asks to be called again",
		fn = function()
			local r = fake_hostapd({["phy0-ap0"] = "FAIL\n"})
			local again = firewall.deny_sync({"aa:bb:cc:dd:ee:01"}, {"phy0-ap0", "phy1-ap0"})
			r.restore()
			assert_eq(#r.execs, 0, "no command for a BSS whose list is unknown")
			assert_true(again, "try again later")
			local r2 = fake_hostapd({})
			firewall._read = function() return "" end
			assert_true(firewall.deny_sync({"aa:bb:cc:dd:ee:01"}, {"phy0-ap0"}),
				"no output at all (the shell never ran): again, and no error")
			assert_eq(#r2.execs, 0, "and nothing run blind")
			assert_false(firewall.deny_sync({}, {}), "no BSS and nothing blocked: done")
			assert_true(firewall.deny_sync({"aa:bb:cc:dd:ee:01"}, {}), "no BSS yet but something blocked: again")
			r2.restore()
		end
	},
	{
		name = "firewall: deny_sync never splices a bad BSS name into the shell",
		fn = function()
			local r = fake_hostapd({["phy0-ap0"] = ""})
			firewall.deny_sync({"aa:bb:cc:dd:ee:01"}, {"phy0-ap0", "x; reboot", "$(id)"})
			r.restore()
			local all = r.script .. table.concat(r.execs, "\n")
			assert_true(all:find("reboot", 1, true) == nil, "the injected name is dropped")
			assert_true(all:find("$(id)", 1, true) == nil, "and so is the substitution")
			assert_contains(all, "-i phy0-ap0 deny_acl ADD_MAC", "the real BSS is still synced")
		end
	},
}
