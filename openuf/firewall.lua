--[[
	Client blocking, driven by the controller's "Block"/"Unblock" client
	actions. Delivered as a one-shot inform-response cmd (`{"_type":"cmd",
	"cmd":"block-sta"|"unblock-sta","mac":"<mac>"}`) -- confirmed live against
	a real controller (see PROTOCOL-VALIDATION.md). There is no persistent
	wire-level block list the controller pushes on every inform (a candidate
	top-level `include_blocks` field stays empty even while a client is
	blocked) -- the device is expected to remember the block itself, the same
	way real hardware persists it locally after a one-shot command.

	Enforcement is nftables, in a dedicated `bridge openuf` table so it never
	collides with (or gets wiped by) OpenWrt's own fw4-managed tables. Rules
	are added directly to the live kernel ruleset, not via UCI -- like
	netconfig.lua's `ip addr`/`ip route` calls, this is ephemeral runtime
	state that must be explicitly reconciled again after a restart (see
	M.reconcile, called both on the block/unblock cmd and at inform.lua
	startup with the persisted list from state.json).

	A single dynamic nft set (`blocked_macs`) holds every blocked MAC, with
	two static rules matching against it (source and destination) -- adding/
	removing a MAC is then a single `nft add|delete element` against the set,
	never touching the rules themselves. M.reconcile rebuilds the whole table
	from scratch (delete + recreate, in one nft transaction: util.nft_apply)
	rather than diffing -- simpler and self-healing if the table was ever
	left in an unexpected state, and a blocked client never slips through
	between the delete and the rebuild.
]]--

local M = {}
local util = package.loaded["openuf.util"]
	or assert(loadfile("util.lua") or loadfile("openuf/util.lua"))()

-- Injectable: shell command runner, for real `nft`/`hostapd_cli` invocations.
M._exec = os.execute

local NFT_TABLE = "bridge openuf"

-- Exactly "aa:bb:cc:dd:ee:ff". Every MAC below is spliced into a shell command
-- line; the list comes from the controller (block-sta) by way of state.json,
-- which is also hand-editable, so this module refuses anything else itself
-- rather than trusting the caller to have.
local is_mac = util.is_mac

-- Rebuild the nftables blocklist to exactly match blocked_macs (a list of
-- MAC address strings). Safe to call with an empty list (leaves an empty,
-- harmless table+set+chain in place) and safe to call repeatedly (each call
-- fully replaces the previous state rather than accumulating).
function M.reconcile(blocked_macs)
	local T = NFT_TABLE
	local stmts = {"add set " .. T .. " blocked_macs { type ether_addr; }"}
	for _, mac in ipairs(blocked_macs or {}) do
		if is_mac(mac) then
			stmts[#stmts + 1] = "add element " .. T .. " blocked_macs { " .. mac .. " }"
		else
			io.stderr:write(("firewall: ignoring malformed blocked MAC %q\n"):format(tostring(mac)))
		end
	end
	stmts[#stmts + 1] = "add chain " .. T .. " block { type filter hook forward priority 0; }"
	stmts[#stmts + 1] = "add rule " .. T .. " block ether saddr @blocked_macs drop"
	stmts[#stmts + 1] = "add rule " .. T .. " block ether daddr @blocked_macs drop"
	util.nft_apply(T, stmts, M._exec)
	return true
end

-- Injectable: run a command and return its output.
M._read = function(cmd) return util.popen(cmd) or "" end

-- Injectable: a file's contents, or nil.
M._read_file = util.read_file

-- The hostapd control sockets that exist and which socket each one is, as
-- one string: a single read of /proc/net/unix, no fork. hostapd opens a
-- BSS's socket when it sets the BSS up, so the inode changes whenever a
-- hostapd restart or a BSS torn down and rebuilt has thrown that BSS's
-- runtime deny list away. A BSS reloaded in place keeps its socket, so this
-- does not see that.
function M.hostapd_sockets()
	local t = {}
	for inode, path in (M._read_file("/proc/net/unix") or ""):gmatch("(%d+) (/var/run/hostapd/%S+)") do
		t[#t + 1] = path .. "=" .. inode
	end
	table.sort(t)
	return table.concat(t, " ")
end

local function macs_in(text)
	local out = {}
	for line in (text or ""):gmatch("[^\n]+") do
		local mac = line:lower():match("^%s*(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
		if mac then out[mac] = true end
	end
	return out
end

--[[
	The refusal half of a block, as the UniFi firmware has it: the driver
	refuses association from a blocked MAC (iwpriv addmac_blksta on every
	user and guest VAP, re-applied whenever one comes up; firmware-confirmed
	for 3.9.27 to 4.0.15). hostapd's equivalent is its deny ACL, which turns
	away authentication and association and drops any station it already
	has with that MAC. The nft drop stays as the backstop: hostapd checks
	its accept list first, so a MAC filter in allow mode that lists a
	blocked MAC still lets it associate.

	The runtime list lives only in hostapd: a restart or a BSS reload
	resets it to what the BSS's config file says (deny_mac_file, the
	controller's MAC filter in deny mode). So the list is read back and
	repaired on every call, and the caller keeps calling while anything is
	blocked. Every runtime entry the config file doesn't list is taken to be
	openUF's: nothing else on OpenWrt adds deny ACL entries at runtime
	(usteer and DAWN ban through ubus). That makes the sync stateless, so an
	unblock while openUF was not running is still cleaned up.

	blocked: the MAC list; bsses: the AP BSS netdevs. Returns true when
	another look is needed: a BSS that did not answer, or a change made that
	the next call will read back.
]]--
function M.deny_sync(blocked, bsses)
	local want = {}
	for _, m in ipairs(blocked or {}) do
		m = tostring(m):lower()
		if is_mac(m) then want[m] = true end
	end
	local names = {}
	for _, b in ipairs(bsses or {}) do
		if type(b) == "string" and b:match("^[%w%._%-]+$") then names[#names + 1] = b end
	end
	if #names == 0 then return next(want) ~= nil end

	local script = {}
	for _, b in ipairs(names) do
		script[#script + 1] = "echo '@ " .. b .. "'; hostapd_cli -i " .. b
			.. " deny_acl SHOW 2>/dev/null || echo FAIL"
	end
	script[#script + 1] = "echo '@'; for f in /var/run/hostapd-*.conf; do"
		.. " grep -E '^(interface|bss|deny_mac_file)=' \"$f\"; done 2>/dev/null"
	local shown, failed, deny_file = {}, {}, {}
	local cur, conf_bss
	for line in M._read(table.concat(script, "; ")):gmatch("[^\n]+") do
		local marker = line:match("^@ ?(.*)$")
		if marker then
			cur = marker ~= "" and marker or nil
			if cur then shown[cur] = {} end
		elseif cur then
			if line:match("^FAIL") then failed[cur] = true
			else
				local mac = line:lower():match("^(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)")
				if mac then shown[cur][mac] = true end
			end
		else
			local key, val = line:match("^([%w_]+)=(.*)$")
			if key == "interface" or key == "bss" then conf_bss = val
			elseif key == "deny_mac_file" and conf_bss then deny_file[conf_bss] = val end
		end
	end

	local cmds, again = {}, false
	for _, b in ipairs(names) do
		if failed[b] or not shown[b] then
			again = true
		else
			local keep = deny_file[b] and macs_in(M._read_file(deny_file[b])) or {}
			for m in pairs(want) do
				if not shown[b][m] then
					cmds[#cmds + 1] = "hostapd_cli -i " .. b .. " deny_acl ADD_MAC " .. m
				end
			end
			for m in pairs(shown[b]) do
				if not want[m] and not keep[m] then
					cmds[#cmds + 1] = "hostapd_cli -i " .. b .. " deny_acl DEL_MAC " .. m
				end
			end
		end
	end
	if #cmds > 0 then
		table.sort(cmds)
		M._exec("{ " .. table.concat(cmds, "; ") .. "; } >/dev/null 2>&1")
		again = true
	end
	return again
end

-- Immediately kick mac if it's currently associated to any of the given
-- wireless interfaces (ifnames), on top of the nft drop rule from
-- M.reconcile -- the drop rule alone stops future traffic, but a station
-- already associated stays associated (just unable to pass data) until it's
-- actually deauthenticated. Best-effort per interface: a station is only
-- ever associated to one radio at a time, so every other call here is
-- expected to (harmlessly) fail to find it.
function M.deauth(mac, ifnames)
	if not is_mac(mac) then return false end
	for _, ifname in ipairs(ifnames or {}) do
		M._exec("hostapd_cli -i " .. ifname .. " deauthenticate " .. mac .. " 2>/dev/null")
	end
	return true
end

return M
