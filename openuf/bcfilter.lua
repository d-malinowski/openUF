--[[
	"Multicast and Broadcast Blocker" enforcement (Settings -> WiFi -> [WLAN]).

	The controller pushes this per WLAN as wireless.<n>.bcfilt.status plus a
	bcfilt.<k>.mac allow-list -- see inform.lua's parser for the live wire
	evidence. Unlike every other WLAN setting openUF carries, there is no
	hostapd or OpenWrt option for it: hostapd can suppress group-addressed
	frames wholesale (ap_isolate, disable_dgaf) but has no notion of an
	allow-list, so this is enforced with nftables instead.

	WHAT IT DOES, and why that is deliberately destructive:

	Per Ubiquiti's own documentation this blocks LAN->WLAN multicast and
	broadcast traffic except from the listed source MACs. That genuinely breaks
	DHCP for wireless clients unless the DHCP server's MAC is on the list --
	Ubiquiti documents exactly that, and instructs admins to add it. So the
	filter here is faithful to the controller's intent and deliberately does
	NOT carve out DHCP/ARP exemptions of its own: an admin who enabled this
	control and curated an allow-list would find a silent "helpful" exemption
	harder to debug than the documented behavior.

	The match is on SOURCE MAC in the to-wireless direction: a group-addressed
	frame heading out a managed VAP is dropped unless its sender is
	allow-listed. (Group destinations are not per-station addresses, so a
	destination match could not express an allow-list at all.)

	Mechanism mirrors firewall.lua: a dedicated `bridge` table rebuilt from
	scratch on every reconcile rather than diffed, so it is idempotent and
	self-healing. It uses its OWN table, separate from firewall.lua's `bridge
	openuf` -- that module deletes and recreates its whole table on each
	block/unblock, which would otherwise wipe these rules.

	REQUIRES kmod-nft-bridge. The rule below is the only place openUF uses a
	`meta` expression in the bridge family, and that expression lives in
	nft_meta_bridge.ko -- a module OpenWrt ships in kmod-nft-bridge, which is
	not pulled in by nftables and is absent from a default filogic or ath79
	image. Without it the kernel rejects the rule with a bare
	"Error: Could not process rule: No such file or directory", nft's caret
	pointing at `oifname`. Everything either side of it still succeeds: the
	table, the chain and the per-VAP allow set are all created and populated,
	so the control looks enabled in the controller and on the device while
	filtering nothing at all. That is why a failed rule add warns loudly
	below rather than being left to the reader of a syslog. `ether saddr`
	needs no module, which is why firewall.lua's block-sta table works on the
	same image and hid this for so long.

	VERIFIED on real hardware (AX3000T, mediatek/filogic, nftables 1.1.6,
	kernel 6.12): with the sender not allow-listed, 14 of 14 broadcast frames
	entering the VLAN bridge from the uplink and heading out the IoT VAP
	matched and were dropped; with the same sender allow-listed, 0 of 15
	matched. Both halves of the control do what the controller advertises.
]]--

local M = {}
local util = package.loaded["openuf.util"]
	or assert(loadfile("util.lua") or loadfile("openuf/util.lua"))()

-- Injectable: shell command runner, for real `nft` invocations.
M._exec = os.execute

local NFT_TABLE = "bridge openuf_bcfilt"

-- Exactly "aa:bb:cc:dd:ee:ff": every allow-list entry is spliced into an nft
-- command line, so the shape is enforced here as well as at the parser.
local is_mac = util.is_mac
local valid_ifname = util.valid_ifname

-- Rebuild the filter to exactly match rules, a list of
-- {ifname = "wlan0", macs = {"aa:bb:..", ...}} entries -- one per VAP that has
-- the control enabled. A VAP with an empty allow-list still belongs here: that
-- is "block all group-addressed traffic to this SSID", which is a meaningful
-- (if aggressive) setting rather than a no-op.
--
-- Safe with an empty/nil list (leaves an empty table in place, blocking
-- nothing) and safe to call repeatedly.
function M.reconcile(rules)
	local T = NFT_TABLE
	local stmts = {"add chain " .. T .. " bcfilt { type filter hook forward priority 0; }"}
	local drop_of = {}   -- statement index -> the ifname its drop rule is for
	for _, rule in ipairs(rules or {}) do
		if rule.ifname and not valid_ifname(rule.ifname) then
			io.stderr:write(("bcfilter: ignoring odd interface name %q\n"):format(tostring(rule.ifname)))
		elseif rule.ifname then
			-- One set per interface, so each SSID keeps its own allow-list.
			local set = "allow_" .. rule.ifname:gsub("[^%w]", "_")
			stmts[#stmts + 1] = "add set " .. T .. " " .. set .. " { type ether_addr; }"
			for _, mac in ipairs(rule.macs or {}) do
				if is_mac(mac) then
					stmts[#stmts + 1] = "add element " .. T .. " " .. set .. " { " .. mac .. " }"
				else
					io.stderr:write(("bcfilter: ignoring malformed MAC %q\n")
						:format(tostring(mac)))
				end
			end
			-- Matches frames leaving via this VAP (the LAN->WLAN direction)
			-- that are group-addressed and not from an allow-listed sender.
			--
			-- oifname, not oif: `oif` resolves the interface to an index when
			-- the rule is added and so fails outright if it does not exist
			-- yet -- fatal here, since these rules are (re)built around a
			-- `wifi reload` that tears the wireless netdevs down and back up.
			-- oifname matches on the name and tolerates its absence. Both were
			-- checked against nftables 1.0.9: `oif wlan0` errors with
			-- "Interface does not exist", `oifname "wlan0"` accepts.
			--
			-- meta pkttype names broadcast and multicast explicitly; an
			-- earlier draft used `ether daddr type multicast`, which is not
			-- valid nft syntax at all (it parses as far as `type` and stops).
			--
			-- This is the one rule in openUF that needs kmod-nft-bridge (see
			-- the header): when that module is missing the add fails while
			-- the set above still exists, leaving a table that looks built
			-- and filters nothing. Say so, with the package name.
			stmts[#stmts + 1] = "add rule " .. T .. " bcfilt oifname \"" .. rule.ifname
				.. "\" meta pkttype { broadcast, multicast } ether saddr != @" .. set .. " drop"
			drop_of[#stmts] = rule.ifname
		end
	end
	local ok, failed = util.nft_apply(T, stmts, M._exec)
	for i = 1, #stmts do
		local ifname = drop_of[i]
		if ifname and failed[i] then
			io.stderr:write(string.format(
				"openuf: Multicast/Broadcast Blocker: nft rejected the drop rule " ..
				"for %s -- install kmod-nft-bridge\n" ..
				"openuf: (nft_meta_bridge); without it this WLAN is filtering nothing.\n",
				ifname))
		end
	end
	return ok
end

return M
