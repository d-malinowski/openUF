--[[
	BT Home Hub 5 Type A hardware profile.

	OpenWrt 25.12 (lantiq/xrx200, Lantiq VRX268, MIPS 34Kc), deployed as a
	plain AP:
	  • radio0 = 5 GHz   (ath10k, QCA988x on PCIe — VHT80)
	  • radio1 = 2.4 GHz (ath9k, PCI — HT40)

	The switch is the SoC's GSWIP, driven by DSA since OpenWrt 22.03, so this
	is the AX3000T shape rather than the swconfig one: every socket is its own
	netdev (lan1..lan4) and all four are bridge ports of br-lan, which holds
	the L3 address. The fifth socket (wan) is a separate netdev outside br-lan
	and is not used by an AP deployment, so it is not reported.

	The four LAN netdevs and br-lan share one MAC (the board's
	label MAC), so any of them gives the same identity. lan_cpueth names a
	socket rather than br-lan because the uplink detection asks the bridge
	that this netdev is enslaved to (sysinfo.bridge_of): lan1 is a member
	whether or not a cable is in it, so the uplink is still found when the
	cable moves.

	Caveat: that only covers uplink detection. A VLAN-tagged SSID builds its
	sub-device on lan_cpueth (`lan1.<vid>`), so those SSIDs assume the uplink
	cable is in lan1. Not tested on this board.
]]--

local dev = {}
dev.conf = {}

dev.conf.net = {
	lan_name	= "lan",
	lan_cpueth	= "lan1",
	lan_vlanid	= 1,
	wan_cpueth	= "wan",
	-- One entry per LAN socket; the uplink is detected from the bridge FDB
	-- (sysinfo.uplink_bridge_port), never declared.
	ports = {
		{idx = 1, ifname = "lan1"},
		{idx = 2, ifname = "lan2"},
		{idx = 3, ifname = "lan3"},
		{idx = 4, ifname = "lan4"},
	},
}

-- Locate / Manage > LED. green:broadband has no trigger and no OpenWrt
-- consumer on an AP (the broadband LEDs were DSL's), so driving it disturbs
-- nothing: blue:power is the power LED and blue:wireless follows the 5 GHz
-- radio's traffic.
dev.conf.led = "green:broadband"

-- No dev.conf.vlan: DSA, no swconfig port numbering (see xiaomi-ax3000t.lua).

dev.openuf = {}

dev.openuf.uap = {
	ufmodel		= "u6iw",
	hwassign	= {"radio0", "radio1"},	-- radio0 = 5 GHz, radio1 = 2.4 GHz
}

return dev
