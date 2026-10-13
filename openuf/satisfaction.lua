--[[
	WiFi Experience ("satisfaction"): the UniFi AP firmware's own formula.

	Ported from libubnt.so of UAP BZ2 firmware 4.0.15 (firmware-confirmed for
	4.0.15; 3.9.27 computes no satisfaction at all): calc_sta_satisfaction for a
	client, calc_vap/radio/ap_satisfaction for the roll-ups, and the per-VAP
	anomaly and reason tallies in fill_wireless_info_full. The controller does
	no computation of its own: it stores what the AP sends.

	A client's score is the lowest of six terms, each 0-100:
	  signal   SNR in dB (the firmware's "rssi"): <5 -> 0, 5-14 -> 5*snr + 15,
	           >=15 -> snr + 75, capped at 100
	  phy_rate the mean of the last tx and rx rates, in steps (phy_score)
	  tcp_packet_loss, tcp_latency
	           from the driver's TCP inspection (ubnt_calc_tcp_stats in
	           umac.ko); mac80211 has no equivalent, so they score 100, which
	           is what the firmware's own formula gives with no TCP seen
	  wifi_retries
	           retries per frame over the last full minute: <=25 % -> 100,
	           then down to 0 at 100 %; minus one point per frame dropped in
	           that minute
	  wifi_latency
	           mean tx completion latency over the last minute (driver
	           _ubnt_log_txtime); no mac80211 source, so 100
	The reason is the bit of the term that set the score (the first one wins a
	tie); anomalies are a bitmask of terms below their threshold, whichever one
	won. Bits 0x20 and 0x40 exist as chart keys but the firmware never sets them.

	The driver keeps the "_mov" counters as the delta over the last completed
	60 s period (sta_stat_iter, a 60000 ms timer in umac.ko), so the retry term
	moves once a minute and scores 100 until a client's first minute is over.
]]--

local M = {}

-- The driver's timer period for the _mov counters.
M.WINDOW_SECS = 60
-- fill_stainfo_json derives signal as rssi + max(noise, -96): the noise floor
-- is never taken as lower than this.
M.NOISE_FLOOR_MIN = -96

-- Bit i (from 0) is key i + 1, in the order of the firmware's chart key
-- tables (anomalies_bar_chart_keys / reasons_bar_chart_keys in libubnt).
M.ANOMALY_KEYS = {"weak_signal", "low_phy_rate", "high_tcp_packet_loss",
	"high_tcp_latency", "high_wifi_retries", "poor_stream_eff", "sleepy_client",
	"high_wifi_latency"}
M.REASON_KEYS = {"signal", "phy_rate", "tcp_packet_loss", "tcp_latency",
	"wifi_retries", "stream_eff", "sleepy_client", "wifi_latency"}

M.SIGNAL, M.PHY_RATE, M.TCP_LOSS, M.TCP_LATENCY = 0x1, 0x2, 0x4, 0x8
M.WIFI_RETRIES, M.WIFI_LATENCY = 0x10, 0x80

-- The firmware's rssi: signal over the noise floor, in whole dB, never below
-- 0 (the driver keeps it in a u8). nil without a signal.
function M.snr(signal, noise)
	if not signal then return nil end
	if not noise or noise == 0 or noise < M.NOISE_FLOOR_MIN then
		noise = M.NOISE_FLOOR_MIN
	end
	local snr = math.floor(signal - noise)
	if snr < 0 then snr = 0 end
	return snr
end

function M.signal_score(snr)
	if snr >= 15 then return math.min(snr + 75, 100) end
	if snr < 5 then return 0 end
	return 5 * snr + 15
end

-- Upper bounds (kbps, inclusive) and the score of each step above the last.
local PHY_STEPS = {
	{6000, 10}, {12000, 25}, {18000, 50}, {24000, 70}, {36000, 75},
	{54000, 80}, {100000, 85}, {200000, 90}, {400000, 95},
}

-- tx_kbps/rx_kbps: the last rates in kbps (0 or nil when unknown). Returns
-- the score and whether it is a low_phy_rate anomaly.
function M.phy_score(tx_kbps, rx_kbps)
	local tx, rx = tx_kbps or 0, rx_kbps or 0
	local r
	if tx == 0 and rx == 0 then return 100, false
	elseif tx == 0 then r = rx
	elseif rx == 0 then r = tx
	else r = math.floor(tx / 2) + math.floor(rx / 2) end
	for i, step in ipairs(PHY_STEPS) do
		if r <= step[1] then return step[2], i <= 2 end
	end
	return 100, false
end

-- tries/retries/dropped: the last minute's frames sent, retries and frames
-- dropped. Returns the score and whether it is a high_wifi_retries anomaly.
function M.retry_score(tries, retries, dropped)
	tries, retries, dropped = tries or 0, retries or 0, dropped or 0
	if retries > tries then return 0, true end
	if tries == 0 then return 100, false end
	local p = math.floor(retries * 100.0 / tries)
	local score = 100
	if p > 25 then score = 100 - math.floor((100 * p - 2500) / 75) end
	score = score - math.min(dropped, 100)
	if score < 0 then score = 0 end
	return score, score < 50
end

-- in: {snr, tx_kbps, rx_kbps, tries, retries, dropped}. Returns score,
-- reason, anomalies, or nil without an snr.
function M.score(input)
	if not input.snr then return nil end
	local score = M.signal_score(input.snr)
	local anomalies = score < 50 and M.SIGNAL or 0
	local reason = score < 100 and M.SIGNAL or 0
	local function term(value, bit, anomaly)
		if anomaly then anomalies = anomalies + bit end
		if value < score then score, reason = value, bit end
	end
	local p, p_anomaly = M.phy_score(input.tx_kbps, input.rx_kbps)
	term(p, M.PHY_RATE, p_anomaly)
	term(100, M.TCP_LOSS, false)
	term(100, M.TCP_LATENCY, false)
	local r, r_anomaly = M.retry_score(input.tries, input.retries, input.dropped)
	term(r, M.WIFI_RETRIES, r_anomaly)
	term(100, M.WIFI_LATENCY, false)
	return score, reason, anomalies
end

-- The per-minute window behind the retry term. prev: this station's last
-- state (nil for a new one); cur: {packets, retries, dropped} lifetime
-- counters. Returns the new state, whose mov = {tries, retries, dropped} is
-- the last completed minute's deltas (nil before the first one). A counter
-- going backwards is a new association: the window restarts.
function M.window(prev, cur, now)
	local base = prev and prev.base
	if not (cur.packets and cur.retries) then
		return {base = nil, mov = prev and prev.mov}
	end
	local dropped = cur.dropped or 0
	if not base or cur.packets < base.packets or cur.retries < base.retries
			or dropped < base.dropped then
		return {base = {t = now, packets = cur.packets, retries = cur.retries,
			dropped = dropped}}
	end
	if now - base.t < M.WINDOW_SECS then
		return {base = base, mov = prev.mov}
	end
	return {
		base = {t = now, packets = cur.packets, retries = cur.retries, dropped = dropped},
		mov = {tries = cur.packets - base.packets, retries = cur.retries - base.retries,
			dropped = dropped - base.dropped},
	}
end

-- A tally of stations' scores: add() each, then mean() (calc_vap_satisfaction:
-- truncated, capped at 100, -1 with none) and the two bar charts, each a
-- count of stations per bit.
function M.tally()
	local t = {n = 0, sum = 0, anomalies = {}, reasons = {}}
	for i = 1, 8 do t.anomalies[i], t.reasons[i] = 0, 0 end
	function t.add(score, reason, anomalies)
		t.n, t.sum = t.n + 1, t.sum + score
		for i = 1, 8 do
			local bit = 2 ^ (i - 1)
			if math.floor(anomalies / bit) % 2 == 1 then t.anomalies[i] = t.anomalies[i] + 1 end
			if math.floor(reason / bit) % 2 == 1 then t.reasons[i] = t.reasons[i] + 1 end
		end
	end
	function t.mean()
		if t.n == 0 then return -1 end
		return math.min(math.floor(t.sum / t.n), 100)
	end
	function t.chart(keys)
		local counts = keys == M.ANOMALY_KEYS and t.anomalies or t.reasons
		local out = {}
		for i, k in ipairs(keys) do out[k] = counts[i] end
		return out
	end
	return t
end

-- Radio and device roll-up over VAP tallies: each VAP's own (truncated)
-- score weighted by its station count, truncated, capped at 100, -1 with no
-- stations (calc_radio_satisfaction / calc_ap_satisfaction).
function M.rollup(tallies)
	local n, sum = 0, 0
	for _, t in ipairs(tallies) do
		if t.n > 0 then n, sum = n + t.n, sum + t.n * t.mean() end
	end
	if n == 0 then return -1 end
	return math.min(math.floor(sum / n), 100)
end

-- mac80211's "tx failed" means frames dropped after the last retry on most
-- drivers, but failed ATTEMPTS on mt76 (it tracks tx retries and can exceed
-- tx packets; measured on an AX3000T): see M.dropped.
function M.failed_is_dropped(driver)
	return not (driver and driver:match("^mt7"))
end

-- A station's dropped frames from its tx failed/retries counters. mt76's
-- tx-free path adds count - 1 to retries and that plus 1 for a frame that
-- finally failed to tx_failed (mt7915/mac.c), so the drops are the
-- difference. Its WED path counts both from the firmware's own report, where
-- failed is far below retries: 0 there, never a negative count.
function M.dropped(failed_is_dropped, failed, retries)
	if failed_is_dropped then return failed end
	if not failed then return nil end
	return math.max(0, failed - (retries or 0))
end

return M
