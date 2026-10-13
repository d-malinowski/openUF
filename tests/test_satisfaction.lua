-- Tests for openuf/satisfaction.lua: the UniFi firmware's WiFi Experience
-- formula (calc_sta_satisfaction and the roll-ups in libubnt 4.0.15).
-- Run from project root: lua tests/run_tests.lua
--
-- The expected values are worked from the decoded MIPS code by hand, so each
-- boundary sits on the exact comparison the firmware makes (slti/sltiu
-- against 0xf, 5, 0x32, 0x1771 ...).

local sat = dofile("openuf/satisfaction.lua")

return {
	{
		name = "satisfaction: snr floors the noise at -96 and never goes negative",
		fn = function()
			assert_eq(sat.snr(-60, -90), 30, "plain difference above the floor")
			assert_eq(sat.snr(-60, -107), 36, "ath9k's -107 is taken as -96")
			assert_eq(sat.snr(-60, nil), 36, "unknown noise: the floor")
			assert_eq(sat.snr(-60, 0), 36, "a zero noise reading: the floor")
			assert_eq(sat.snr(-100, -96), 0, "below the floor clamps to 0, as the driver's u8 does")
			assert_nil(sat.snr(nil, -90), "no signal, no snr")
		end
	},
	{
		name = "satisfaction: signal term steps at 5 and 15 dB",
		fn = function()
			assert_eq(sat.signal_score(0), 0, "0 dB")
			assert_eq(sat.signal_score(4), 0, "4 dB: still 0")
			assert_eq(sat.signal_score(5), 40, "5 dB: 5*5+15")
			assert_eq(sat.signal_score(14), 85, "14 dB: 5*14+15")
			assert_eq(sat.signal_score(15), 90, "15 dB: 15+75")
			assert_eq(sat.signal_score(24), 99, "24 dB")
			assert_eq(sat.signal_score(25), 100, "25 dB: capped")
			assert_eq(sat.signal_score(60), 100, "60 dB: capped")
		end
	},
	{
		name = "satisfaction: phy term is the mean rate in absolute steps",
		fn = function()
			local function p(tx, rx) return (sat.phy_score(tx, rx)) end
			assert_eq(p(0, 0), 100, "no rate known: not judged")
			assert_eq(p(nil, nil), 100, "nil rates: not judged")
			assert_eq(p(6000, 0), 10, "6000 kbps (only tx known)")
			assert_eq(p(0, 6001), 25, "6001 kbps (only rx known)")
			assert_eq(p(12000, 12000), 25, "12000")
			assert_eq(p(12002, 12002), 50, "12002 (the halves sum to 12002)")
			assert_eq(p(18000, 18000), 50, "18000")
			assert_eq(p(24000, 24000), 70, "24000")
			assert_eq(p(24001, 24003), 75, "24000 + 1: floor(24001/2) + floor(24003/2) = 24001")
			assert_eq(p(36000, 36000), 75, "36000")
			assert_eq(p(54000, 54000), 80, "54000")
			assert_eq(p(72200, 72200), 85, "HT MCS 7 both ways")
			assert_eq(p(100000, 100000), 85, "100000")
			assert_eq(p(200000, 200000), 90, "200000")
			assert_eq(p(400000, 400000), 95, "400000")
			assert_eq(p(400001, 400001), 95, "the halves of two odd rates lose a kbps each: 400000")
			assert_eq(p(400002, 400002), 100, "400001")
			assert_eq(p(866700, 6000), 100, "VHT tx and a 6 Mbit/s legacy rx frame: 433350 + 3000")
			local _, low = sat.phy_score(12000, 12000)
			assert_true(low, "12000 is a low_phy_rate anomaly")
			_, low = sat.phy_score(12002, 12002)
			assert_false(low, "12001 is not")
		end
	},
	{
		name = "satisfaction: retry term starts at 25 % and takes a point per drop",
		fn = function()
			local function r(t, re, d) return (sat.retry_score(t, re, d)) end
			assert_eq(r(0, 0, 0), 100, "no frames: not judged")
			assert_eq(r(0, 0, 50), 100, "no frames: drops not counted either")
			assert_eq(r(100, 25, 0), 100, "25 %")
			assert_eq(r(100, 26, 0), 99, "26 %: 100 - floor(100/75)")
			assert_eq(r(100, 50, 0), 67, "50 %: 100 - 2500/75 = 100 - 33")
			assert_eq(r(100, 100, 0), 0, "100 %")
			assert_eq(r(1000, 251, 0), 100, "25.1 % truncates to 25")
			assert_eq(r(100, 101, 0), 0, "more retries than frames: 0")
			assert_eq(r(100, 0, 30), 70, "30 drops")
			assert_eq(r(100, 0, 500), 0, "drops count at most 100")
			assert_eq(r(100, 50, 80), 0, "never below 0")
			local _, a = sat.retry_score(100, 0, 51)
			assert_true(a, "49 is a high_wifi_retries anomaly")
			_, a = sat.retry_score(100, 0, 50)
			assert_false(a, "50 is not")
			_, a = sat.retry_score(100, 101, 0)
			assert_true(a, "retries > frames is one")
		end
	},
	{
		name = "satisfaction: the lowest term sets score and reason, anomalies collect",
		fn = function()
			local s, reason, anomalies = sat.score{snr = 40, tx_kbps = 866700, rx_kbps = 866700}
			assert_eq(s, 100, "clean client")
			assert_eq(reason, 0, "nothing below 100: no reason")
			assert_eq(anomalies, 0, "no anomalies")

			s, reason, anomalies = sat.score{snr = 20, tx_kbps = 866700, rx_kbps = 866700}
			assert_eq(s, 95, "signal 20 dB binds")
			assert_eq(reason, sat.SIGNAL, "reason: signal")
			assert_eq(anomalies, 0, "95 is no anomaly")

			s, reason, anomalies = sat.score{snr = 20, tx_kbps = 72200, rx_kbps = 72200}
			assert_eq(s, 85, "phy 85 < signal 95")
			assert_eq(reason, sat.PHY_RATE, "reason: phy_rate")

			s, reason = sat.score{snr = 10, tx_kbps = 72200, rx_kbps = 72200}
			assert_eq(s, 65, "signal 65 < phy 85")
			assert_eq(reason, sat.SIGNAL, "reason: signal")

			s, reason = sat.score{snr = 14, tx_kbps = 72200, rx_kbps = 72200}
			assert_eq(s, 85, "a tie: signal 85 = phy 85")
			assert_eq(reason, sat.SIGNAL, "the earlier term keeps the reason on a tie")

			s, reason, anomalies = sat.score{snr = 6, tx_kbps = 6000, rx_kbps = 6000,
				tries = 100, retries = 100}
			assert_eq(s, 0, "retries 100 % -> 0")
			assert_eq(reason, sat.WIFI_RETRIES, "reason: wifi_retries")
			assert_eq(anomalies, sat.SIGNAL + sat.PHY_RATE + sat.WIFI_RETRIES,
				"every weak term is an anomaly, whichever won")

			assert_nil(sat.score{tx_kbps = 1000}, "no snr: unscored")
		end
	},
	{
		name = "satisfaction: the retry window is the last completed minute",
		fn = function()
			local w = sat.window(nil, {packets = 100, retries = 10, dropped = 0}, 1000)
			assert_nil(w.mov, "a new station has no minute yet")
			w = sat.window(w, {packets = 200, retries = 60, dropped = 0}, 1050)
			assert_nil(w.mov, "50 s: still not")
			w = sat.window(w, {packets = 300, retries = 70, dropped = 2}, 1060)
			assert_eq(w.mov.tries, 200, "60 s: frames over the minute")
			assert_eq(w.mov.retries, 60, "retries over the minute")
			assert_eq(w.mov.dropped, 2, "drops over the minute")
			w = sat.window(w, {packets = 900, retries = 700, dropped = 2}, 1110)
			assert_eq(w.mov.tries, 200, "the minute holds until the next one completes")
			w = sat.window(w, {packets = 1000, retries = 700, dropped = 2}, 1120)
			assert_eq(w.mov.tries, 700, "next minute")
			assert_eq(w.mov.retries, 630, "next minute's retries")
			w = sat.window(w, {packets = 5, retries = 0, dropped = 0}, 1130)
			assert_nil(w.mov, "counters going backwards: a new association starts over")
			w = sat.window(w, {packets = 50, retries = 1}, 1190)
			assert_eq(w.mov.dropped, 0, "no drop counter: 0")
			local kept = sat.window(w, {}, 1200)
			assert_eq(kept.mov.tries, 45, "a sample without counters keeps the last minute")
		end
	},
	{
		name = "satisfaction: vap mean truncates, roll-ups weight by stations",
		fn = function()
			local a = sat.tally()
			assert_eq(a.mean(), -1, "no stations: -1")
			a.add(100, 0, 0)
			a.add(85, sat.PHY_RATE, 0)
			a.add(40, sat.SIGNAL, sat.SIGNAL + sat.PHY_RATE)
			assert_eq(a.mean(), 75, "225/3 = 75")
			local b = sat.tally()
			b.add(90, sat.SIGNAL, 0)
			b.add(91, sat.SIGNAL, 0)
			assert_eq(b.mean(), 90, "90.5 truncates")
			assert_eq(sat.rollup({a, b, sat.tally()}), 81, "(3*75 + 2*90) / 5 = 81, the empty VAP ignored")
			assert_eq(sat.rollup({sat.tally()}), -1, "no stations anywhere: -1")
			assert_eq(sat.rollup({}), -1, "no VAPs: -1")
			local an = a.chart(sat.ANOMALY_KEYS)
			assert_eq(an.weak_signal, 1, "one weak_signal")
			assert_eq(an.low_phy_rate, 1, "one low_phy_rate")
			assert_eq(an.high_wifi_latency, 0, "every key present")
			local re = a.chart(sat.REASON_KEYS)
			assert_eq(re.signal, 1, "one limited by signal")
			assert_eq(re.phy_rate, 1, "one by phy rate")
			assert_eq(re.wifi_retries, 0, "none by retries")
			local n = 0
			for _ in pairs(re) do n = n + 1 end
			assert_eq(n, 8, "eight reason keys")
		end
	},
	{
		name = "satisfaction: tx failed is a drop count except on mt76",
		fn = function()
			assert_true(sat.failed_is_dropped("ath9k"), "ath9k")
			assert_true(sat.failed_is_dropped("ath10k_pci"), "ath10k")
			assert_true(sat.failed_is_dropped(nil), "unknown driver: mac80211's meaning")
			assert_false(sat.failed_is_dropped("mt798x-wmac"), "MT7981 (AX3000T)")
			assert_false(sat.failed_is_dropped("mt7915e"), "mt7915e")
			assert_false(sat.failed_is_dropped("mt76x2e"), "mt76x2e")
		end
	},
	{
		name = "satisfaction: dropped() is tx failed, or failed less retries on mt76",
		fn = function()
			assert_eq(sat.dropped(true, 5, 40), 5, "ath: failed is the drop count")
			assert_eq(sat.dropped(false, 42, 40), 2, "mt76 tx-free path: failed = retries + drops")
			assert_eq(sat.dropped(false, 3, 40), 0, "mt76 WED path: never a negative count")
			assert_eq(sat.dropped(false, 4, nil), 4, "no retries line: all of failed")
			assert_eq(sat.dropped(false, nil, 4), nil, "no failed line: unknown")
		end
	},
}
