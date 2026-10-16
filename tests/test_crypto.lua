-- Tests for openuf/crypto.lua (AES-128-CBC/GCM wrappers).
-- Run from project root: lua tests/run_tests.lua
-- Requires: lua-openssl or luacrypto (or the openssl CLI for CBC fallback)

local crypto = dofile("openuf/crypto.lua")

-- Fixed IV for deterministic tests
local FIXED_IV = string.rep("\0", 16)

-- NIST AES-128-CBC test vector (from NIST SP 800-38A, F.2.1):
-- Key:  2b7e151628aed2a6abf7158809cf4f3c
-- IV:   000102030405060708090a0b0c0d0e0f
-- PT:   6bc1bee22e409f96e93d7e117393172a
-- CT:   7649abac8119b246cee98e9b12e9197d
local NIST_KEY = "2b7e151628aed2a6abf7158809cf4f3c"
local NIST_IV  = string.char(
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
)
local NIST_PT  = string.char(
	0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
	0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
)
local NIST_CT  = string.char(
	0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
	0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d
)

return {
	{
		name = "crypto: hex_to_bin converts correctly",
		fn = function()
			local b = crypto.hex_to_bin("deadbeef")
			assert_eq(#b, 4, "byte count")
			assert_eq(string.byte(b, 1), 0xde, "byte 1")
			assert_eq(string.byte(b, 4), 0xef, "byte 4")
		end
	},
	{
		name = "crypto: bin_to_hex converts correctly",
		fn = function()
			local h = crypto.bin_to_hex(string.char(0xde, 0xad, 0xbe, 0xef))
			assert_eq(h, "deadbeef", "hex string")
		end
	},
	{
		name = "crypto: hex_to_bin + bin_to_hex round-trip",
		fn = function()
			local original = crypto.DEFAULT_KEY
			assert_eq(crypto.bin_to_hex(crypto.hex_to_bin(original)), original, "round-trip")
		end
	},
	{
		name = "crypto: random_iv returns 16 bytes by default",
		fn = function()
			local iv = crypto.random_iv()
			assert_eq(#iv, 16, "IV length")
		end
	},
	{
		name = "crypto: random_iv injectable override works",
		fn = function()
			local called = false
			crypto._random_bytes = function(n)
				called = true
				return string.rep("\66", n)
			end
			local iv = crypto.random_iv(16)
			crypto._random_bytes = nil
			assert_true(called, "override was called")
			assert_eq(iv, string.rep("\66", 16), "returned injected value")
		end
	},
	{
		name = "crypto: CBC encrypt + decrypt round-trip",
		fn = function()
			local key = crypto.DEFAULT_KEY
			local plaintext = "Hello, UniFi! OK"	-- exactly 16 bytes
			local ct = crypto.aes_cbc_encrypt(key, FIXED_IV, plaintext)
			local pt = crypto.aes_cbc_decrypt(key, FIXED_IV, ct)
			assert_eq(pt, plaintext, "round-trip plaintext")
		end
	},
	{
		name = "crypto: CBC encrypt + decrypt round-trip with non-block-aligned plaintext",
		fn = function()
			local key = crypto.DEFAULT_KEY
			local plaintext = "short"
			local ct = crypto.aes_cbc_encrypt(key, FIXED_IV, plaintext)
			local pt = crypto.aes_cbc_decrypt(key, FIXED_IV, ct)
			assert_eq(pt, plaintext, "round-trip non-block-aligned")
		end
	},
	{
		name = "crypto: CBC ciphertext length is multiple of 16 (PKCS7 padded)",
		fn = function()
			local key = crypto.DEFAULT_KEY
			-- 16-byte plaintext should produce 32-byte ciphertext (padding block added)
			local ct = crypto.aes_cbc_encrypt(key, FIXED_IV, string.rep("A", 16))
			assert_eq(#ct % 16, 0, "ciphertext is block-aligned")
			assert_true(#ct >= 32, "PKCS7 padding block added for 16-byte input")
		end
	},
	{
		name = "crypto: CBC NIST test vector",
		fn = function()
			-- Encrypt exactly one block (16 bytes, no PKCS7 needed for this check)
			-- We check that the first 16 bytes of the ciphertext match NIST
			local ct = crypto.aes_cbc_encrypt(NIST_KEY, NIST_IV, NIST_PT)
			-- ct includes PKCS7 padding block; first 16 bytes must match NIST_CT
			assert_eq(#ct >= 16, true, "ciphertext at least 16 bytes")
			local first_block = ct:sub(1, 16)
			assert_bytes_eq(first_block, NIST_CT, "NIST AES-128-CBC first block")
		end
	},
	{
		name = "crypto: CBC different keys produce different ciphertext",
		fn = function()
			local pt = "same plaintext!!"
			local ct1 = crypto.aes_cbc_encrypt(crypto.DEFAULT_KEY, FIXED_IV, pt)
			local ct2 = crypto.aes_cbc_encrypt("ffffffffffffffffffffffffffffffff", FIXED_IV, pt)
			assert_neq(ct1, ct2, "different keys produce different ciphertext")
		end
	},
	{
		name = "crypto: CBC different IVs produce different ciphertext",
		fn = function()
			local key = crypto.DEFAULT_KEY
			local pt = "same plaintext!!"
			local iv2 = string.rep("\255", 16)
			local ct1 = crypto.aes_cbc_encrypt(key, FIXED_IV, pt)
			local ct2 = crypto.aes_cbc_encrypt(key, iv2, pt)
			assert_neq(ct1, ct2, "different IVs produce different ciphertext")
		end
	},
	{
		name = "crypto: CBC decrypt with wrong key never recovers the plaintext",
		fn = function()
			-- One deterministic assertion. The old shape ("if ok then
			-- assert_neq") took the pkcs7-unpad error path on almost every run
			-- and asserted nothing at all.
			local pt = "secret message!!"
			local ct = crypto.aes_cbc_encrypt(crypto.DEFAULT_KEY, FIXED_IV, pt)
			local ok, result = pcall(crypto.aes_cbc_decrypt,
				"ffffffffffffffffffffffffffffffff", FIXED_IV, ct)
			assert_true((not ok) or (result ~= pt),
				"wrong key must error or produce different data, never the plaintext")
		end
	},
	{
		-- The GCM path (the post-adoption inform crypto) needs a Lua binding
		-- (lua-openssl/luacrypto). Locally a missing binding downgrades the
		-- GCM tests to a LOUD skip; in CI OPENUF_REQUIRE_GCM=1 turns a
		-- missing backend into a hard failure, so the pipeline can never
		-- silently lose GCM coverage again (it did: for a long stretch no
		-- environment executed the GCM code at all -- the old tests quietly
		-- returned without asserting).
		name = "crypto: GCM known-answer vector (16-byte IV, 40-byte AAD, cross-implementation)",
		fn = function()
			if not crypto.gcm_available() then
				if os.getenv("OPENUF_REQUIRE_GCM") == "1" then
					error("OPENUF_REQUIRE_GCM=1 but no GCM backend -- CI must install lua-openssl")
				end
				print("SKIP  GCM known-answer vector (no backend -- luarocks install --local openssl)")
				return
			end
			-- Vector generated once with pycryptodome (an independent AES-GCM
			-- implementation, the same library tools/test_controller.py runs
			-- on), so a shared misunderstanding on both sides -- dropped AAD,
			-- mishandled 16-byte IV (OpenSSL's GCM default is 12; SET_IVLEN
			-- is load-bearing) -- cannot round-trip its way past this test.
			--   key = 000102...0f, iv = 101112...1f (16 bytes),
			--   aad = bytes 0x00..0x27 (40 bytes, the TNBU header length)
			local key_hex = "000102030405060708090a0b0c0d0e0f"
			local iv      = crypto.hex_to_bin("101112131415161718191a1b1c1d1e1f")
			local aad_b = {}
			for i = 0, 39 do aad_b[#aad_b + 1] = string.char(i) end
			local aad = table.concat(aad_b)
			local pt  = '{"_type":"state","probe":42}'
			local want_ct  = crypto.hex_to_bin(
				"bebca8c204c241aaec3ab0f6c05b4af5d9df50ed0264c2da93b2b5eb")
			local want_tag = crypto.hex_to_bin("245b6d60f69b94d3d94bc4e46ac809a7")

			local ct, tag = crypto.aes_gcm_encrypt(key_hex, iv, pt, aad)
			assert_bytes_eq(ct, want_ct, "ciphertext matches the pycryptodome vector")
			assert_bytes_eq(tag, want_tag, "auth tag matches the pycryptodome vector")
			assert_eq(crypto.aes_gcm_decrypt(key_hex, iv, want_ct, want_tag, aad), pt,
				"decrypt of the vector recovers the exact plaintext")
		end
	},
	{
		name = "crypto: GCM decrypt fails on tampered AAD or tag",
		fn = function()
			if not crypto.gcm_available() then
				if os.getenv("OPENUF_REQUIRE_GCM") == "1" then
					error("OPENUF_REQUIRE_GCM=1 but no GCM backend -- CI must install lua-openssl")
				end
				print("SKIP  GCM tamper test (no backend)")
				return
			end
			local key = crypto.DEFAULT_KEY
			local pt  = "GCM secret body!"
			local aad = string.rep("\1", 40)
			local ct, tag = crypto.aes_gcm_encrypt(key, FIXED_IV, pt, aad)
			assert_eq(#tag, 16, "GCM tag is 16 bytes")
			assert_eq(crypto.aes_gcm_decrypt(key, FIXED_IV, ct, tag, aad), pt,
				"round-trip sanity before tampering")
			assert_error(function()
				crypto.aes_gcm_decrypt(key, FIXED_IV, ct, tag, string.rep("\2", 40))
			end, "wrong AAD must fail verification")
			local bad_tag = string.rep("\0", 16)
			assert_error(function()
				crypto.aes_gcm_decrypt(key, FIXED_IV, ct, bad_tag, aad)
			end, "wrong tag must fail verification")
		end
	},
	{
		name = "crypto: GCM without a backend raises a clear error (never silent garbage)",
		fn = function()
			if crypto.gcm_available() then
				print("SKIP  no-backend contract (a GCM backend is installed here)")
				return
			end
			local ok, err = pcall(crypto.aes_gcm_encrypt,
				crypto.DEFAULT_KEY, FIXED_IV, "x", string.rep("\1", 40))
			assert_false(ok, "gcm_encrypt must error without a backend")
			assert_contains(tostring(err), "no GCM backend", "actionable error message")
		end
	},
	{
		name = "crypto: module table has no top-level encrypt field (require self-collision guard)",
		fn = function()
			-- crypto.lua does pcall(require, "crypto") to detect a luacrypto
			-- binding. Lua's default package.path includes "./?.lua", so when
			-- this file runs from its own directory (e.g. /opt/openuf, exactly
			-- how install.sh deploys it) with neither lua-openssl nor
			-- luacrypto installed, require("crypto") can resolve right back to
			-- this same crypto.lua instead of failing. The fix checks the
			-- returned table has luacrypto's shape (an `encrypt` function)
			-- before trusting it, so a self-match falls through to the
			-- openssl(1) CLI backend instead of erroring. That guard only
			-- works because this module's own public API has no top-level
			-- `encrypt` field -- assert that invariant holds.
			assert_true(crypto.encrypt == nil, "module has no top-level encrypt field")
		end
	},
	{
		name = "crypto: looking for luacrypto never loads a second copy of this module",
		fn = function()
			-- The daemons run from /opt/openuf, where "./?.lua" made
			-- require("crypto") load this file again and keep that copy in
			-- package.loaded for the life of the process. Reproduce the
			-- directory with "openuf/?.lua" on the path, with lua-openssl
			-- present and with it missing.
			local path, preload = package.path, package.preload.openssl
			local had_ossl, had_crypto = package.loaded.openssl, package.loaded.crypto
			local function load_from_openuf_dir()
				package.loaded.crypto = nil
				package.path = "openuf/?.lua;" .. path
				local ok, err = pcall(dofile, "openuf/crypto.lua")
				package.path = path
				assert_true(ok, tostring(err))
				local c = package.loaded.crypto
				return c == nil or type(c.encrypt) == "function"
			end
			local ok, err = pcall(function()
				local orig_require, asks = require, 0
				require = function(name)
					if name == "crypto" then asks = asks + 1 end
					return orig_require(name)
				end
				package.loaded.openssl = nil
				package.preload.openssl = function() return {} end  -- loads; never called here
				local fine = load_from_openuf_dir()
				require = orig_require
				assert_true(fine, "with lua-openssl")
				assert_eq(asks, 0, "with lua-openssl, luacrypto is not looked for at all")
				package.loaded.openssl = nil
				package.preload.openssl = function() error("lua-openssl absent") end
				assert_true(load_from_openuf_dir(), "without lua-openssl")
			end)
			package.path, package.preload.openssl = path, preload
			package.loaded.openssl, package.loaded.crypto = had_ossl, had_crypto
			if not ok then error(err, 0) end
		end
	},
}
