--[[
	AES-128-CBC and AES-128-GCM wrappers.

	Backend selection (in priority order):
	  1. lua-openssl (require "openssl") — preferred. apk package "lua-openssl"
	     on OpenWrt 25.12+. In-process, supports both CBC and GCM.
	  2. luacrypto  (require "crypto")   — legacy. Only on older OpenWrt where the
	     "luacrypto" package still exists (dropped from the 25.12 feeds).
	  3. openssl(1) CLI                  — last resort when neither binding is
	     present. CBC only; GCM is unavailable on this path.

	All keys and IVs are passed as 32-char hex strings (16 raw bytes).
	Plaintext and ciphertext are Lua binary strings.
]]--

local M = {}

M.DEFAULT_KEY = "ba86f2bbe107c7c57eb5f2690775c712"

-- Injectable for tests: override to return deterministic IVs
M._random_bytes = nil

-- Convert 32-char hex string → 16-byte binary string
function M.hex_to_bin(hex)
	return (hex:gsub("..", function(h) return string.char(tonumber(h, 16)) end))
end

-- Convert binary string → hex string
function M.bin_to_hex(bin)
	return (bin:gsub(".", function(c) return string.format("%02x", string.byte(c)) end))
end

-- Generate a random binary string of `len` bytes (default 16)
function M.random_iv(len)
	len = len or 16
	if M._random_bytes then
		return M._random_bytes(len)
	end
	-- Try /dev/urandom (available on Linux and macOS)
	local f = io.open("/dev/urandom", "rb")
	if f then
		local bytes = f:read(len)
		f:close()
		if bytes and #bytes == len then return bytes end
	end
	-- Last resort: math.random (weak, only if /dev/urandom unavailable)
	math.randomseed(os.time())
	local t = {}
	for i = 1, len do t[i] = string.char(math.random(0, 255)) end
	return table.concat(t)
end

-- PKCS#7 pad to block boundary
local function pkcs7_pad(data, blocksize)
	blocksize = blocksize or 16
	local pad = blocksize - (#data % blocksize)
	return data .. string.rep(string.char(pad), pad)
end

-- Strip PKCS#7 padding; raises error on invalid padding
local function pkcs7_unpad(data)
	if #data == 0 then error("pkcs7_unpad: empty input") end
	local pad = string.byte(data, #data)
	if pad < 1 or pad > 16 then
		error("pkcs7_unpad: invalid padding byte " .. tostring(pad))
	end
	for i = #data - pad + 1, #data do
		if string.byte(data, i) ~= pad then
			error("pkcs7_unpad: padding mismatch at byte " .. i)
		end
	end
	return data:sub(1, #data - pad)
end

-- Backend detection. lua-openssl is preferred; luacrypto is a legacy fallback.
--
-- luacrypto is only looked for without lua-openssl, and only as the C module
-- it is: Lua's default package.path includes "./?.lua", and the daemons run
-- from /opt/openuf, so require("crypto") resolved right back to this file and
-- loaded a second copy of it into package.loaded for the life of the process.
-- package.path is emptied for that one require. The shape check stays as a
-- belt: this module's own table has no `encrypt`.
local _ossl_ok,   _ossl    = pcall(require, "openssl")
local _crypto_ok, _lcrypto = false, nil
if not _ossl_ok then
	local path = package.path
	package.path = ""
	_crypto_ok, _lcrypto = pcall(require, "crypto")
	package.path = path
	_crypto_ok = _crypto_ok and type(_lcrypto) == "table" and type(_lcrypto.encrypt) == "function"
end

-- Internal: unpredictable temp path for the openssl(1) CLI fallback. Names in
-- the old code were "/tmp/uf_cbc_in_<os.time()>" — guessable to any local user,
-- inviting symlink pre-creation and disclosure of the plaintext inform payload
-- written there. The normal path is now lua-openssl (in-process, no temp file);
-- this CLI branch only runs when no binding is present at all.
local function _tmp_path(tag)
	local rnd = M.bin_to_hex(M.random_iv(8))
	return "/tmp/uf_" .. tag .. "_" .. rnd
end

-- Internal: AES-128-CBC via openssl CLI (fallback when no Lua binding is present)
local function _openssl_cbc(decrypt, key_hex, iv_hex, data)
	local tmpIn  = _tmp_path("cbc_in")
	local tmpOut = _tmp_path("cbc_out")
	local fIn = io.open(tmpIn, "wb")
	if not fIn then error("crypto: cannot write temp file") end
	fIn:write(data)
	fIn:close()
	local dcflag = decrypt and "-d " or ""
	local cmd = string.format(
		"openssl enc -aes-128-cbc %s-K %s -iv %s -nopad -nosalt -in %s -out %s 2>/dev/null",
		dcflag, key_hex, iv_hex, tmpIn, tmpOut
	)
	local rc = os.execute(cmd)
	local result
	if rc == 0 or rc == true then
		local fOut = io.open(tmpOut, "rb")
		if fOut then
			result = fOut:read("*a")
			fOut:close()
		end
	end
	os.remove(tmpIn)
	os.remove(tmpOut)
	if not result then error("crypto: openssl enc failed") end
	return result
end

-- AES-128-CBC encrypt
-- key_hex: 32-char hex string
-- iv: 16-byte binary string (from M.random_iv())
-- plaintext: binary string
-- returns: ciphertext binary string (PKCS#7 padded)
function M.aes_cbc_encrypt(key_hex, iv, plaintext)
	local padded = pkcs7_pad(plaintext, 16)
	local key = M.hex_to_bin(key_hex)
	if _ossl_ok then
		-- lua-openssl: pad ourselves (padding(false)) so the wire format matches
		-- the controller, which PKCS#7-pads then encrypts with no extra padding.
		local ctx = _ossl.cipher.get("aes-128-cbc"):new(true, key, iv)
		ctx:padding(false)
		return ctx:update(padded) .. ctx:final()
	elseif _crypto_ok then
		-- luacrypto: encrypt(algo, data, key, iv[, raw])
		-- Pass raw=true (or omit for raw binary output depending on version)
		local ok, result = pcall(_lcrypto.encrypt, "aes-128-cbc", padded, key, iv, true)
		if not ok then
			-- Some versions don't take the raw flag; try without
			result = _lcrypto.encrypt("aes-128-cbc", padded, key, iv)
			-- Decode base64 if returned as base64
			if result and result:find("[A-Za-z0-9+/=]") and not result:find("[\0-\31]") then
				local ok2, dec = pcall(require("mime").unb64, result)
				if ok2 then result = dec end
			end
		end
		return result
	else
		return _openssl_cbc(false, key_hex, M.bin_to_hex(iv), padded)
	end
end

-- AES-128-CBC decrypt
-- key_hex: 32-char hex string
-- iv: 16-byte binary string
-- ciphertext: binary string
-- returns: plaintext binary string (PKCS#7 stripped)
function M.aes_cbc_decrypt(key_hex, iv, ciphertext)
	local key = M.hex_to_bin(key_hex)
	if _ossl_ok then
		local ctx = _ossl.cipher.get("aes-128-cbc"):new(false, key, iv)
		ctx:padding(false)
		return pkcs7_unpad(ctx:update(ciphertext) .. ctx:final())
	elseif _crypto_ok then
		local ok, result = pcall(_lcrypto.decrypt, "aes-128-cbc", ciphertext, key, iv, true)
		if not ok then
			result = _lcrypto.decrypt("aes-128-cbc", ciphertext, key, iv)
		end
		return pkcs7_unpad(result)
	else
		local raw = _openssl_cbc(true, key_hex, M.bin_to_hex(iv), ciphertext)
		return pkcs7_unpad(raw)
	end
end

-- AES-128-GCM encrypt (requires luacrypto with AEAD/GCM support)
-- aad: optional binary string for authenticated additional data (the 40-byte
--      TNBU header per amd989/unifi-gateway; nil = no AAD)
-- Returns: ciphertext (binary string), auth_tag (16-byte binary string)
function M.aes_gcm_encrypt(key_hex, iv, plaintext, aad)
	local key = M.hex_to_bin(key_hex)
	if _ossl_ok then
		-- The TNBU IV field is 16 bytes; OpenSSL GCM defaults to a 12-byte
		-- nonce, so SET_IVLEN must precede init to accept the full IV.
		local C   = _ossl.cipher
		local ctx = C.get("aes-128-gcm"):encrypt_new()
		ctx:ctrl(C.EVP_CTRL_GCM_SET_IVLEN, #iv)
		ctx:init(key, iv)
		ctx:padding(false)
		if aad and #aad > 0 then ctx:update(aad, true) end  -- true = AAD, not plaintext
		local ct  = ctx:update(plaintext) .. ctx:final()
		local tag = ctx:ctrl(C.EVP_CTRL_GCM_GET_TAG, 16)
		return ct, tag
	elseif _crypto_ok and _lcrypto.aead then
		local ctx = _lcrypto.aead("aes-128-gcm", key, iv, true)
		-- Feed AAD if the luacrypto binding exposes updateAAD (version-dependent)
		if aad and #aad > 0 and type(ctx.updateAAD) == "function" then
			ctx:updateAAD(aad)
		end
		local ct = ctx:update(plaintext)
		ct = ct .. ctx:final()
		local tag = ctx:getTag(16)
		return ct, tag
	end
	error("aes_gcm_encrypt: no GCM backend (install lua-openssl); use CBC instead")
end

-- AES-128-GCM decrypt
-- aad: optional binary string for AAD verification (must match what was used to encrypt)
-- Raises an error if authentication tag verification fails
function M.aes_gcm_decrypt(key_hex, iv, ciphertext, tag, aad)
	local key = M.hex_to_bin(key_hex)
	if _ossl_ok then
		local C   = _ossl.cipher
		local ctx = C.get("aes-128-gcm"):decrypt_new()
		ctx:ctrl(C.EVP_CTRL_GCM_SET_IVLEN, #iv)
		ctx:init(key, iv)
		ctx:padding(false)
		if aad and #aad > 0 then ctx:update(aad, true) end
		local pt = ctx:update(ciphertext)
		ctx:ctrl(C.EVP_CTRL_GCM_SET_TAG, tag)
		local final = ctx:final()  -- verifies the tag; falsy on mismatch
		if not final then error("aes_gcm_decrypt: authentication tag verification failed") end
		return pt .. final
	elseif _crypto_ok and _lcrypto.aead then
		local ctx = _lcrypto.aead("aes-128-gcm", key, iv, false)
		if aad and #aad > 0 and type(ctx.updateAAD) == "function" then
			ctx:updateAAD(aad)
		end
		ctx:setTag(tag)
		local pt = ctx:update(ciphertext)
		pt = pt .. ctx:final()  -- final() verifies the tag; throws on mismatch
		return pt
	end
	error("aes_gcm_decrypt: no GCM backend (install lua-openssl)")
end

-- Returns true if GCM is supported by the available backend
function M.gcm_available()
	return (_ossl_ok and _ossl.cipher ~= nil)
		or (_crypto_ok and _lcrypto.aead ~= nil)
end

return M
