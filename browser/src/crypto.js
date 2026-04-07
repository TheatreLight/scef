/**
 * SCEF Browser Viewer — Crypto module.
 * HMAC-SHA256 verification, DEK unwrap, data chunk decryption.
 * All operations use WebCrypto API (AES-256-GCM, HMAC-SHA256).
 */

/**
 * Import a raw key for WebCrypto use.
 * @param {Uint8Array} keyBytes - 32-byte key
 * @param {string} algorithm - 'AES-GCM' or 'HMAC'
 * @param {string[]} usages - e.g. ['decrypt'] or ['sign']
 * @returns {Promise<CryptoKey>}
 */
async function importKey(keyBytes, algorithm, usages) {
    if (algorithm === 'HMAC') {
        return crypto.subtle.importKey(
            'raw', keyBytes,
            { name: 'HMAC', hash: 'SHA-256' },
            false, usages
        );
    }
    return crypto.subtle.importKey(
        'raw', keyBytes,
        { name: 'AES-GCM' },
        false, usages
    );
}

/**
 * Compute HMAC-SHA256.
 * @param {Uint8Array} key - 32-byte KEK
 * @param {Uint8Array} data - bytes to authenticate
 * @returns {Promise<Uint8Array>} 32-byte HMAC
 */
async function computeHMAC(key, data) {
    const cryptoKey = await importKey(key, 'HMAC', ['sign']);
    const sig = await crypto.subtle.sign('HMAC', cryptoKey, data);
    return new Uint8Array(sig);
}

/**
 * Constant-time comparison of two Uint8Arrays.
 * Prevents timing side-channel on HMAC verification.
 */
function constantTimeEqual(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff === 0;
}

/**
 * Verify header HMAC.
 * HMAC-SHA256 of header bytes [0x0000..0x009F] using KEK.
 * @param {Uint8Array} kek - 32-byte KEK
 * @param {Uint8Array} hmacProtectedBytes - header bytes [0x0000..0x009F]
 * @param {Uint8Array} storedHmac - 32-byte HMAC from header [0x00A0..0x00BF]
 * @returns {Promise<boolean>} true if HMAC matches
 */
async function verifyHeaderHMAC(kek, hmacProtectedBytes, storedHmac) {
    const computed = await computeHMAC(kek, hmacProtectedBytes);
    return constantTimeEqual(computed, storedHmac);
}

/**
 * Unwrap (decrypt) the DEK using KEK via AES-256-GCM.
 *
 * Botan wire format:
 *   - nonce:     12 bytes (header.dekNonce)
 *   - ciphertext: 32 bytes (header.encryptedDek)
 *   - auth tag:   16 bytes (header.dekAuthTag)
 *
 * WebCrypto expects: decrypt(iv, ciphertext || tag)
 *
 * @param {Uint8Array} kek - 32-byte KEK
 * @param {Uint8Array} dekNonce - 12-byte nonce
 * @param {Uint8Array} encryptedDek - 32-byte encrypted DEK
 * @param {Uint8Array} dekAuthTag - 16-byte auth tag
 * @returns {Promise<Uint8Array>} 32-byte plaintext DEK
 * @throws {Error} on wrong password / auth failure
 */
async function unwrapDEK(kek, dekNonce, encryptedDek, dekAuthTag) {
    const kekKey = await importKey(kek, 'AES-GCM', ['decrypt']);

    // WebCrypto expects ciphertext || tag as a single buffer.
    const ctAndTag = new Uint8Array(encryptedDek.length + dekAuthTag.length);
    ctAndTag.set(encryptedDek, 0);
    ctAndTag.set(dekAuthTag, encryptedDek.length);

    try {
        const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: dekNonce },
            kekKey,
            ctAndTag
        );
        return new Uint8Array(plaintext);
    } catch (e) {
        throw new Error('Wrong password: DEK authentication failed');
    }
}

/**
 * Decrypt a single data chunk.
 * Chunk wire format: [nonce 12B][ciphertext N bytes][auth tag 16B]
 *
 * @param {CryptoKey} dekKey - pre-imported DEK CryptoKey
 * @param {Uint8Array} chunkData - raw encrypted chunk (nonce + ct + tag)
 * @returns {Promise<Uint8Array>} decrypted plaintext
 */
async function decryptChunk(dekKey, chunkData) {
    const nonce = chunkData.slice(0, SCEF.NONCE_SIZE);
    const ctAndTag = chunkData.slice(SCEF.NONCE_SIZE);

    try {
        const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: nonce },
            dekKey,
            ctAndTag
        );
        return new Uint8Array(plaintext);
    } catch (e) {
        throw new Error('Data chunk authentication failed (corrupted data)');
    }
}

/**
 * Import DEK as a CryptoKey once for reuse across all chunk decryptions.
 * @param {Uint8Array} dek - 32-byte DEK
 * @returns {Promise<CryptoKey>}
 */
async function importDEKKey(dek) {
    return importKey(dek, 'AES-GCM', ['decrypt']);
}

/**
 * Compute SHA-256 hash of data (for file integrity check after download).
 * @param {Uint8Array} data
 * @returns {Promise<string>} hex-encoded SHA-256
 */
async function sha256hex(data) {
    const hash = await crypto.subtle.digest('SHA-256', data);
    const arr = new Uint8Array(hash);
    return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}
