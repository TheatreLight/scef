/**
 * SCEF Header Parser — mirrors include/Header.h binary layout.
 *
 * All offsets and sizes match spec Table 4.2.
 */

const SCEF = Object.freeze({
    HEADER_SIZE:        4096,
    BLOCK_SIZE:         65536,
    NONCE_SIZE:         12,
    AUTH_TAG_SIZE:      16,
    HMAC_PROTECTED_SIZE: 0x00A0,
    SLOT_COUNT:         4,
    SLOT_PERCENTAGES:   [0, 25, 50, 75],
    MAGIC:              [0x53, 0x43, 0x45, 0x46], // "SCEF"

    // Cipher IDs
    CIPHER_AES_256_GCM:    0x01,
    CIPHER_KUZNECHIK_GCM:  0x02,

    // Hash IDs
    HASH_SHA_256:       0x01,
    HASH_STREEBOG_256:  0x02,
    HASH_STREEBOG_512:  0x03,

    // Binary layout offsets
    POS_MAGIC:           0x0000,
    POS_VERSION_MAJOR:   0x0004,
    POS_VERSION_MINOR:   0x0006,
    POS_HEADER_SIZE:     0x0008,
    POS_CIPHER_ID:       0x000C,
    POS_KDF_ID:          0x000D,
    POS_KDF_PROFILE_ID:  0x000E,
    POS_KDF_M_KIB:       0x0010,
    POS_KDF_T:           0x0014,
    POS_KDF_P:           0x0018,
    POS_SALT:            0x001C,
    POS_DEK_NONCE:       0x003C,
    POS_ENCRYPTED_DEK:   0x0048,
    POS_DEK_AUTH_TAG:    0x0068,
    POS_CONTAINER_SIZE:  0x0078,
    POS_FILE_TABLE_SIZE: 0x0080,
    POS_MAX_TABLE_SIZE:  0x0084,
    POS_FILE_COUNT:      0x0088,
    POS_BLOCK_SIZE:      0x008C,
    POS_HEADER_VERSION:  0x0090,
    POS_FLAGS:           0x0094,
    POS_HASH_ALGO_ID:    0x0098,
    POS_HEADER_HMAC:     0x00A0,
    POS_JSON_METADATA:   0x0200,

    // KDF validation bounds (match KdfProfiles.h)
    KDF_M_KIB_MIN: 1,
    KDF_M_KIB_MAX: 4096 * 1024,
    KDF_T_MIN: 1,
    KDF_T_MAX: 100,
    KDF_P_MIN: 1,
    KDF_P_MAX: 64,

    // Browser-specific: WASM typed arrays are capped at 2^31 bytes (2 GiB).
    // Argon2id adds ~1 KiB overhead, so m=2048 MiB overflows by ~1 KiB.
    // Practical max: 2047 MiB.
    KDF_M_KIB_BROWSER_MAX: 2047 * 1024,  // 2047 MiB
});

/**
 * Compute the byte offset of a header slot.
 * Mirrors C++ computeSlotOffset() from FileManager.h:
 *   floor(containerSize * percent / 100 / headerSize) * headerSize
 */
function computeSlotOffset(containerSize, percent, headerSize) {
    if (percent === 0) return 0;
    // Use BigInt to avoid precision loss for large containers.
    const cs = BigInt(containerSize);
    const hs = BigInt(headerSize);
    const p  = BigInt(percent);
    return Number((cs * p / 100n / hs) * hs);
}

/**
 * Compute all 4 slot offsets for a given container size.
 */
function computeSlotOffsets(containerSize, headerSize) {
    return SCEF.SLOT_PERCENTAGES.map(p => computeSlotOffset(containerSize, p, headerSize));
}

/**
 * Parse a 4096-byte header buffer into a structured object.
 * Returns null if magic bytes don't match.
 */
function parseHeader(buffer) {
    if (buffer.byteLength < SCEF.HEADER_SIZE) {
        return null;
    }

    const dv = new DataView(buffer);

    // Check magic: "SCEF" = 0x53, 0x43, 0x45, 0x46
    for (let i = 0; i < 4; i++) {
        if (dv.getUint8(SCEF.POS_MAGIC + i) !== SCEF.MAGIC[i]) {
            return null;
        }
    }

    const header = {
        versionMajor:   dv.getUint16(SCEF.POS_VERSION_MAJOR, true),
        versionMinor:   dv.getUint16(SCEF.POS_VERSION_MINOR, true),
        headerSize:     dv.getUint32(SCEF.POS_HEADER_SIZE, true),
        cipherId:       dv.getUint8(SCEF.POS_CIPHER_ID),
        kdfId:          dv.getUint8(SCEF.POS_KDF_ID),
        kdfProfileId:   dv.getUint16(SCEF.POS_KDF_PROFILE_ID, true),
        kdfMKib:        dv.getUint32(SCEF.POS_KDF_M_KIB, true),
        kdfT:           dv.getUint32(SCEF.POS_KDF_T, true),
        kdfP:           dv.getUint32(SCEF.POS_KDF_P, true),
        salt:           new Uint8Array(buffer, SCEF.POS_SALT, 32),
        dekNonce:       new Uint8Array(buffer, SCEF.POS_DEK_NONCE, 12),
        encryptedDek:   new Uint8Array(buffer, SCEF.POS_ENCRYPTED_DEK, 32),
        dekAuthTag:     new Uint8Array(buffer, SCEF.POS_DEK_AUTH_TAG, 16),
        containerSize:  Number(dv.getBigUint64(SCEF.POS_CONTAINER_SIZE, true)),
        fileTableSize:  dv.getUint32(SCEF.POS_FILE_TABLE_SIZE, true),
        maxTableSize:   dv.getUint32(SCEF.POS_MAX_TABLE_SIZE, true),
        fileCount:      dv.getUint32(SCEF.POS_FILE_COUNT, true),
        blockSize:      dv.getUint32(SCEF.POS_BLOCK_SIZE, true),
        headerVersion:  dv.getUint32(SCEF.POS_HEADER_VERSION, true),
        flags:          dv.getUint32(SCEF.POS_FLAGS, true),
        hashAlgoId:     dv.getUint8(SCEF.POS_HASH_ALGO_ID),
        headerHmac:     new Uint8Array(buffer, SCEF.POS_HEADER_HMAC, 32),
    };

    // Copy typed arrays so they don't reference the original buffer
    // (the buffer may be reused for other slots).
    header.salt         = new Uint8Array(header.salt);
    header.dekNonce     = new Uint8Array(header.dekNonce);
    header.encryptedDek = new Uint8Array(header.encryptedDek);
    header.dekAuthTag   = new Uint8Array(header.dekAuthTag);
    header.headerHmac   = new Uint8Array(header.headerHmac);

    // HMAC-protected bytes: [0x0000..0x009F]
    header.hmacProtectedBytes = new Uint8Array(buffer.slice(0, SCEF.HMAC_PROTECTED_SIZE));

    return header;
}

/**
 * Validate header fields against acceptable bounds before use.
 * Checks structural fields (headerSize, blockSize, maxTableSize) and
 * KDF parameters (DoS prevention). Called before HMAC verification —
 * these fields are not yet authenticated, so bounds limit the damage
 * an attacker-crafted header can cause.
 */
function validateKdfParams(header) {
    // Structural fields — must match expected values or be in safe ranges
    if (header.headerSize !== SCEF.HEADER_SIZE) {
        return 'Unexpected header size: ' + header.headerSize;
    }
    if (header.blockSize < 512 || header.blockSize > 64 * 1024 * 1024) {
        return 'Block size out of range: ' + header.blockSize;
    }
    if (header.maxTableSize < SCEF.NONCE_SIZE + SCEF.AUTH_TAG_SIZE ||
        header.maxTableSize > 64 * 1024 * 1024) {
        return 'Max table size out of range: ' + header.maxTableSize;
    }
    // KDF parameters
    if (header.kdfMKib < SCEF.KDF_M_KIB_MIN || header.kdfMKib > SCEF.KDF_M_KIB_MAX) {
        return 'KDF memory parameter out of range';
    }
    if (header.kdfT < SCEF.KDF_T_MIN || header.kdfT > SCEF.KDF_T_MAX) {
        return 'KDF iterations parameter out of range';
    }
    if (header.kdfP < SCEF.KDF_P_MIN || header.kdfP > SCEF.KDF_P_MAX) {
        return 'KDF parallelism parameter out of range';
    }
    return null; // valid
}
