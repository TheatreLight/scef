/**
 * SCEF Browser Viewer — KDF module.
 * Derives KEK from password + salt via hash-wasm Argon2id.
 */

/**
 * Derive a 256-bit KEK using Argon2id.
 * @param {string} password - User password (UTF-8 encoded internally by hash-wasm)
 * @param {Uint8Array} salt - 32-byte salt from header
 * @param {number} mKib - Memory in KiB
 * @param {number} t - Iterations
 * @param {number} p - Parallelism
 * @returns {Promise<Uint8Array>} 32-byte KEK
 */
async function deriveKEK(password, salt, mKib, t, p) {
    // hash-wasm exposes argon2id() on the global `hashwasm` object (UMD build).
    const result = await hashwasm.argon2id({
        password: password,
        salt: salt,
        parallelism: p,
        iterations: t,
        memorySize: mKib,
        hashLength: 32,
        outputType: 'binary',
    });

    return new Uint8Array(result);
}
