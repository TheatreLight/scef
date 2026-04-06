/**
 * Cross-implementation test: verify JS KDF + HMAC match C++ test vectors.
 * Usage: node test/test_crypto_node.js
 *
 * Tests:
 *   1. Argon2id KEK derivation (hash-wasm vs Botan)
 *   2. HMAC-SHA256 (WebCrypto vs Botan)
 */
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

// Load hash-wasm
const hashwasmPath = path.join(__dirname, '..', 'vendor', 'argon2.umd.min.js');
const hashwasmCode = fs.readFileSync(hashwasmPath, 'utf8');
// UMD build sets `self.hashwasm` or `exports`; patch for Node
const self = {};
const fn = new Function('self', 'exports', 'module', hashwasmCode);
const mod = { exports: {} };
fn(self, mod.exports, mod);
const hashwasm = self.hashwasm || mod.exports;

// Load test vectors
const vectors = JSON.parse(fs.readFileSync(path.join(__dirname, 'test_vectors.json'), 'utf8'));

function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
}

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join('');
}

async function testKEK() {
    console.log('=== Test 1: Argon2id KEK derivation ===');
    console.log('Password:', vectors.password);
    console.log('Salt:', vectors.salt);
    console.log('Params: m=' + vectors.kdf_m_kib + ' KiB, t=' + vectors.kdf_t + ', p=' + vectors.kdf_p);

    const salt = hexToBytes(vectors.salt);

    const kek = await hashwasm.argon2id({
        password: vectors.password,
        salt: salt,
        parallelism: vectors.kdf_p,
        iterations: vectors.kdf_t,
        memorySize: vectors.kdf_m_kib,
        hashLength: 32,
        outputType: 'binary',
    });

    const kekHex = bytesToHex(new Uint8Array(kek));
    const expected = vectors.expected_kek;

    console.log('Expected KEK:', expected);
    console.log('Got KEK:     ', kekHex);

    if (kekHex === expected) {
        console.log('PASS: KEK matches\n');
        return new Uint8Array(kek);
    } else {
        console.log('FAIL: KEK mismatch\n');
        process.exit(1);
    }
}

async function testHMAC(kek) {
    console.log('=== Test 2: HMAC-SHA256 ===');

    const hmacInput = hexToBytes(vectors.hmac_input);
    const expected = vectors.expected_hmac;

    // Use Node.js crypto (same algorithm as WebCrypto, which isn't available in Node)
    const hmac = crypto.createHmac('sha256', kek);
    hmac.update(hmacInput);
    const result = hmac.digest();
    const resultHex = bytesToHex(new Uint8Array(result));

    console.log('Expected HMAC:', expected);
    console.log('Got HMAC:     ', resultHex);

    if (resultHex === expected) {
        console.log('PASS: HMAC matches\n');
    } else {
        console.log('FAIL: HMAC mismatch\n');
        process.exit(1);
    }
}

async function main() {
    const kek = await testKEK();
    await testHMAC(kek);
    console.log('All cross-implementation tests PASSED');
}

main().catch(e => {
    console.error('Test error:', e);
    process.exit(1);
});
