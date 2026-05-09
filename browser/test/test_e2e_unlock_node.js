/**
 * End-to-end unlock test: open real container → derive KEK → verify HMAC → unwrap DEK.
 * Usage: node test/test_e2e_unlock_node.js <container.scef> <password>
 */
const fs = require('fs');
const cryptoNode = require('crypto');
const path = require('path');
const vm = require('vm');

// Load hash-wasm
const hashwasmPath = path.join(__dirname, '..', 'vendor', 'argon2.umd.min.js');
const hashwasmCode = fs.readFileSync(hashwasmPath, 'utf8');
const self = {};
const fn = new Function('self', 'exports', 'module', hashwasmCode);
const mod = { exports: {} };
fn(self, mod.exports, mod);
const hashwasm = self.hashwasm || mod.exports;

// Load header.js
const headerCode = fs.readFileSync(path.join(__dirname, '..', 'src', 'header.js'), 'utf8');
const wrapped = '(function() {\n' + headerCode + '\nreturn { SCEF, computeSlotOffsets, parseHeader, validateKdfParams };\n})()';
const { SCEF, computeSlotOffsets, parseHeader, validateKdfParams } = eval(wrapped);

// Args
const containerPath = process.argv[2];
const password = process.argv[3];
if (!containerPath || !password) {
    console.error('Usage: node test_e2e_unlock_node.js <container.scef> <password>');
    process.exit(1);
}

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join('');
}

async function main() {
    // Read container
    const buf = fs.readFileSync(containerPath);
    const ab = new ArrayBuffer(buf.length);
    new Uint8Array(ab).set(buf);

    console.log('Container size:', buf.length);

    // Find valid slot
    const offsets = computeSlotOffsets(buf.length, SCEF.HEADER_SIZE);
    let header = null;
    let slotIndex = -1;
    for (let i = 0; i < SCEF.SLOT_COUNT; i++) {
        const h = parseHeader(ab.slice(offsets[i], offsets[i] + SCEF.HEADER_SIZE));
        if (h) { header = h; slotIndex = i; break; }
    }
    if (!header) { console.log('FAIL: no valid slot'); process.exit(1); }
    console.log('Active slot:', slotIndex);
    console.log('KDF: m=' + header.kdfMKib + ' KiB, t=' + header.kdfT + ', p=' + header.kdfP);

    // Step 1: Derive KEK
    console.log('\n--- Step 1: Derive KEK (Argon2id) ---');
    const t0 = Date.now();
    const kek = new Uint8Array(await hashwasm.argon2id({
        password: password,
        salt: header.salt,
        parallelism: header.kdfP,
        iterations: header.kdfT,
        memorySize: header.kdfMKib,
        hashLength: 32,
        outputType: 'binary',
    }));
    console.log('KEK derived in', (Date.now() - t0), 'ms');
    console.log('KEK:', bytesToHex(kek));

    // Step 2: Verify HMAC
    console.log('\n--- Step 2: Verify HMAC ---');
    const hmac = cryptoNode.createHmac('sha256', kek);
    hmac.update(header.hmacProtectedBytes);
    const computedHmac = new Uint8Array(hmac.digest());
    const storedHmac = header.headerHmac;

    console.log('Computed HMAC:', bytesToHex(computedHmac));
    console.log('Stored HMAC: ', bytesToHex(storedHmac));

    const match = cryptoNode.timingSafeEqual(
        Buffer.from(computedHmac),
        Buffer.from(storedHmac)
    );
    if (!match) {
        console.log('FAIL: HMAC mismatch — wrong password or corrupted');
        process.exit(1);
    }
    console.log('PASS: HMAC verified');

    // Step 3: Unwrap DEK (AES-256-GCM)
    console.log('\n--- Step 3: Unwrap DEK ---');
    // Node.js crypto.createDecipheriv for AES-256-GCM
    const decipher = cryptoNode.createDecipheriv('aes-256-gcm', kek, header.dekNonce);
    decipher.setAuthTag(Buffer.from(header.dekAuthTag));
    let dek = decipher.update(Buffer.from(header.encryptedDek));
    try {
        const final = decipher.final();
        dek = Buffer.concat([dek, final]);
    } catch (e) {
        console.log('FAIL: DEK unwrap failed —', e.message);
        process.exit(1);
    }
    console.log('DEK:', bytesToHex(new Uint8Array(dek)));
    console.log('PASS: DEK unwrapped successfully');

    console.log('\n=== All steps PASSED — container unlocked ===');
}

main().catch(e => {
    console.error('Error:', e);
    process.exit(1);
});
