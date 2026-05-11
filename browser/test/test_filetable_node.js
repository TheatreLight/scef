/**
 * Test file table decryption from a real container.
 * Usage: node test/test_filetable_node.js <container.scef> <password>
 */
const fs = require('fs');
const cryptoNode = require('crypto');
const path = require('path');

// Load hash-wasm
const hashwasmPath = path.join(__dirname, '..', 'vendor', 'argon2.umd.min.js');
const hashwasmCode = fs.readFileSync(hashwasmPath, 'utf8');
const self = {};
const fn = new Function('self', 'exports', 'module', hashwasmCode);
const mod = { exports: {} };
fn(self, mod.exports, mod);
const hashwasm = self.hashwasm || mod.exports;

// Load our modules
const headerCode = fs.readFileSync(path.join(__dirname, '..', 'src', 'header.js'), 'utf8');
const { SCEF, computeSlotOffsets, parseHeader } = eval(
    '(function() {\n' + headerCode + '\nreturn { SCEF, computeSlotOffsets, parseHeader };\n})()'
);

// Args
const containerPath = process.argv[2];
const password = process.argv[3];
if (!containerPath || !password) {
    console.error('Usage: node test_filetable_node.js <container.scef> <password>');
    process.exit(1);
}

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join('');
}

async function main() {
    const buf = fs.readFileSync(containerPath);
    const ab = new ArrayBuffer(buf.length);
    new Uint8Array(ab).set(buf);

    // Find valid slot
    const offsets = computeSlotOffsets(buf.length, SCEF.HEADER_SIZE);
    let header = null;
    let slotIndex = -1;
    for (let i = 0; i < SCEF.SLOT_COUNT; i++) {
        const h = parseHeader(ab.slice(offsets[i], offsets[i] + SCEF.HEADER_SIZE));
        if (h) { header = h; slotIndex = i; break; }
    }
    if (!header) { console.log('FAIL: no valid slot'); process.exit(1); }

    // Derive KEK
    const kek = new Uint8Array(await hashwasm.argon2id({
        password: password,
        salt: header.salt,
        parallelism: header.kdfP,
        iterations: header.kdfT,
        memorySize: header.kdfMKib,
        hashLength: 32,
        outputType: 'binary',
    }));

    // Unwrap DEK using Node crypto
    const decipher = cryptoNode.createDecipheriv('aes-256-gcm', kek, header.dekNonce);
    decipher.setAuthTag(Buffer.from(header.dekAuthTag));
    let dekBuf = decipher.update(Buffer.from(header.encryptedDek));
    dekBuf = Buffer.concat([dekBuf, decipher.final()]);
    const dek = new Uint8Array(dekBuf);
    console.log('DEK:', bytesToHex(dek));

    // Decrypt file table
    const encSize = header.fileTableSize;
    console.log('File table encrypted size:', encSize);

    if (encSize <= SCEF.NONCE_SIZE + SCEF.AUTH_TAG_SIZE) {
        console.log('Empty file table (no files)');
        return;
    }

    const tableOffset = offsets[slotIndex] + header.headerSize;
    const encData = new Uint8Array(ab.slice(tableOffset, tableOffset + encSize));

    // Decrypt: [nonce 12][ciphertext][tag 16]
    const nonce = encData.slice(0, SCEF.NONCE_SIZE);
    const ctAndTag = encData.slice(SCEF.NONCE_SIZE);
    // Node crypto: separate ct and tag
    const ct = ctAndTag.slice(0, ctAndTag.length - SCEF.AUTH_TAG_SIZE);
    const tag = ctAndTag.slice(ctAndTag.length - SCEF.AUTH_TAG_SIZE);

    const dec = cryptoNode.createDecipheriv('aes-256-gcm', dek, nonce);
    dec.setAuthTag(Buffer.from(tag));
    let plain = dec.update(Buffer.from(ct));
    plain = Buffer.concat([plain, dec.final()]);

    const jsonStr = plain.toString('utf-8');
    console.log('File table JSON:', jsonStr);

    const obj = JSON.parse(jsonStr);
    console.log('\n--- Files ---');
    obj.files.forEach((f, i) => {
        console.log('[' + i + '] ' + f.name + ' (' + f.size + ' bytes, ' + f.chunks + ' chunk(s), offset=' + f.offset + ')');
        console.log('    Checksum: ' + f.checksum);
    });
    console.log('next_write_offset:', obj.next_write_offset);

    console.log('\nPASS: File table decrypted and parsed successfully');
}

main().catch(e => {
    console.error('Error:', e);
    process.exit(1);
});
