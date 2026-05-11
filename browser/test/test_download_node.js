/**
 * End-to-end download test: open container → unlock → decrypt chunks → verify SHA-256.
 * Usage: node test/test_download_node.js <container.scef> <password>
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

// Load download.js for skipSlots/bytesUntilNextSlot
const downloadCode = fs.readFileSync(path.join(__dirname, '..', 'src', 'download.js'), 'utf8');
const { skipSlots, bytesUntilNextSlot } = eval(
    '(function() {\n' + downloadCode + '\nreturn { skipSlots, bytesUntilNextSlot };\n})()'
);

// Args
const containerPath = process.argv[2];
const password = process.argv[3];
if (!containerPath || !password) {
    console.error('Usage: node test_download_node.js <container.scef> <password>');
    process.exit(1);
}

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join('');
}

/**
 * readFragmented for Node — reads from Buffer with slot-skipping.
 */
function readFragmentedNode(containerBuf, startPos, size, slotOffsets, slotReservedSize) {
    const result = Buffer.alloc(size);
    let totalRead = 0;
    let pos = startPos;

    while (totalRead < size) {
        pos = skipSlots(pos, slotOffsets, slotReservedSize);
        const canRead = bytesUntilNextSlot(pos, size - totalRead, slotOffsets);
        containerBuf.copy(result, totalRead, pos, pos + canRead);
        totalRead += canRead;
        pos += canRead;
    }

    return { data: new Uint8Array(result), endPos: pos };
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

    // Derive KEK + unwrap DEK
    const kek = new Uint8Array(await hashwasm.argon2id({
        password, salt: header.salt,
        parallelism: header.kdfP, iterations: header.kdfT,
        memorySize: header.kdfMKib, hashLength: 32, outputType: 'binary',
    }));

    const decipher = cryptoNode.createDecipheriv('aes-256-gcm', kek, header.dekNonce);
    decipher.setAuthTag(Buffer.from(header.dekAuthTag));
    let dekBuf = decipher.update(Buffer.from(header.encryptedDek));
    dekBuf = Buffer.concat([dekBuf, decipher.final()]);
    const dek = new Uint8Array(dekBuf);

    // Decrypt file table
    const encSize = header.fileTableSize;
    const tableOffset = offsets[slotIndex] + header.headerSize;
    const encTable = new Uint8Array(ab.slice(tableOffset, tableOffset + encSize));

    const ftNonce = encTable.slice(0, SCEF.NONCE_SIZE);
    const ftCtTag = encTable.slice(SCEF.NONCE_SIZE);
    const ftCt = ftCtTag.slice(0, ftCtTag.length - SCEF.AUTH_TAG_SIZE);
    const ftTag = ftCtTag.slice(ftCtTag.length - SCEF.AUTH_TAG_SIZE);

    const ftDec = cryptoNode.createDecipheriv('aes-256-gcm', dek, ftNonce);
    ftDec.setAuthTag(Buffer.from(ftTag));
    let ftPlain = ftDec.update(Buffer.from(ftCt));
    ftPlain = Buffer.concat([ftPlain, ftDec.final()]);
    const fileTable = JSON.parse(ftPlain.toString('utf-8'));

    console.log('Files in container:', fileTable.files.length);

    if (header.hashAlgoId !== SCEF.HASH_SHA_256) {
        console.warn(`WARNING: test_download_node.js only verifies SHA-256 checksums. ` +
            `Container has hashAlgoId=0x${header.hashAlgoId.toString(16).padStart(2,'0')}; ` +
            `skipping checksum verification.`);
    }

    // Decrypt each file and verify checksum (only when hash_algo_id == 0x01)
    const slotReservedSize = header.headerSize + header.maxTableSize;
    let allPassed = true;

    for (const file of fileTable.files) {
        console.log('\n--- Downloading: ' + file.name + ' ---');
        console.log('  Size:', file.size, 'bytes, Chunks:', file.chunks, ', Offset:', file.offset);

        const chunks = [];
        let pos = file.offset;
        let remaining = file.size;

        for (let i = 0; i < file.chunks; i++) {
            const plainSize = Math.min(remaining, header.blockSize);
            const chunkEncSize = plainSize + SCEF.NONCE_SIZE + SCEF.AUTH_TAG_SIZE;

            const { data: encData, endPos } = readFragmentedNode(
                buf, pos, chunkEncSize, offsets, slotReservedSize
            );
            pos = endPos;

            // Decrypt chunk
            const nonce = encData.slice(0, SCEF.NONCE_SIZE);
            const ctTag = encData.slice(SCEF.NONCE_SIZE);
            const ct = ctTag.slice(0, ctTag.length - SCEF.AUTH_TAG_SIZE);
            const tag = ctTag.slice(ctTag.length - SCEF.AUTH_TAG_SIZE);

            const chunkDec = cryptoNode.createDecipheriv('aes-256-gcm', dek, nonce);
            chunkDec.setAuthTag(Buffer.from(tag));
            let plain = chunkDec.update(Buffer.from(ct));
            plain = Buffer.concat([plain, chunkDec.final()]);
            chunks.push(plain);

            remaining -= plainSize;
        }

        // Assemble and verify SHA-256 (only when hash_algo_id == 0x01)
        const assembled = Buffer.concat(chunks);
        if (header.hashAlgoId === SCEF.HASH_SHA_256) {
            const hash = cryptoNode.createHash('sha256').update(assembled).digest('hex').toUpperCase();

            console.log('  Expected checksum:', file.checksum);
            console.log('  Got SHA-256:     ', hash);

            if (hash === file.checksum) {
                console.log('  PASS: checksum matches');
                console.log('  Content preview:', assembled.toString('utf-8').substring(0, 80));
            } else {
                console.log('  FAIL: checksum mismatch');
                allPassed = false;
            }
        } else {
            console.log('  Checksum verification skipped (non-SHA-256 hash algorithm)');
            console.log('  Content preview:', assembled.toString('utf-8').substring(0, 80));
        }
    }

    console.log('\n' + (allPassed ? 'All files PASSED' : 'Some files FAILED'));
    if (!allPassed) process.exit(1);
}

main().catch(e => {
    console.error('Error:', e);
    process.exit(1);
});
