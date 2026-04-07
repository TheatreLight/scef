/**
 * Quick Node.js test for header.js — verifies parsing against a real container.
 * Usage: node test/test_header_node.js <path_to_container.scef>
 */
const fs = require('fs');
const vm = require('vm');

// Load header.js — wrap in a function to capture exports since const/function
// declarations in vm strict mode don't leak to the context object.
const headerCode = fs.readFileSync(__dirname + '/../src/header.js', 'utf8');
const wrapped = '(function() {\n' + headerCode + '\nreturn { SCEF, computeSlotOffsets, parseHeader, validateKdfParams };\n})()';
const { SCEF, computeSlotOffsets, parseHeader, validateKdfParams } = eval(wrapped);

const containerPath = process.argv[2];
if (!containerPath) {
    console.error('Usage: node test_header_node.js <container.scef>');
    process.exit(1);
}

const buf = fs.readFileSync(containerPath);
// Node Buffer may share underlying ArrayBuffer with other data, so copy it.
const ab = new ArrayBuffer(buf.length);
new Uint8Array(ab).set(buf);

const offsets = computeSlotOffsets(buf.length, SCEF.HEADER_SIZE);
console.log('Container size:', buf.length);
console.log('Slot offsets:', offsets);

const header = parseHeader(ab.slice(0, SCEF.HEADER_SIZE));
if (!header) {
    console.log('ERROR: header parse failed at slot 0');
    process.exit(1);
}

console.log('--- Parsed header (slot 0) ---');
console.log('Version:', header.versionMajor + '.' + header.versionMinor);
console.log('Cipher:', header.cipherId === 1 ? 'AES-256-GCM' : header.cipherId === 2 ? 'Kuznechik-GCM' : 'unknown');
console.log('KDF:', header.kdfMKib, 'KiB (' + (header.kdfMKib / 1024) + ' MiB), t=' + header.kdfT + ', p=' + header.kdfP);
console.log('Container size (header):', header.containerSize);
console.log('File count:', header.fileCount);
console.log('File table size:', header.fileTableSize);
console.log('Max table size:', header.maxTableSize);
console.log('Block size:', header.blockSize);
console.log('Header version:', header.headerVersion);
console.log('Salt:', Buffer.from(header.salt).toString('hex'));
console.log('KDF validation:', validateKdfParams(header) || 'OK');

// Match container size
if (header.containerSize !== buf.length) {
    console.log('WARNING: header.containerSize (' + header.containerSize + ') != file size (' + buf.length + ')');
}

// Try all 4 slots
console.log('\n--- Slot scan ---');
let validCount = 0;
for (let i = 0; i < SCEF.SLOT_COUNT; i++) {
    const off = offsets[i];
    if (off + SCEF.HEADER_SIZE > buf.length) {
        console.log('Slot ' + i + ' (offset ' + off + '): out of bounds');
        continue;
    }
    const h = parseHeader(ab.slice(off, off + SCEF.HEADER_SIZE));
    const status = h ? 'VALID' : 'invalid';
    if (h) validCount++;
    console.log('Slot ' + i + ' (offset ' + off + '): ' + status);
}

console.log('\nResult: ' + validCount + '/4 slots valid');
if (validCount === 4) {
    console.log('SUCCESS: All slots parsed correctly');
} else if (validCount > 0) {
    console.log('PARTIAL: Some slots are valid (expected for non-corrupted container: 4/4)');
} else {
    console.log('FAILURE: No valid slots found');
    process.exit(1);
}
