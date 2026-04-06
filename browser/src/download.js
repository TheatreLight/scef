/**
 * SCEF Browser Viewer — Download module.
 * Decrypts file chunks with slot-skipping logic, assembles Blob, triggers download.
 *
 * Mirrors C++ FileManager::readChunks() + readFragmented() + skipSlots().
 */

/**
 * Skip past any slot area that the position falls inside.
 * Mirrors C++ FileManager::skipSlots().
 *
 * @param {number} pos - current byte position
 * @param {number[]} slotOffsets - 4 slot offsets
 * @param {number} slotReservedSize - headerSize + maxTableSize
 * @returns {number} adjusted position (same or past the slot)
 */
function skipSlots(pos, slotOffsets, slotReservedSize) {
    for (const slot of slotOffsets) {
        if (pos >= slot && pos < slot + slotReservedSize) {
            return slot + slotReservedSize;
        }
    }
    return pos;
}

/**
 * Limit the read size so it doesn't cross into the next slot.
 * Mirrors C++ FileManager::bytesUntilNextSlot().
 *
 * @param {number} cur - current byte position (already past any slot)
 * @param {number} remaining - bytes left to read
 * @param {number[]} slotOffsets - 4 slot offsets (sorted ascending)
 * @returns {number} bytes that can be read contiguously
 */
function bytesUntilNextSlot(cur, remaining, slotOffsets) {
    for (const slot of slotOffsets) {
        if (slot > cur) {
            return Math.min(remaining, slot - cur);
        }
    }
    return remaining;
}

/**
 * Read `size` bytes from the container File starting at `startPos`,
 * skipping over slot reserved areas. Returns contiguous Uint8Array.
 *
 * Mirrors C++ FileManager::readFragmented().
 *
 * @param {File} file - container File
 * @param {number} startPos - logical start position
 * @param {number} size - total bytes to read
 * @param {number[]} slotOffsets - 4 slot offsets
 * @param {number} slotReservedSize - headerSize + maxTableSize
 * @returns {Promise<{data: Uint8Array, endPos: number}>}
 */
async function readFragmented(file, startPos, size, slotOffsets, slotReservedSize) {
    const result = new Uint8Array(size);
    let totalRead = 0;
    let pos = startPos;

    while (totalRead < size) {
        pos = skipSlots(pos, slotOffsets, slotReservedSize);
        const canRead = bytesUntilNextSlot(pos, size - totalRead, slotOffsets);

        const slice = file.slice(pos, pos + canRead);
        const chunk = new Uint8Array(await slice.arrayBuffer());
        result.set(chunk, totalRead);

        totalRead += canRead;
        pos += canRead;
    }

    return { data: result, endPos: pos };
}

/**
 * Decrypt a single file from the container into a Uint8Array.
 * Verifies SHA-256 checksum. Throws on failure.
 *
 * @param {File} containerFile - container File object
 * @param {object} header - parsed header
 * @param {object} fileEntry - { name, size, offset, chunks, checksumSha256 }
 * @param {Uint8Array} dek - 32-byte DEK
 * @param {number[]} slotOffsets - 4 slot offsets
 * @param {string} [progressPrefix] - optional prefix for status messages
 * @returns {Promise<Uint8Array>} decrypted and verified file data
 */
async function decryptFile(containerFile, header, fileEntry, dek, slotOffsets, progressPrefix) {
    const blockSize = header.blockSize;
    const slotReservedSize = header.headerSize + header.maxTableSize;
    const prefix = progressPrefix || '';

    const decryptedChunks = [];
    let pos = fileEntry.offset;
    let remaining = fileEntry.size;

    for (let i = 0; i < fileEntry.chunks; i++) {
        const plainSize = Math.min(remaining, blockSize);
        const encSize = plainSize + SCEF.NONCE_SIZE + SCEF.AUTH_TAG_SIZE;

        const { data: encData, endPos } = await readFragmented(
            containerFile, pos, encSize, slotOffsets, slotReservedSize
        );
        pos = endPos;

        const plainData = await decryptChunk(dek, encData);
        decryptedChunks.push(plainData);
        remaining -= plainSize;

        const pct = Math.round(((i + 1) / fileEntry.chunks) * 100);
        UI.status(prefix + 'Decrypting ' + fileEntry.name + '... ' + pct + '%', 'info');
    }

    // Assemble
    const totalSize = decryptedChunks.reduce((s, c) => s + c.length, 0);
    const assembled = new Uint8Array(totalSize);
    let offset = 0;
    for (const chunk of decryptedChunks) {
        assembled.set(chunk, offset);
        offset += chunk.length;
    }

    // Verify SHA-256
    const hash = await sha256hex(assembled);
    if (hash !== fileEntry.checksumSha256) {
        throw new Error('Checksum mismatch for ' + fileEntry.name +
            ': expected ' + fileEntry.checksumSha256 + ', got ' + hash);
    }

    return assembled;
}

/**
 * Download a single file from the container.
 */
async function downloadFile(containerFile, header, fileEntry, dek, slotOffsets) {
    const data = await decryptFile(containerFile, header, fileEntry, dek, slotOffsets);
    triggerDownload(data, fileEntry.name);
    UI.status('Downloaded ' + fileEntry.name + ' (' + formatSize(data.length) + '), checksum verified.', 'success');
}

/**
 * Decrypt all files and download as a single .zip archive.
 */
async function downloadAllAsZip(containerFile, header, files, dek, slotOffsets) {
    const zip = new JSZip();

    for (let i = 0; i < files.length; i++) {
        const prefix = '[' + (i + 1) + '/' + files.length + '] ';
        const data = await decryptFile(containerFile, header, files[i], dek, slotOffsets, prefix);
        zip.file(files[i].name, data);
    }

    UI.status('Creating ZIP archive...', 'info');
    const blob = await zip.generateAsync({ type: 'blob' });
    triggerDownload(blob, 'scef_files.zip');
    UI.status('All ' + files.length + ' file(s) extracted as scef_files.zip.', 'success');
}

/**
 * Trigger browser download of a Blob or Uint8Array.
 */
function triggerDownload(data, filename) {
    const blob = data instanceof Blob ? data : new Blob([data]);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}
