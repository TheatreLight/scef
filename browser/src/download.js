/**
 * SCEF Browser Viewer — Download module.
 * Decrypts file chunks with slot-skipping logic, triggers download.
 *
 * Two download modes:
 *   - Streaming (File System Access API): decrypt → write chunks to disk directly.
 *     No file size limit. Works in Chrome/Edge.
 *   - Blob fallback: decrypt → assemble in memory → download.
 *     Limited to MAX_BLOB_SIZE. Works in all browsers.
 *
 * Mirrors C++ FileManager::readChunks() + skipSlots().
 */

// Blob download memory limit (decrypted data + assembled array + Blob copy).
const MAX_BLOB_SIZE = 500 * 1024 * 1024; // 500 MiB

/**
 * Check if File System Access API (streaming writes) is available.
 */
function hasStreamingSupport() {
    return typeof window.showSaveFilePicker === 'function';
}

/**
 * Skip past any slot area that the position falls inside.
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
 * Buffered reader: loads large blocks from the File and serves
 * individual chunk reads from the in-memory buffer.
 * Reduces async file.slice() calls from one-per-chunk to one-per-N-MiB.
 */
const READ_AHEAD_SIZE = 8 * 1024 * 1024; // 8 MiB

function createBufferedReader(file, slotOffsets, slotReservedSize) {
    let bufData = null;   // Uint8Array of current loaded block
    let bufStart = -1;    // file offset where bufData starts
    let bufEnd = -1;      // file offset where bufData ends

    async function ensureLoaded(filePos, needed) {
        if (bufData && filePos >= bufStart && filePos + needed <= bufEnd) {
            return; // already in buffer
        }
        if (filePos >= file.size) {
            throw new Error('Read past end of container at offset ' + filePos);
        }
        const available = file.size - filePos;
        if (needed > available) {
            throw new Error('Read beyond container end: need ' + needed +
                ' bytes at offset ' + filePos + ' but only ' + available + ' remain');
        }
        const readSize = Math.min(Math.max(needed, READ_AHEAD_SIZE), available);
        const slice = file.slice(filePos, filePos + readSize);
        bufData = new Uint8Array(await slice.arrayBuffer());
        bufStart = filePos;
        bufEnd = filePos + readSize;
    }

    function getBytes(filePos, size) {
        const offset = filePos - bufStart;
        return bufData.subarray(offset, offset + size);
    }

    /**
     * Read `size` bytes starting at `startPos`, skipping slot areas.
     * Uses buffer; only does async I/O when buffer doesn't cover the range.
     */
    async function readFragmentedBuffered(startPos, size) {
        const result = new Uint8Array(size);
        let totalRead = 0;
        let pos = startPos;

        while (totalRead < size) {
            pos = skipSlots(pos, slotOffsets, slotReservedSize);
            const canRead = bytesUntilNextSlot(pos, size - totalRead, slotOffsets);

            await ensureLoaded(pos, canRead);
            result.set(getBytes(pos, canRead), totalRead);

            totalRead += canRead;
            pos += canRead;
        }

        return { data: result, endPos: pos };
    }

    return { readFragmentedBuffered };
}

/**
 * Decrypt a file and collect all chunks in memory.
 * For small files (Blob download path).
 */
async function decryptFileToMemory(containerFile, header, fileEntry, dekKey, slotOffsets, progressPrefix) {
    const blockSize = header.blockSize;
    const slotReservedSize = header.headerSize + header.maxTableSize;
    const prefix = progressPrefix || '';
    const reader = createBufferedReader(containerFile, slotOffsets, slotReservedSize);

    const decryptedChunks = [];
    let pos = fileEntry.offset;
    let remaining = fileEntry.size;
    let lastReportedPct = -1;

    for (let i = 0; i < fileEntry.chunks; i++) {
        const plainSize = Math.min(remaining, blockSize);
        const encSize = plainSize + SCEF.NONCE_SIZE + SCEF.AUTH_TAG_SIZE;

        const { data: encData, endPos } = await reader.readFragmentedBuffered(pos, encSize);
        pos = endPos;

        const plainData = await decryptChunk(dekKey, encData);
        decryptedChunks.push(plainData);
        remaining -= plainSize;

        const pct = Math.round(((i + 1) / fileEntry.chunks) * 100);
        if (pct > lastReportedPct) {
            lastReportedPct = pct;
            UI.status(prefix + 'Decrypting ' + fileEntry.name + '... ' + pct + '%', 'info');
        }
    }

    // Assemble
    const totalSize = decryptedChunks.reduce((s, c) => s + c.length, 0);
    const assembled = new Uint8Array(totalSize);
    let offset = 0;
    for (const chunk of decryptedChunks) {
        assembled.set(chunk, offset);
        offset += chunk.length;
    }

    // Verify SHA-256 (browser viewer supports SHA-256 containers only)
    const hash = await sha256hex(assembled);
    if (hash !== fileEntry.checksum) {
        throw new Error('Checksum mismatch for ' + fileEntry.name +
            ': expected ' + fileEntry.checksum + ', got ' + hash);
    }

    return assembled;
}

/**
 * Decrypt a file and stream chunks directly to disk via File System Access API.
 * Memory usage: only one 64 KiB chunk at a time + SHA-256 state.
 * No file size limit.
 */
async function decryptFileStreaming(containerFile, header, fileEntry, dekKey, slotOffsets, writable, progressPrefix) {
    const blockSize = header.blockSize;
    const slotReservedSize = header.headerSize + header.maxTableSize;
    const prefix = progressPrefix || '';
    const reader = createBufferedReader(containerFile, slotOffsets, slotReservedSize);

    // Streaming SHA-256 via hash-wasm — incremental update per chunk
    const hasher = await hashwasm.createSHA256();
    hasher.init();

    let pos = fileEntry.offset;
    let remaining = fileEntry.size;
    let lastReportedPct = -1;

    for (let i = 0; i < fileEntry.chunks; i++) {
        const plainSize = Math.min(remaining, blockSize);
        const encSize = plainSize + SCEF.NONCE_SIZE + SCEF.AUTH_TAG_SIZE;

        const { data: encData, endPos } = await reader.readFragmentedBuffered(pos, encSize);
        pos = endPos;

        const plainData = await decryptChunk(dekKey, encData);
        hasher.update(plainData);
        await writable.write(plainData);
        remaining -= plainSize;

        const pct = Math.round(((i + 1) / fileEntry.chunks) * 100);
        if (pct > lastReportedPct) {
            lastReportedPct = pct;
            UI.status(prefix + 'Decrypting ' + fileEntry.name + '... ' + pct + '%', 'info');
        }
    }

    // Verify whole-file SHA-256 checksum (browser viewer supports SHA-256 containers only)
    const hash = hasher.digest('hex').toUpperCase();
    if (hash !== fileEntry.checksum) {
        throw new Error('Checksum mismatch for ' + fileEntry.name +
            ': expected ' + fileEntry.checksum + ', got ' + hash);
    }
}

/**
 * Download a single file. Uses streaming if available, Blob fallback otherwise.
 */
async function downloadFile(containerFile, header, fileEntry, dekKey, slotOffsets) {
    // Try streaming for large files or when API is available
    if (hasStreamingSupport()) {
        try {
            const handle = await window.showSaveFilePicker({
                suggestedName: fileEntry.name,
            });
            const writable = await handle.createWritable();
            try {
                UI.status('Writing ' + fileEntry.name + ' to disk...', 'info');
                await decryptFileStreaming(containerFile, header, fileEntry, dekKey, slotOffsets, writable);
                await writable.close();
                UI.status('Downloaded ' + fileEntry.name + ' (' + formatSize(fileEntry.size) + '), checksum verified.', 'success');
                return;
            } catch (err) {
                await writable.abort();
                throw err;
            }
        } catch (err) {
            // User cancelled the save dialog
            if (err.name === 'AbortError') {
                UI.status('Download cancelled.', 'info');
                return;
            }
            // SecurityError — API not available in this context (file://), fall through to Blob
            if (err.name !== 'SecurityError') {
                throw err;
            }
        }
    }

    // Blob fallback — check size limit
    if (fileEntry.size > MAX_BLOB_SIZE) {
        throw new Error(fileEntry.name + ' is ' + formatSize(fileEntry.size) +
            ' — too large for this browser. Use Chrome/Edge for large files, or the native CLI.');
    }

    const data = await decryptFileToMemory(containerFile, header, fileEntry, dekKey, slotOffsets);
    triggerBlobDownload(data, fileEntry.name);
    UI.status('Downloaded ' + fileEntry.name + ' (' + formatSize(data.length) + '), checksum verified.', 'success');
}

/**
 * Decrypt all files and download as a single .zip archive.
 */
async function downloadAllAsZip(containerFile, header, files, dekKey, slotOffsets) {
    const totalSize = files.reduce((s, f) => s + f.size, 0);
    if (totalSize > MAX_BLOB_SIZE) {
        throw new Error('Total size ' + formatSize(totalSize) +
            ' exceeds browser limit (' + formatSize(MAX_BLOB_SIZE) +
            '). Download files individually or use the native CLI.');
    }
    const zip = new JSZip();

    for (let i = 0; i < files.length; i++) {
        const prefix = '[' + (i + 1) + '/' + files.length + '] ';
        const data = await decryptFileToMemory(containerFile, header, files[i], dekKey, slotOffsets, prefix);
        // Strip path components to prevent traversal (e.g. ../etc/passwd) in the ZIP.
        // Mirrors C++ extract() which uses std::filesystem::path::filename().
        const safeName = files[i].name.split('/').pop().split('\\').pop() || files[i].name;
        zip.file(safeName, data);
    }

    UI.status('Creating ZIP archive...', 'info');
    const blob = await zip.generateAsync({ type: 'blob' });
    triggerBlobDownload(blob, 'scef_files.zip');
    UI.status('All ' + files.length + ' file(s) extracted as scef_files.zip.', 'success');
}

/**
 * Trigger browser download of a Blob or Uint8Array via <a> element.
 */
function triggerBlobDownload(data, filename) {
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
