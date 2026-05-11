/**
 * SCEF Browser Viewer — File Table module.
 * Reads and decrypts the encrypted file table from the active slot.
 *
 * File table layout (immediately after header):
 *   [nonce 12B][JSON ciphertext][auth tag 16B]
 *
 * JSON format (matches FileTable::serialize() in C++):
 *   { "next_write_offset": N, "files": [ { "name", "size", "offset", "chunks", "checksum" } ] }
 */

/**
 * Read and decrypt the file table from the container.
 *
 * @param {File} file - container File object
 * @param {object} header - parsed header
 * @param {number} slotOffset - byte offset of the active slot
 * @param {CryptoKey} dekKey - pre-imported DEK CryptoKey
 * @returns {Promise<object>} parsed file table { nextWriteOffset, files: [...] }
 */
async function readFileTable(file, header, slotOffset, dekKey) {
    const encSize = header.fileTableSize;

    // No files in container
    if (encSize <= SCEF.NONCE_SIZE + SCEF.AUTH_TAG_SIZE) {
        return { nextWriteOffset: 0, files: [] };
    }

    // File table starts right after the header
    const tableOffset = slotOffset + header.headerSize;
    const slice = file.slice(tableOffset, tableOffset + encSize);
    const encBuf = new Uint8Array(await slice.arrayBuffer());

    // Decrypt: encBuf = [nonce 12][ciphertext][tag 16]
    // decryptChunk expects the same layout
    const decrypted = await decryptChunk(dekKey, encBuf);

    // Parse JSON
    const jsonStr = new TextDecoder('utf-8').decode(decrypted);
    const obj = JSON.parse(jsonStr);

    const files = (obj.files || []).map(f => ({
        name:           f.name,
        size:           f.size,
        offset:         f.offset,
        chunks:         f.chunks,
        checksum:       f.checksum,
    }));

    return {
        nextWriteOffset: obj.next_write_offset || 0,
        files: files,
    };
}
