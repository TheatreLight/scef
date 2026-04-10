# Data Flows

## Key Derivation Flow

```mermaid
flowchart TD
    PW["User password (std::string)"]
    SALT["32-byte random salt\n(CryptoManager::generateSalt)"]
    ARGON["Argon2id KDF\n(Botan::PasswordHashFamily)\nm_kib, t, p from header"]
    KEK["32-byte KEK\nkey-encryption key\nkek_ in CryptoManager"]
    SCRUB["Botan::secure_scrub_memory\n(password zeroed)"]
    PW --> ARGON
    SALT --> ARGON
    ARGON --> KEK
    PW --> SCRUB
```

Source: `src/CryptoManager.cpp:26-41`, `src/FileManager.cpp:179-233`

On **create**: salt is generated fresh, then KEK is derived. Password is zeroed immediately after `deriveKek()` returns.

On **open**: salt and KDF params are read from the first magic-valid slot header. Password is zeroed after derivation. At most 2 derivations per open (corruption recovery case).

---

## Container Creation Flow

```mermaid
flowchart TD
    A["FileManager::write()"]
    B["createContainerFile()\npre-allocate to container_size bytes\n(seek to last byte, write 0x00)"]
    C["initCryptoForCreate()\ngenerateSalt → deriveKek → zero password\nwrapDek → setDekNonce/EncryptedDek/Tag"]
    D["computeAndStoreHeaderHmac()\nheader.serialize() → HMAC-SHA256(bytes[0..0x9F]) → storeHmac"]
    E["writeAllSlots()\nwrite Header + empty FileTable at all 4 slot offsets"]
    F["writeChunks(dataStart)\nfor each file in filesList_:\n  open file, loop over BLOCK_SIZE chunks:\n    updateChecksum(chunk)\n    crypto->encrypt(chunk) → writeFragmented()"]
    G["fileTable.setNextWriteOffset(endPos)"]
    H["writeFileTableToAllSlots()\nserialize JSON → encrypt → write Header+Table at all 4 slots\nincrementHeaderVersion + recompute HMAC"]

    A --> B --> C --> D --> E --> F --> G --> H
```

Source: `src/FileManager.cpp:643-670`

### writeChunks detail

For each file:
1. Open source file for reading.
2. `fileTable_.resetChecksum()`.
3. Read up to `BLOCK_SIZE` bytes at a time.
4. `fileTable_.updateChecksum(chunk)` — feeds SHA-256 hasher.
5. `crypto_->encrypt(chunk, encBuf, chunkSize)` — writes `[nonce 12B][ciphertext][tag 16B]`.
6. `writeFragmented(encBuf)` — writes to container, skipping slot areas.
7. After all chunks: `fileTable_.getChecksum()` — hex SHA-256 of plaintext.
8. `fileTable_.addFileEntry(path, checksum, startOffset, actualSize)`.

---

## Add File Flow

```mermaid
flowchart TD
    A["FileManager::add()"]
    B["Resume from fileTable_.getNextWriteOffset()\ncompute free capacity"]
    C["Validate: required encrypted bytes <= free capacity"]
    D["writeChunks(dataEnd)\nappend new file chunks, same logic as create"]
    E["writeFileTableToAllSlots()\nupdate all 4 slots with new file entry"]

    A --> B --> C --> D --> E
```

The `next_write_offset` field in the file table JSON is persisted so `add()` can resume without scanning the entire container.

Source: `src/FileManager.cpp:672-730`

---

## Open Container (readMeta) Flow

```mermaid
flowchart TD
    A["FileManager::readMeta()"]
    B["Compute 4 slot offsets from file size"]
    C["For slot i in 0..3:\nread 4096 bytes → check magic"]
    D{Magic valid?}
    E["slotsWithValidMagic++"]
    F{KEK derived\nfor this slot's\nsalt+params?}
    G["validateKdfParamsAndDeriveKek()\nArgon2id → zero password"]
    H["verifyHeaderHmac()\nconstant_time_compare"]
    I{HMAC OK?}
    J["unwrapDekFromHeader()\nAES-256-GCM decrypt DEK"]
    K["activeSlotOffset_ = slotOff\nrecovered = true → break"]
    L["log error, try next slot"]
    M{recovered?}
    N["readFilesTable()"]
    O["throw: wrong password / corrupted"]

    A --> B --> C --> D
    D -->|No| C
    D -->|Yes| E --> F
    F -->|No| G --> H
    F -->|Yes| H
    H --> I
    I -->|No| L --> C
    I -->|Yes| J --> K --> M
    M -->|Yes| N
    M -->|No| O
```

Source: `src/FileManager.cpp:417-582`

---

## Extract Flow

```mermaid
flowchart TD
    A["FileManager::extract(outputFolder)"]
    B{filesList_ empty?}
    C["Extract all files from fileTable_"]
    D["Extract only requested file names"]
    E["For each file:\nsafeFilename = path.filename()\nopen output file"]
    F["readChunks(output, fileEntry)\nfor each chunk:\n  seek to skipSlots(offset)\n  read NONCE_SIZE + plainSize + AUTH_TAG_SIZE\n  crypto->decrypt(encBuf) → write to output"]
    G["checkSumVerify(fileEntry)\ncompute SHA-256 of decrypted output\ncompare to fileEntry.checksum_sha256"]
    H{Match?}
    I["log warning (output file kept)"]
    J["file extracted OK"]

    A --> B
    B -->|Yes| C --> E
    B -->|No| D --> E
    E --> F --> G --> H
    H -->|No| I
    H -->|Yes| J
```

Source: `src/FileManager.cpp:584-641`

---

## Header Sync Flow (after every write)

```mermaid
flowchart TD
    A["Data written to container\nor file table changed"]
    B["header_.incrementHeaderVersion()"]
    C["fileTable_.serialize() → JSON string"]
    D["crypto_->encrypt(jsonStr) → encTable\nheader_.setFileTableSize(encSize)"]
    E["computeAndStoreHeaderHmac()\nheader_.serialize()\nHMAC(bytes[0..0x9F]) → header_.storeHmac"]
    F["For i in 0..3:\n  writeHeaderAt(slotOffsets_[i])\n  writeFileTableAt(slotOffsets_[i], encTable)"]
    G["containerStream_->flush()"]

    A --> B --> C --> D --> E --> F --> G
```

Source: `src/FileManager.cpp:389-413`

---

## DEK Wrap/Unwrap

### Wrap (on create)

```mermaid
flowchart TD
    DEK["Generate 32-byte random DEK\n(Botan::AutoSeeded_RNG)"]
    NONCE["Generate 12-byte random nonce"]
    ENC["AES-256-GCM encrypt(key=KEK, iv=nonce, pt=DEK)\noutput: ciphertext(32B) + tag(16B)"]
    STORE["header.setDekNonce\nheader.setEncryptedDek\nheader.setDekAuthTag"]
    DEK --> ENC
    NONCE --> ENC
    ENC --> STORE
```

### Unwrap (on open)

```mermaid
flowchart TD
    LOAD["Read from header:\nnonce, encrypted_dek, dek_auth_tag"]
    DEC["AES-256-GCM decrypt(key=KEK, iv=nonce, ct=enc_dek||tag)"]
    FAIL{Auth OK?}
    OK["Store 32-byte DEK in dek_\ndek_ready_ = true"]
    ERR["throw: Wrong password: DEK authentication failed"]
    LOAD --> DEC --> FAIL
    FAIL -->|Yes| OK
    FAIL -->|No| ERR
```

Source: `src/CryptoManager.cpp:43-115`

---

## Chunk Encryption/Decryption

### Encrypt one chunk

```
Input: plaintext data (up to 65536 bytes)
1. Generate random 12-byte nonce (Botan::AutoSeeded_RNG)
2. AES-256-GCM encrypt(key=DEK, iv=nonce, plaintext)
   → ciphertext (same length as plaintext) + 16-byte auth tag
3. Write: [nonce 12B][ciphertext N B][auth tag 16B]
```

### Decrypt one chunk

```
Input: [nonce 12B][ciphertext N B][auth tag 16B]
1. Read nonce (first 12 bytes)
2. AES-256-GCM decrypt(key=DEK, iv=nonce, ciphertext+tag)
   → plaintext N bytes
   → throws on auth failure (corrupted data)
```

Source: `src/CryptoManager.cpp:136-210`

---

## Browser Unlock Flow

See [browser-viewer.md](browser-viewer.md) for the full JS sequence diagram.

Key differences from native:
- Argon2id via hash-wasm WASM (not Botan)
- AES-256-GCM via WebCrypto API (`crypto.subtle`)
- HMAC-SHA256 via WebCrypto (`HMAC` + `SHA-256`)
- All async (Promises)
- No re-derivation on corruption: derives once, tries all valid slots with the same KEK
- KEK zeroed best-effort (`kek.fill(0)`)
