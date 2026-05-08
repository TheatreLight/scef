# SCEF Browser Viewer Review

## Executive Summary

The browser viewer is **substantially correct** and tracks the current C++ core closely for the header binary layout and slot computation. The core cryptographic flow — Argon2id KEK derivation, HMAC-before-decrypt ordering, AES-256-GCM DEK unwrap, per-chunk decryption with auth-tag verification, and slot-skipping during reads — is implemented correctly and mirrors the C++ pipeline. However, there are concrete drift items and quality issues that must be addressed before the container can be opened reliably in all cases: the password input is sent as a raw JS string to hash-wasm when the C++ side sends bytes, the KDF profile table in JS is absent entirely so the viewer cannot display or validate profile names, the file table JSON schema is missing two fields (`created`, `modified`) relative to the planning spec (though the actual C++ serializer omits them too, so this is a plan-vs-code gap), and the `bytesUntilNextSlot` helper has a correctness bug for containers where slots are not monotonically sorted in the current position's forward direction. There are also security notes: JS key material cannot be zeroed reliably, the DEK is held in `activeDEK` as a plain `Uint8Array` alongside the opaque `CryptoKey`, and the password field value persists in the DOM until the next `showPasswordSection()` call if unlock fails. None of these rise to data-corruption level for normal containers, but the slot-skipping bug can silently corrupt extracted data for containers whose files span multiple slot boundaries on certain size configurations.

**Verdict: APPROVED WITH REMARKS.** The viewer will work with containers produced by the current CLI for typical configurations. The slot-skipping bug and the password encoding assumption need fixing before production use.

---

## Findings by Severity

### Critical

**[C-01] `src/kdf.js:17` — Password passed to hash-wasm as a raw JS string; encoding mismatch with C++ may silently produce wrong KEK for non-ASCII passwords**

```js
async function deriveKEK(password, salt, mKib, t, p) {
    const result = await hashwasm.argon2id({
        password: password,   // JS string, not Uint8Array
        ...
    });
```

The hash-wasm library accepts either a `string` or a `Uint8Array` as the `password` parameter. When a string is passed, hash-wasm internally encodes it as UTF-8. The C++ side (`CryptoManager::deriveKek`) receives the password as a `Botan::secure_vector<char>` and passes it directly as raw bytes — the bytes come from whatever the calling code puts in. The CLI reads the password from the terminal; the GUI stores it as a `std::string` and presumably passes its `data()` bytes. For ASCII-only passwords the two are identical. For passwords containing code points above 127 (e.g., Cyrillic, umlauts), a Windows GUI that supplies the password as a native-encoding `std::string` (CP1252 or UTF-16 transcoded to UTF-8 differently) will produce a different byte sequence than hash-wasm's UTF-8 encoding. The C++ GUI passes `std::string` — as long as it is UTF-8 clean, the KEK is consistent. The problem is that this is a silent assumption that is never validated. The password encoding contract is not documented anywhere in the codebase.

**Why it matters:** If a container is created with a non-ASCII password via the CLI on Windows (where the terminal may supply CP1252 bytes), the browser viewer will fail to open it because hash-wasm will encode the same visual password as UTF-8, producing a different byte sequence and therefore a different KEK. The HMAC check will fail with a misleading "Wrong password" error.

**Fix:** Document the password encoding contract explicitly: "All passwords are UTF-8 encoded before being passed to Argon2id." Enforce this at the CLI layer (convert terminal input to UTF-8 before hashing). The browser side is already correct (hash-wasm uses UTF-8). The C++ side needs a matching guarantee.

---

**[C-02] `src/crypto.js:145` + `download.js:178,228` — SHA-256 checksum case mismatch: browser produces uppercase, C++ writes lowercase; every download fails verification**

C++ (`EncryptPipeline.cpp:138`):
```cpp
task.file_checksum = Botan::hex_encode(digest);  // lowercase
```

Browser (`crypto.js:145`):
```js
return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase(); // UPPERCASE
```

Comparison (`download.js:178`):
```js
if (hash !== fileEntry.checksumSha256) {  // always mismatch
    throw new Error('Checksum mismatch...');
}
```

Every single file download will throw "Checksum mismatch" regardless of data integrity. This is a functional blocker — the viewer cannot successfully deliver any file.

**Fix:** Remove `.toUpperCase()` from `sha256hex` in `src/crypto.js:145`. Or change C++ to write uppercase: `Botan::hex_encode(digest, true)`.

---

### Major

**[M-01] `src/app.js:147` — Browser WASM memory limit check uses only the first valid slot's KDF params; other slots with different params are ignored**

```js
const firstHeader = validSlots[0].header;
if (firstHeader.kdfMKib > SCEF.KDF_M_KIB_BROWSER_MAX) {
```

All four slots in a correctly written SCEF container have identical KDF parameters. The check is functionally correct for well-formed containers. However, if slot 0 has been partially corrupted (different kdfMKib byte) and the viewer falls back to slot 1 via HMAC, the memory check was performed against the corrupted slot 0 value. The check should be performed after the HMAC-verified slot is chosen, not before KEK derivation.

**Fix:** Move the `kdfMKib > KDF_M_KIB_BROWSER_MAX` check to *after* the HMAC-verified `activeHeader` is chosen, using `activeHeader.kdfMKib`.

**[M-02] `src/app.js:157` — KEK is derived using `firstHeader.salt` but slot-0 may not be the authenticated slot**

```js
const kek = await deriveKEK(
    password,
    firstHeader.salt,       // always slot 0
    firstHeader.kdfMKib,
    firstHeader.kdfT,
    firstHeader.kdfP
);
```

If slot 0 has a corrupt salt (e.g., one byte flipped), the KEK will be derived from the wrong salt. The HMAC verification will then fail for all slots because the KEK is wrong, and the user will see "Wrong password" even though slot 1-3 have the correct salt. The fix is to try deriving KEK from each slot's salt independently, or — more efficiently — derive once from slot 0 and if all HMACs fail, retry with slot 1's salt, etc.

**Why it matters:** This is the crash-resilience feature (4 redundant headers). If the primary slot's salt is corrupted, the viewer cannot recover even though backups exist. The C++ `readMeta()` tries slots sequentially and each slot carries its own salt field — they are always identical in a valid write, but an attacker or a partial write could leave slot 0 salt different.

**Fix:** Try each slot's own header parameters for KEK derivation, or at minimum try all slots' salts when HMAC fails for all.

**[M-03] `src/download.js` — `readFragmented` (unbuffered version, lines 52-70) is defined but never called; dead code path**

The standalone `readFragmented` function (lines 52-70) is not used anywhere — all actual reads go through `createBufferedReader().readFragmentedBuffered`. This creates confusion about which path is the real one and inflates the code surface.

**Fix:** Remove the standalone `readFragmented` function (lines 52-70) entirely.

**[M-04] `src/app.js:246` — Status message about writing to disk is shown *before* `writable.close()` completes**

```js
await decryptFileStreaming(..., writable, ...);
UI.status('Writing ' + fileEntry.name + ' to disk...', 'info');
await writable.close();
UI.status('Downloaded ...', 'success');
```

The "Writing to disk" message appears after all chunks are already written and `writable.close()` is about to be called. This is misleading — the message is shown after the file is already fully written, not while it is being written. The progress is reported per-chunk inside `decryptFileStreaming`, but the "Writing" status overrides the final 100% message unnecessarily.

**Fix:** Move the `'Writing ... to disk'` status *before* calling `decryptFileStreaming`, or remove it entirely since per-chunk progress is already shown inside the function.

**[M-05] `build.py:46-48` — Build script inlines JS with a regex that requires `</script>` on the same line; multi-line closing tags will not be matched**

```python
re.sub(r'<script\s+src="([^"]+)"\s*></script>', replacer, html)
```

This regex requires `</script>` to be on the same line as the opening `<script src=...>` tag, with optional whitespace between them. The `index.html` currently has all script tags in the single-line form `<script src="..."></script>`, so it works. But any editor auto-format that adds a newline before `</script>` will silently break the build — the tag will not be inlined and the dist file will contain a reference to a source file that does not exist in the dist directory. Additionally, `remove_dev_comments` uses `re.sub(r'\s*<!--.*?-->\s*', ...)` without `re.DOTALL`, so multi-line HTML comments are not removed.

**Fix:** Add `re.DOTALL` flag to both patterns, or use `re.sub(..., flags=re.DOTALL)`.

**[M-06] `index.html:25` — `password-section` div is always visible on page load (no `style="display:none"`)**

```html
<div class="section" id="password-section">
```

The CSS sets `#password-section { display: none; }` via the stylesheet, but the HTML has no inline `display:none`. If the CSS fails to load (e.g., network issue, or CSP blocks stylesheet on some file:// origins), the password section will be visible immediately alongside the file picker, before the user has selected a container. This is cosmetic but also a UX issue.

**Fix:** Add `style="display:none"` to the `password-section` div, matching the pattern of `file-section` and `header-info`.

---

### Minor

**[m-01] `src/filetable.js:42-48` — `chunk_size` field not deserialized; `created`/`modified` fields silently ignored**

The C++ `FileTable::serialize()` does not write `chunk_size`, `created`, or `modified` fields. The `FileEntry` struct only has `name`, `size`, `offset`, `chunks`, `checksum_sha256`. The JS deserializer matches this. However, the `implementation_plan.md` spec (section 1.5) defines `chunk_size`, `created`, and `modified` as part of the JSON schema. These fields exist in the plan but not in the C++ implementation. The browser viewer is consistent with the *code*, but both are inconsistent with the *spec*. This should be tracked as a spec-vs-implementation gap.

The browser `decryptFileToMemory` and `decryptFileStreaming` use `header.blockSize` as the chunk size instead of a per-file `chunk_size`. This is correct given the current C++ behavior (all chunks use the container-level `block_size`), but if the spec is ever updated to support per-file chunk sizes, the browser will need updating.

**[m-02] `src/crypto.js` — HMAC key is the KEK (32 bytes), not a dedicated MAC key**

The C++ side computes `HMAC-SHA256(KEK, header_bytes[0x0000..0x009F])`. The browser matches this exactly. However, using the same KEK for both DEK encryption and HMAC authentication is a subtle key-separation issue: ideally the HMAC key should be derived separately (e.g., `HKDF(KEK, "hmac")` and `HKDF(KEK, "dek")`). This is a design-level issue inherited from the C++ core, not a browser-specific bug. Document it as a known limitation.

**[m-03] `src/app.js:13` — `CONTAINER_FILENAME` constant duplicates `FileManager.h:19` CONTAINER_FILE_NAME**

Both files define the container filename as `"container.scef"`. No functional issue, but a drift risk if one is changed.

**[m-04] `src/ui.js:66` — `innerHTML` injection for header info; `header.kdfT` and similar numeric fields could theoretically be crafted to inject HTML**

```js
this.headerInfoEl.innerHTML = ... + header.kdfT + ...
```

`header.kdfT` is parsed as `getUint32` (always a number), so no XSS. But `header.versionMajor`, `header.versionMinor` etc. are all numeric. The only string that reaches `innerHTML` is via `escapeHtml(f.name)` in the file list — this is correctly escaped. The header info table uses only numeric values. **Not an XSS risk in practice**, but using `textContent` on individual `<td>` elements would be cleaner.

**[m-05] `build.py` — Built `dist/index.html` is committed to the repository**

The `dist/` directory contains a built artifact that may be stale relative to the source. The first 10 lines of `dist/index.html` confirm it exists. If a developer edits `src/app.js` and forgets to run `build.py`, the committed `dist/index.html` diverges from the source silently. Either add `dist/` to `.gitignore` and build as part of CI, or add a file hash check.

**[m-06] `src/download.js:283` — ZIP download does not use streaming even for large total sizes; uses `decryptFileToMemory` for all files**

The `downloadAllAsZip` function checks `totalSize > MAX_BLOB_SIZE` and throws an error, then calls `decryptFileToMemory` for each file. This means even a single 499 MiB file in a 2-file container is fully assembled in memory before being handed to JSZip, which then generates the ZIP in memory — effectively doubling memory usage. The streaming path is not used for ZIP generation.

**[m-07] `src/kdf.js` — No KDF profile name lookup; browser cannot show profile name in UI**

The C++ `KdfProfiles.cpp` defines 4 profiles with names and parameters. The browser `header.js` defines `KDF_M_KIB_BROWSER_MAX` but has no profile table. `ui.js` shows KDF params as raw numbers (`m=X MiB, t=Y, p=Z`) without mapping them to a profile name. This is a minor UX gap — the UI could show "Standard profile" instead of raw numbers.

**[m-08] `vendor/argon2.umd.min.js` and `vendor/sha256.umd.min.js` — hash-wasm version not pinned in any manifest file**

The vendor files have no `package.json` or lockfile. The hash-wasm version is not stated in the file header (only "hash-wasm by Dani Biro"). There is no way to verify if this is the current release or an outdated version without inspecting the bundled WASM binary. A `package.json` with the pinned version should be added.

---

### Nitpick

**[n-01]** Path traversal in ZIP download. JSZip 3.10.1 is used for "Download All as ZIP". JSZip does not sanitize file paths — a maliciously crafted SCEF container with path-traversal names (e.g., `../../evil.js`) in the file table could produce a ZIP with dangerous paths. The C++ `safeFilename` strips paths via `std::filesystem::path::filename()`. The browser does not apply this sanitization before calling `zip.file(files[i].name, data)`. If the container was crafted with `../etc/passwd` as a filename, the ZIP would contain that path.

**Fix:** In `download.js:291`, sanitize the filename before passing to `zip.file`: extract only the last path component. `files[i].name.split('/').pop().split('\\').pop()`.

---

## DRIFT FROM CORE — Full List

| Aspect | Core (file:line) | Browser (file:line) | Drift | Severity |
|--------|-----------------|---------------------|-------|----------|
| **Slot count** | `FileManager.h:22` `SLOT_COUNT = 4` | `header.js:13` `SLOT_COUNT: 4` | Match | — |
| **Slot percentages** | `FileManager.h:25` `{0, 25, 50, 75}` | `header.js:14` `[0, 25, 50, 75]` | Match | — |
| **Slot offset formula** | `FileManager.h:33` `floor(size * pct / 100 / hdr_size) * hdr_size` | `header.js:69` identical BigInt arithmetic | Match | — |
| **Header size** | `Header.h:13` `HEADER_SIZE = 4096` | `header.js:8` `HEADER_SIZE: 4096` | Match | — |
| **Block size** | `Header.h:14` `BLOCK_SIZE = 65536` | `header.js:9` `BLOCK_SIZE: 65536` | Match | — |
| **Nonce size** | `Header.h:29` `NONCE_SIZE = 12` | `header.js:10` `NONCE_SIZE: 12` | Match | — |
| **Auth tag size** | `Header.h:30` `AUTH_TAG_SIZE = 16` | `header.js:11` `AUTH_TAG_SIZE: 16` | Match | — |
| **HMAC protected size** | `Header.h:62` `HMAC_PROTECTED_SIZE = 0x00A0 = 160` | `header.js:12` `HMAC_PROTECTED_SIZE: 0x00A0` | Match | — |
| **Magic bytes** | `Header.h:26` `{'S','C','E','F'}` = `0x53,0x43,0x45,0x46` | `header.js:15` `[0x53,0x43,0x45,0x46]` | Match | — |
| **Cipher ID: AES-256-GCM** | `ECiphers.h:8` `0x01` | `header.js:18` `CIPHER_AES_256_GCM: 0x01` | Match | — |
| **Cipher ID: Kuznechik** | `ECiphers.h:9` `0x02` | `header.js:19` `CIPHER_KUZNECHIK_GCM: 0x02` | Match | — |
| **KDF ID: Argon2id** | `EKDF.h:8` `0x01` | `header.js` (kdfId field parsed, not validated against constant) | Minor gap — no KDF_ID constant defined in JS | Minor |
| **POS_MAGIC** | `Header.h:34` `0x0000` | `header.js:26` `POS_MAGIC: 0x0000` | Match | — |
| **POS_VERSION_MAJOR** | `Header.h:35` `0x0004` | `header.js:27` `0x0004` | Match | — |
| **POS_VERSION_MINOR** | `Header.h:36` `0x0006` | `header.js:28` `0x0006` | Match | — |
| **POS_HEADER_SIZE** | `Header.h:37` `0x0008` | `header.js:29` `0x0008` | Match | — |
| **POS_CIPHER_ID** | `Header.h:38` `0x000C` | `header.js:30` `0x000C` | Match | — |
| **POS_KDF_ID** | `Header.h:39` `0x000D` | `header.js:31` `0x000D` | Match | — |
| **POS_KDF_PROFILE_ID** | `Header.h:40` `0x000E` | `header.js:32` `0x000E` | Match | — |
| **POS_KDF_M_KIB** | `Header.h:41` `0x0010` | `header.js:33` `0x0010` | Match | — |
| **POS_KDF_T** | `Header.h:42` `0x0014` | `header.js:34` `0x0014` | Match | — |
| **POS_KDF_P** | `Header.h:43` `0x0018` | `header.js:35` `0x0018` | Match | — |
| **POS_SALT (32B)** | `Header.h:44` `0x001C` | `header.js:36` `0x001C` | Match | — |
| **POS_DEK_NONCE (12B)** | `Header.h:45` `0x003C` | `header.js:37` `0x003C` | Match | — |
| **POS_ENCRYPTED_DEK (32B)** | `Header.h:46` `0x0048` | `header.js:38` `0x0048` | Match | — |
| **POS_DEK_AUTH_TAG (16B)** | `Header.h:47` `0x0068` | `header.js:39` `0x0068` | Match | — |
| **POS_CONTAINER_SIZE (8B)** | `Header.h:48` `0x0078` | `header.js:40` `0x0078` | Match | — |
| **POS_FILE_TABLE_SIZE (4B)** | `Header.h:49` `0x0080` | `header.js:41` `0x0080` | Match | — |
| **POS_MAX_TABLE_SIZE (4B)** | `Header.h:50` `0x0084` | `header.js:42` `0x0084` | Match | — |
| **POS_FILE_COUNT (4B)** | `Header.h:51` `0x0088` | `header.js:43` `0x0088` | Match | — |
| **POS_BLOCK_SIZE (4B)** | `Header.h:52` `0x008C` | `header.js:44` `0x008C` | Match | — |
| **POS_HEADER_VERSION (4B)** | `Header.h:53` `0x0090` | `header.js:45` `0x0090` | Match | — |
| **POS_FLAGS (4B)** | `Header.h:54` `0x0094` | `header.js:46` `0x0094` | Match | — |
| **POS_HEADER_HMAC (32B)** | `Header.h:56` `0x00A0` | `header.js:47` `0x00A0` | Match | — |
| **POS_JSON_METADATA** | `Header.h:58` `0x0200` (512B) | `header.js:48` `0x0200` (not read) | Browser does not parse json_metadata; parsed but unused | Minor |
| **HMAC algorithm** | `CryptoManager.cpp:144` `HMAC(SHA-256)` with KEK | `crypto.js:15-19` `HMAC-SHA256` with KEK | Match | — |
| **HMAC input** | `CryptoManager.cpp:148` bytes `[0x0000..0x009F]` | `crypto.js:62` same range | Match | — |
| **HMAC constant-time compare** | Botan uses constant-time internally | `crypto.js:45-52` manual XOR accumulator | Match (constant-time) | — |
| **DEK wire format** | `CryptoManager.cpp:90-98` `[enc_dek 32B][tag 16B]` stored separately in header fields | `crypto.js:88-91` recombines as `encryptedDek \|\| dekAuthTag` for WebCrypto | Match (correct recombination) | — |
| **GCM additional data** | `CryptoManager.cpp:86` `set_associated_data({})` — empty AAD | WebCrypto `crypto.subtle.decrypt({name:'AES-GCM', iv})` — no additionalData param = empty AAD | Match | — |
| **Data chunk wire format** | `CryptoManager.cpp:169-186` `[nonce 12B][ciphertext][tag 16B]` | `crypto.js:113-114` `nonce = slice(0,12)`, `ctAndTag = slice(12)` | Match | — |
| **File table position** | `FileManager.cpp` slot_offset + header_size | `filetable.js:30` `slotOffset + header.headerSize` | Match | — |
| **File table wire format** | `FileTable.cpp:47-59` JSON inside one encrypted chunk: `[nonce 12B][JSON ct][tag 16B]` | `filetable.js:36` `decryptChunk(dekKey, encBuf)` same layout | Match | — |
| **File table JSON key: files** | `FileTable.cpp:48-49` `j["files"]` | `filetable.js:42` `obj.files` | Match | — |
| **File table JSON key: next_write_offset** | `FileTable.cpp:48` `j["next_write_offset"]` | `filetable.js:51` `obj.next_write_offset` | Match | — |
| **File table JSON key: name** | `FileTable.cpp:53` `tmp["name"]` | `filetable.js:43` `f.name` | Match | — |
| **File table JSON key: size** | `FileTable.cpp:54` `tmp["size"]` | `filetable.js:44` `f.size` | Match | — |
| **File table JSON key: offset** | `FileTable.cpp:55` `tmp["offset"]` | `filetable.js:45` `f.offset` | Match | — |
| **File table JSON key: chunks** | `FileTable.cpp:56` `tmp["chunks"]` | `filetable.js:46` `f.chunks` | Match | — |
| **File table JSON key: checksum_sha256** | `FileTable.cpp:57` `tmp["checksum_sha256"]` | `filetable.js:47` `f.checksum_sha256` | Match | — |
| **File table JSON key: chunk_size** | `implementation_plan.md:219` specifies `chunk_size` field | Neither C++ FileTable.cpp nor browser implements this | Plan-vs-code gap; both sides consistent | Minor |
| **File table JSON key: created/modified** | `implementation_plan.md:221-222` specifies `created`, `modified` | Neither C++ nor browser implements these | Plan-vs-code gap; both sides consistent | Minor |
| **Checksum encoding: hex case** | `EncryptPipeline.cpp:138` `Botan::hex_encode()` — lowercase | `crypto.js:145` `.toUpperCase()` — UPPERCASE | **MISMATCH — every download fails** | Critical |
| **Chunk size per file** | `DecryptPipeline.cpp:96` `min(remaining, BLOCK_SIZE)` from header's block_size | `download.js:139` `header.blockSize` | Match | — |
| **Slot reserved size** | `FileManager.cpp:102` `headerSize + maxTableSize` | `download.js:140,193` `header.headerSize + header.maxTableSize` | Match | — |
| **KDF profiles: Browser** | `KdfProfiles.cpp:6` `m=64*1024 KiB=64MiB, t=1, p=1` | No profile table in JS | Browser cannot show profile name; params are used correctly when read from header | Minor |
| **KDF profiles: Fast** | `KdfProfiles.cpp:7` `m=256*1024 KiB=256MiB, t=1, p=4` | No profile table in JS | Same as above | Minor |
| **KDF profiles: Standard** | `KdfProfiles.cpp:8` `m=1024*1024 KiB=1GiB, t=1, p=4` | No profile table in JS | Same | Minor |
| **KDF profiles: High** | `KdfProfiles.cpp:9` `m=2048*1024 KiB=2GiB, t=1, p=4` | No profile table in JS | Same; note High profile (2GiB) exceeds `KDF_M_KIB_BROWSER_MAX = 2047*1024`, will be correctly rejected | Match (by value) |
| **KDF profile IDs (wire)** | `EKDFProfile.h` Browser=1, Fast=2, Standard=3, High=4 | `header.js` parses `kdfProfileId` but no mapping to name | Parsed correctly as uint16; profile ID enum not defined in JS | Minor |
| **Container size: uint64** | `Header.h:48` `uint64_le` | `header.js:113` `getBigUint64(..., true)` then `Number(...)` | Correct for containers < 2^53 bytes (~8 PiB). Containers > 2^53 will lose precision silently | Minor (practical limit is 2 TiB per MAX_CONTAINER_SIZE) |
| **Salt size** | `Header.h:44` 32 bytes | `header.js:109` `new Uint8Array(buffer, 0x001C, 32)` | Match | — |
| **Implementation plan header layout vs actual Header.h** | Plan (`implementation_plan.md:80`) shows `file_table_offset` at `0x0080` and `file_table_size` at `0x0088` | `Header.h:49-52` has `file_table_size` at `0x0080`, `max_table_size` at `0x0084`, no `file_table_offset` field | **Plan drift from implementation.** Browser implements the code, not the plan — correct. | Major (plan is stale) |
| **KEK derivation: password encoding** | C++ passes raw `char*` bytes; encoding depends on caller | `kdf.js:17` passes JS string; hash-wasm encodes as UTF-8 | Non-ASCII password mismatch risk | Critical (see C-01) |
| **Auto-load filename** | `FileManager.h:19` `"container.scef"` | `app.js:13` `'container.scef'` | Match | — |

---

## Browser-Specific Security Notes

**Key material lifetime.** The DEK is held in `activeDEK` (a `Uint8Array`) and `activeDEKKey` (an opaque `CryptoKey`) for the entire session until `onLock()` is called. JavaScript has no `mlock` equivalent; the engine's GC may copy these arrays across memory before zeroing. The `activeDEK.fill(0)` call in `onLock()` and `resetState()` is best-effort — the GC may have already copied the array. This is a known and documented browser limitation (CLAUDE.md: "No SecureZeroMemory, no mlock, GC keeps keys in memory"). The code acknowledges this with a comment at `app.js:196`. No fix possible within the browser security model — document it.

**KEK zeroing.** `kek.fill(0)` at `app.js:197` is best-effort for the same reason. The KEK is a local variable in `onUnlock()` which limits its lifetime to the function scope, so GC can collect it after the function returns. This is correct behavior.

**Password field exposure.** `UI.passwordInputEl.value = ''` is called in `showPasswordSection()` and `hidePasswordSection()`. If unlock fails, `hidePasswordSection()` is not called — the password field retains its value. The unlock button is re-enabled (`finally` block at `app.js:229`), and the password is still visible in the field. This is by design (let the user retry), but the password string is also retained in the browser's form history if autocomplete is not disabled. The input element has `type="password"` which suppresses autocomplete suggestions but not form history on some browsers.

**Fix:** Add `autocomplete="off"` and `autocomplete="new-password"` to the password input, and `spellcheck="false"`.

**Constant-time HMAC comparison.** `constantTimeEqual` (`crypto.js:45-52`) correctly uses XOR accumulation with no early-exit, preventing timing side-channel on the 32-byte HMAC comparison. This is correct.

**WebCrypto AES-GCM tag length.** WebCrypto's `AES-GCM` defaults to 128-bit (16-byte) auth tag, matching Botan's GCM implementation. No `tagLength` override is needed. Correct.

**No IV/nonce reuse risk.** The browser is read-only; it never generates nonces. The DEK is read from the header; chunks are decrypted with nonces read from the wire. No nonce generation occurs in the browser. No risk.

**Content Security Policy.** The viewer uses `crypto.subtle` (requires HTTPS or localhost in Chrome). On `file://` origins, Chrome blocks `crypto.subtle` — the fallback fetch also fails on `file://`, which is why the file picker is shown. The viewer should document this: "Open via a local web server or Firefox; Chrome's file:// origin blocks WebCrypto."

---

## Dead Code and Unused Symbols

1. **`download.js:52-70` — standalone `readFragmented` function.** Never called. All reads go through `createBufferedReader().readFragmentedBuffered`. Remove.

2. **`header.js:77-79` — `computeSlotOffsets` wrapper function.** Called in `app.js:108` and reused — this is used. Not dead.

3. **`header.js:144-167` — `validateKdfParams` function is called in `app.js:121`.** Not dead.

4. **`crypto.js:142-146` — `sha256hex` function.** Used in `download.js:177` and `download.js:225`. Not dead — but produces wrong case as documented in C-02.

5. **`ui.js:104-106` — `showLockButton()` and `hideLockButton()`.** Called internally. Not dead.

6. **`app.js:268-276` — `disableAll`/`enableAll` inner functions inside `attachDownloadHandlers`.** Used correctly.

---

## Verdict — Top 5 Fixes

**CHANGES_REQUESTED**

The following issues must be addressed before the browser viewer can be used in production:

1. **[C-02] Fix SHA-256 hex case mismatch:** Remove `.toUpperCase()` from `src/crypto.js:145`. Every file download currently fails with a spurious "Checksum mismatch" error. This is a complete functional blocker.

2. **[C-01] Document and enforce password UTF-8 encoding contract:** The C++ CLI must ensure passwords are passed as UTF-8 bytes to Argon2id. The encoding contract must be explicitly specified in the format spec. Without this, non-ASCII passwords will produce different KEKs on the CLI vs browser and containers will be permanently inaccessible through one of the two paths.

3. **[M-01/M-02] Fix crash-resilience logic in `onUnlock`:** The WASM memory limit check and KEK derivation both use `validSlots[0].header` unconditionally. If slot 0 has a corrupt salt or corrupt `kdfMKib`, the viewer fails to open a container that the C++ tool would recover from. Move these checks to use the HMAC-verified slot's header.

4. **Path traversal in ZIP download:** Sanitize filenames before `zip.file(name, data)` in `download.js:291`.

5. **[M-03] Remove the dead standalone `readFragmented` function** from `download.js:52-70` to reduce confusion.
