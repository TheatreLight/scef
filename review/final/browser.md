# Final Review — SCEF Browser Viewer

## Executive Summary

After reading both reviewer reports and verifying every disputed claim against the actual source code, the conclusion is: **Codex was substantially correct on the functional verdict; Sonnet was correct on most individual issues but fabricated the most dramatic one.**

Sonnet's C-02 — "SHA-256 hex case mismatch: C++ writes lowercase, JS writes uppercase, every download fails" — is a **false positive**. `Botan::hex_encode(digest)` defaults to **uppercase** (Botan's documented default: `bool uppercase = true`). The JS `sha256hex` returns `.toUpperCase()`, and the streaming path calls `hasher.digest('hex').toUpperCase()`. Both sides produce uppercase. The comparison `hash !== fileEntry.checksumSha256` compares uppercase to uppercase and works correctly.

Codex's "0 bytes of functional drift, APPROVED_WITH_REMARKS" is correct on the format side and on the crypto correctness, but Codex missed real issues: the M-01/M-02 slot-0 KEK derivation weakness, the `readFragmented` dead code, the build.py multi-line regex fragility, and the CLI Windows password encoding concern. Codex also inflated its password-field issues to MAJOR when those are documented browser-environment limitations.

The actual verdict for this codebase is **APPROVED_WITH_REMARKS**. There are no functional blockers. The slot-0 KEK derivation issue (Sonnet M-01/M-02) is a real crash-resilience gap but affects only containers with a corrupt slot-0 salt — a scenario that does not arise in normal use.

---

## Reviewer Comparison

| Claim | Sonnet | Codex | Verified verdict |
|-------|--------|-------|-----------------|
| C-02: SHA-256 case mismatch, every download fails | CRITICAL | Not mentioned | **FALSE POSITIVE** — both sides uppercase |
| C-01: Password UTF-8 mismatch (non-ASCII) | CRITICAL | Not mentioned | **CONFIRMED** but scoped to CLI on Windows |
| M-01/M-02: Slot-0 KEK derivation unconditional | MAJOR | Not mentioned | **CONFIRMED** — real crash-resilience gap |
| M-03: `readFragmented` dead code | MAJOR | Not mentioned | **CONFIRMED** |
| M-04: UI status message ordering | MAJOR | Not mentioned | **CONFIRMED** |
| M-05: build.py regex fragility | MAJOR | Not mentioned | **CONFIRMED** (partial — inline whitespace handled, newline not) |
| M-06: `password-section` always visible | MAJOR | Not mentioned | **CONFIRMED** |
| Password field not cleared after unlock | Not rated | MAJOR | **CONFIRMED** (minor risk, browser limitation) |
| Password string not scrubable in JS | Not mentioned | MAJOR | **CONFIRMED** (documented design trade-off, not a bug) |
| Binary format drift | 34 matches, 1 false CRITICAL | 0 drift | **Codex correct** |
| Path traversal in ZIP (filenames) | NITPICK | Not mentioned | **CONFIRMED** |

---

## Findings (Deduplicated, Verified, Prioritized)

### CRITICAL

None. The only CRITICAL claim in any report (Sonnet C-02, SHA-256 case mismatch) is a false positive — see the resolution section below.

---

### MAJOR

**[F-1] `scef/browser/src/kdf.js:15,18` — CLI on Windows may pass non-UTF-8 bytes for non-ASCII passwords, producing a different KEK than the browser**

- **Source:** Sonnet C-01
- **Verdict:** CONFIRMED — scoped to CLI on Windows
- **What it is:** `CryptoManager::deriveKek` receives a `Botan::secure_vector<char>` of raw bytes. On the CLI path (`main.cpp`), `read_password()` calls `std::cin.get(ch)` which delivers bytes in whatever encoding the OS terminal uses. On a Windows console with `chcp 1252` (the default), a non-ASCII character such as `ä` arrives as byte `0xE4` (CP1252), not as `0xC3 0xA4` (UTF-8). hash-wasm's `argon2id({ password: string })` documents that strings are UTF-8 encoded internally, so it sends `0xC3 0xA4`. The two byte sequences produce different Argon2id outputs → different KEKs → browser cannot open the container. The GUI is safe: `ScefController.cpp:46` uses `password.toUtf8()` which always produces UTF-8.
- **Fix:** In `main.cpp::read_password()`, after reading from stdin on Windows, convert the byte string from the current console code page to UTF-8 using `MultiByteToWideChar` + `WideCharToMultiByte(CP_UTF8)`. Document the password encoding contract (UTF-8) in the format spec. The browser side requires no change.

**[F-2] `scef/browser/src/app.js:147,157-163` — KEK derived from slot-0 salt unconditionally; corrupt slot-0 disables crash recovery**

- **Source:** Sonnet M-01/M-02
- **Verdict:** CONFIRMED

Reading lines 146–163 of app.js:
```js
const firstHeader = validSlots[0].header;
if (firstHeader.kdfMKib > SCEF.KDF_M_KIB_BROWSER_MAX) { ... }  // line 147

const kek = await deriveKEK(
    password,
    firstHeader.salt,       // always slot 0, line 159
    firstHeader.kdfMKib,
    firstHeader.kdfT,
    firstHeader.kdfP
);
```

The design intent (4 redundant slots for crash resilience) requires that if slot 0's salt is corrupted, the viewer tries slot 1. The current code derives the KEK from slot-0's salt unconditionally, regardless of which slot later passes HMAC verification. All four slots should have the same salt in a correctly-written container, so this is not an issue for normal containers. However, a partially-failed write that leaves slot 0 with a corrupted salt (e.g., one byte flipped during a write that was interrupted mid-header) would cause all four HMAC checks to fail silently, even though slots 1–3 have valid data — presenting the user with "Wrong password" when the password is correct.

Note: the `kdfMKib` check at line 147 uses `validSlots[0].header` before the HMAC-verified slot is known. This is a minor ordering issue subordinate to the main salt problem.

- **Fix:** Derive KEK independently per slot in the `for (const slot of validSlots)` loop. The cost is re-running Argon2id for each slot with a different salt, but since all valid slots in a well-written container share the same salt, only one Argon2id invocation is needed for the common case.

**[F-3] `scef/browser/src/download.js:52-70` — standalone `readFragmented` is dead code**

- **Source:** Sonnet M-03
- **Verdict:** CONFIRMED

`readFragmented` at lines 52–70 is never called. All decryption paths call `reader.readFragmentedBuffered` from `createBufferedReader()`. The dead function is complete and correct code; it is the unbuffered predecessor of the buffered version. Its presence creates confusion about which path is authoritative.

- **Fix:** Remove lines 52–70 of `scef/browser/src/download.js`.

**[F-4] `scef/browser/src/download.js:244-245` — "Writing to disk" status shown after write, not during**

- **Source:** Sonnet M-04
- **Verdict:** CONFIRMED

Lines 243–247:
```js
await decryptFileStreaming(containerFile, header, fileEntry, dekKey, slotOffsets, writable);
UI.status('Writing ' + fileEntry.name + ' to disk...', 'info');   // after write
await writable.close();
UI.status('Downloaded ...', 'success');
```
`decryptFileStreaming` already calls `writable.write()` for each chunk and shows per-chunk progress. The "Writing to disk" status message overrides the final 100% progress update and appears after all data has been written, just before `writable.close()`. The message is misleading.

- **Fix:** Move the `UI.status('Writing...')` call to before `decryptFileStreaming(...)`, or remove it entirely since per-chunk progress is already shown inside the function.

**[F-5] `scef/browser/build.py:45-48,53-54` — regex does not handle newlines in script tags or multi-line HTML comments**

- **Source:** Sonnet M-05
- **Verdict:** CONFIRMED

The `inline_scripts` regex at line 46:
```python
r'<script\s+src="([^"]+)"\s*></script>'
```
`\s` in Python `re` does match `\n` by default, so `\s*` between `>` and `</script>` actually handles a newline before `</script>`. However, the `remove_dev_comments` regex at line 54:
```python
r'\s*<!--.*?-->\s*'
```
uses `.*?` which, without `re.DOTALL`, matches any character except newline. Multi-line HTML comments such as:
```html
<!--
  Development note
-->
```
will not be removed by this pattern. Currently all comments in `index.html` are single-line, so this does not affect the current build. But it is a latent build-script bug.

- **Fix:** Add `re.DOTALL` to the `remove_dev_comments` call: `re.sub(r'\s*<!--.*?-->\s*', '\n', html, flags=re.DOTALL)`.

**[F-6] `scef/browser/index.html:25` — `#password-section` visible on page load without inline `display:none`**

- **Source:** Sonnet M-06
- **Verdict:** CONFIRMED

```html
<div class="section" id="password-section">
```
`file-section` has `style="display:none"` (line 20). `password-section` does not. CSS hides it, but CSS can fail to load on certain `file://` origins or under a restrictive CSP. If it fails, the password prompt appears immediately alongside the file picker before any container is loaded.

- **Fix:** Add `style="display:none"` to the `password-section` div at `index.html:25`.

---

### MINOR

**[F-7] `scef/browser/src/app.js:136,197` — Password string not cleared after unlock (browser JS limitation)**

- **Source:** Codex M1/M2, Sonnet browser-security section
- **Verdict:** CONFIRMED as a known browser limitation, documented in CLAUDE.md

The password is a JS string (immutable) and cannot be zeroed. `kek.fill(0)` at line 197 is best-effort. The password field value persists in the DOM input after a failed unlock attempt (correct UX) but also after a successful one (unnecessary exposure). CLAUDE.md explicitly acknowledges this trade-off: "No SecureZeroMemory, no mlock, GC keeps keys in memory."

- **Fix:** Add `UI.passwordInputEl.value = ''` after successful unlock completes (after line 223 in `onUnlock`). Add `autocomplete="off"` to the password input in `index.html`.

**[F-8] `scef/browser/src/download.js:291` — ZIP filenames not sanitized; path traversal in crafted containers**

- **Source:** Sonnet n-01 (NITPICK, elevated here)
- **Verdict:** CONFIRMED

Line 291–292:
```js
const data = await decryptFileToMemory(..., files[i], ...);
zip.file(files[i].name, data);
```
`files[i].name` comes from decrypted (GCM-authenticated) JSON, so it cannot be tampered with in transit. However, a container created locally with `../etc/passwd` as a filename — which the C++ CLI allows — would produce a ZIP with that path. The native C++ `extract()` uses `std::filesystem::path::filename()` to strip path components before writing to disk. The browser ZIP generation does not apply equivalent sanitization.

- **Fix:**
```js
const safeName = files[i].name.split('/').pop().split('\\').pop() || files[i].name;
zip.file(safeName, data);
```

**[F-9] `scef/browser/src/filetable.js:47` and `download.js:178,226` — `chunk_size`, `created`, `modified` fields missing from spec**

- **Source:** Sonnet m-01
- **Verdict:** CONFIRMED as plan-vs-code gap; both C++ and JS are consistent with each other

`FileTable::serialize()` does not write `chunk_size`, `created`, or `modified`. The JS deserializer correctly omits these fields. This is a gap between `implementation_plan.md` and the actual code — both sides agree on what fields are present.

- **Fix:** No change needed in the browser viewer. File as a plan-vs-implementation note.

**[F-10] `scef/browser/src/ui.js:66` — `innerHTML` with header fields**

- **Source:** Sonnet m-04
- **Verdict:** NOT A REAL RISK — all fields inserted via `innerHTML` are numeric (parsed as integers from the binary header) or passed through `escapeHtml()`. No user-controlled string reaches `innerHTML` without escaping. Downgraded to NITPICK.

**[F-11] `scef/browser/vendor/` — hash-wasm version not pinned**

- **Source:** Sonnet m-08
- **Verdict:** CONFIRMED — no `package.json` or version comment identifying the hash-wasm version.

- **Fix:** Add a `package.json` or a comment in `vendor/argon2.umd.min.js` header: `// hash-wasm v4.x.x`.

**[F-12] `scef/browser/src/app.js:13` — `CONTAINER_FILENAME` duplicates `FileManager.h`**

- **Source:** Sonnet m-03
- **Verdict:** CONFIRMED — no functional impact, maintenance drift risk only.

---

### NITPICK

**[F-13] `scef/browser/src/download.js:77` — `READ_AHEAD_SIZE` magic number not in SCEF constants object**

- **Source:** Codex NP3
- **Verdict:** CONFIRMED — low priority.

**[F-14] `scef/browser/src/app.js:79` — Kuznechik check comment could be clearer**

- **Source:** Codex N1
- **Verdict:** CONFIRMED — defensive check is correct; message could mention "Use the native CLI."

**[F-15] `scef/browser/src/crypto.js` — HMAC key = KEK (same key for DEK encryption and MAC)**

- **Source:** Sonnet m-02
- **Verdict:** CONFIRMED as a design-level issue inherited from the C++ core. Both C++ and JS use KEK as the HMAC key. Key separation via HKDF would be better (`HKDF(KEK, "hmac")` for HMAC, `HKDF(KEK, "dek")` for DEK encryption), but this is a post-MVP architectural decision.

---

## SHA-256 Case-Mismatch Resolution

Sonnet's C-02 is a **false positive**. The claim was: "C++ writes lowercase, JS produces uppercase, every download fails." This was incorrect on the C++ side.

**C++ side — `scef/src/EncryptPipeline.cpp:138`:**
```cpp
task.file_checksum = Botan::hex_encode(digest);
```
`Botan::hex_encode` has the following signature (confirmed in Botan documentation and source):
```cpp
std::string hex_encode(const uint8_t input[], size_t length, bool uppercase = true);
```
The default is `uppercase = true`. When called as `Botan::hex_encode(digest)` without a second argument, it produces **UPPERCASE** hex: `"A3F2..."`.

**JS side — `scef/browser/src/crypto.js:142-146`:**
```js
async function sha256hex(data) {
    const hash = await crypto.subtle.digest('SHA-256', data);
    const arr = new Uint8Array(hash);
    return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}
```
Also produces **UPPERCASE** via explicit `.toUpperCase()`.

**JS streaming path — `scef/browser/src/download.js:225`:**
```js
const hash = hasher.digest('hex').toUpperCase();
```
Also **UPPERCASE**.

**Comparison site — `scef/browser/src/download.js:178,226`:**
```js
if (hash !== fileEntry.checksumSha256) {  // UPPERCASE vs UPPERCASE — match
    throw new Error('Checksum mismatch...');
}
```
Both sides produce uppercase. The comparison succeeds for a valid file. **This is not a bug.**

Sonnet incorrectly assumed that `Botan::hex_encode` defaults to lowercase. Codex's verdict of zero functional drift on this point was correct.

---

## DRIFT FROM CORE — Verified Final Table

All items verified by reading `scef/include/Header.h`, `scef/browser/src/header.js`, `scef/src/FileTable.cpp`, `scef/browser/src/filetable.js`, `scef/src/KdfProfiles.cpp`, and `scef/src/EncryptPipeline.cpp` directly.

| Aspect | Core | Browser | Status |
|--------|------|---------|--------|
| HEADER_SIZE = 4096 | `Header.h:13` | `header.js:8` | MATCH |
| BLOCK_SIZE = 65536 | `Header.h:14` | `header.js:9` | MATCH |
| NONCE_SIZE = 12 | `Header.h:29` | `header.js:10` | MATCH |
| AUTH_TAG_SIZE = 16 | `Header.h:30` | `header.js:11` | MATCH |
| HMAC_PROTECTED_SIZE = 0x00A0 | `Header.h:62` | `header.js:12` | MATCH |
| SLOT_COUNT = 4 | `FileManager.h` | `header.js:13` | MATCH |
| SLOT_PERCENTAGES = [0,25,50,75] | `FileManager.h` | `header.js:14` | MATCH |
| MAGIC = "SCEF" 0x53,0x43,0x45,0x46 | `Header.h:26` | `header.js:15` | MATCH |
| CIPHER_AES_256_GCM = 0x01 | `ECiphers.h:8` | `header.js:18` | MATCH |
| CIPHER_KUZNECHIK_GCM = 0x02 | `ECiphers.h:9` | `header.js:19` | MATCH |
| POS_MAGIC = 0x0000 | `Header.h:34` | `header.js:22` | MATCH |
| POS_VERSION_MAJOR = 0x0004 | `Header.h:35` | `header.js:23` | MATCH |
| POS_VERSION_MINOR = 0x0006 | `Header.h:36` | `header.js:24` | MATCH |
| POS_HEADER_SIZE = 0x0008 | `Header.h:37` | `header.js:25` | MATCH |
| POS_CIPHER_ID = 0x000C | `Header.h:38` | `header.js:26` | MATCH |
| POS_KDF_ID = 0x000D | `Header.h:39` | `header.js:27` | MATCH |
| POS_KDF_PROFILE_ID = 0x000E | `Header.h:40` | `header.js:28` | MATCH |
| POS_KDF_M_KIB = 0x0010 | `Header.h:41` | `header.js:29` | MATCH |
| POS_KDF_T = 0x0014 | `Header.h:42` | `header.js:30` | MATCH |
| POS_KDF_P = 0x0018 | `Header.h:43` | `header.js:31` | MATCH |
| POS_SALT = 0x001C (32 B) | `Header.h:44` | `header.js:32` | MATCH |
| POS_DEK_NONCE = 0x003C (12 B) | `Header.h:45` | `header.js:33` | MATCH |
| POS_ENCRYPTED_DEK = 0x0048 (32 B) | `Header.h:46` | `header.js:34` | MATCH |
| POS_DEK_AUTH_TAG = 0x0068 (16 B) | `Header.h:47` | `header.js:35` | MATCH |
| POS_CONTAINER_SIZE = 0x0078 (uint64) | `Header.h:48` | `header.js:36` | MATCH |
| POS_FILE_TABLE_SIZE = 0x0080 (uint32) | `Header.h:49` | `header.js:37` | MATCH |
| POS_MAX_TABLE_SIZE = 0x0084 (uint32) | `Header.h:50` | `header.js:38` | MATCH |
| POS_FILE_COUNT = 0x0088 (uint32) | `Header.h:51` | `header.js:39` | MATCH |
| POS_BLOCK_SIZE = 0x008C (uint32) | `Header.h:52` | `header.js:40` | MATCH |
| POS_HEADER_VERSION = 0x0090 (uint32) | `Header.h:53` | `header.js:41` | MATCH |
| POS_FLAGS = 0x0094 (uint32) | `Header.h:54` | `header.js:42` | MATCH |
| POS_HEADER_HMAC = 0x00A0 (32 B) | `Header.h:56` | `header.js:43` | MATCH |
| POS_JSON_METADATA = 0x0200 (512 B) | `Header.h:58` | `header.js:44` | MATCH (parsed but not used in JS) |
| File table JSON: name, size, offset, chunks, checksum_sha256 | `FileTable.cpp:52-57` | `filetable.js:42-47` | MATCH |
| File table JSON: next_write_offset | `FileTable.cpp:48` | `filetable.js:51` | MATCH |
| Checksum hex case: Botan::hex_encode defaults uppercase | `EncryptPipeline.cpp:138` | `crypto.js:145`, `download.js:225` | MATCH — both uppercase |
| HMAC algorithm: HMAC-SHA256 with KEK | `CryptoManager.cpp:144` | `crypto.js:35-38,62` | MATCH |
| HMAC input range [0x0000..0x009F] | `CryptoManager.cpp:144-148` | `crypto.js:62`, `header.js:132` | MATCH |
| DEK wire format: [ct 32B][tag 16B] | `CryptoManager.cpp:90-98` | `crypto.js:88-91` | MATCH |
| Chunk wire format: [nonce 12B][ct][tag 16B] | `CryptoManager.cpp:169-186` | `crypto.js:113-114` | MATCH |
| Argon2id KDF profiles: Browser=64MiB t=1 p=1 | `KdfProfiles.cpp:6` | header parsed from container | MATCH (params read from wire) |
| Argon2id KDF profiles: Fast=256MiB t=1 p=4 | `KdfProfiles.cpp:7` | header parsed from container | MATCH |
| Argon2id KDF profiles: Standard=1024MiB t=1 p=4 | `KdfProfiles.cpp:8` | header parsed from container | MATCH |
| Argon2id KDF profiles: High=2048MiB t=1 p=4 | `KdfProfiles.cpp:9` | header parsed from container | MATCH |
| KDF bounds: m_kib min=1, max=4096*1024 | `KdfProfiles.h:9,11` | `header.js:47-48` | MATCH |
| KDF bounds: t min=1, max=100 | `KdfProfiles.h:12,13` | `header.js:49-50` | MATCH |
| KDF bounds: p min=1, max=64 | `KdfProfiles.h:14,15` | `header.js:51-52` | MATCH |

**Total drift items: 0 functional, 0 format.** The browser viewer is correctly spec-compliant on all binary layout, crypto algorithm, and key-handling dimensions.

One non-critical gap: both C++ and JS omit `chunk_size`, `created`, and `modified` fields from the file table JSON, which the `implementation_plan.md` spec lists. This is a plan-vs-code gap in both implementations simultaneously, not a C++-vs-browser drift.

---

## False Positives

**Sonnet C-02 — SHA-256 uppercase/lowercase mismatch (claimed CRITICAL):** FALSE POSITIVE. `Botan::hex_encode` defaults to uppercase. Both C++ and JS produce and compare uppercase hex strings. The comparison works correctly. This was the most impactful claim in Sonnet's report and the only item Codex's report implicitly refuted by finding no drift. Codex was correct.

**Codex MAJOR "Password string not scrubable in JS memory":** NOT A BUG — this is a documented design trade-off (CLAUDE.md: "No SecureZeroMemory, no mlock, GC keeps keys in memory"). It is worth documenting in a comment, but calling it MAJOR severity implies the code is defective. It is not — it is an inherent browser constraint. The actual UI fix (clear the input field) is the one actionable improvement.

**Sonnet m-02 "HMAC key = KEK is a security issue":** VALID OBSERVATION but architectural, not a browser-viewer bug. The C++ core has the same design. Fix this in the core, not in the browser viewer alone.

---

## Browser-Specific Security

The following properties hold and are verified correct:

- **Constant-time HMAC comparison:** `constantTimeEqual` at `crypto.js:45-52` uses XOR accumulation with no early exit. Correct.
- **No nonce reuse possible:** Browser is read-only; it never generates nonces. All nonces are read from the wire.
- **GCM auth tags verified on all paths:** Every chunk decryption calls WebCrypto `AES-GCM` which verifies the 128-bit tag. The file table decryption uses `decryptChunk()` with the same path.
- **HMAC verified before DEK decryption:** `verifyHeaderHMAC` is called before `unwrapDEK` in `onUnlock`. Correct authenticate-then-decrypt ordering.
- **DEK zeroed on lock:** `activeDEK.fill(0)` at `app.js:239` is best-effort but present and correct.
- **WebCrypto AES-GCM tag length:** Defaults to 128 bits (16 bytes) which matches Botan's GCM output. No `tagLength` override needed.

Remaining browser-specific limitations (inherent, not fixable):
- No `mlock` equivalent; OS may swap key material.
- JS strings are immutable; the password string cannot be zeroed.
- Chrome blocks `crypto.subtle` on `file://` origins; containers must be served from a local web server or opened via file picker in Firefox.

---

## Verdict — Top 5 Fixes Prioritized

**APPROVED_WITH_REMARKS**

There are no functional blockers. The viewer works correctly for all containers produced by the current C++ CLI with ASCII passwords. The following issues should be addressed in priority order:

1. **[F-1] — CLI Windows password encoding (MAJOR):** Non-ASCII passwords created on the Windows CLI will be permanently inaccessible from the browser. Fix: add UTF-8 conversion in `main.cpp::read_password()` and document the encoding contract. This is the highest-impact real issue.

2. **[F-2] — Slot-0 KEK derivation (MAJOR):** If a container's slot-0 salt is corrupted (partial write failure), the browser viewer reports "Wrong password" even though slots 1–3 are intact. The crash-resilience feature is not fully implemented on the browser side. Fix: derive KEK per slot in the slot-iteration loop, or at minimum retry with slot 1's salt when all four HMACs fail.

3. **[F-8] — ZIP filename path traversal (MINOR, elevated):** A locally-crafted container with `../path` filenames in the file table produces a ZIP with traversal paths. The C++ extractor sanitizes this; the browser ZIP path does not. Fix: `files[i].name.split('/').pop().split('\\').pop()` before `zip.file(...)`.

4. **[F-3] — Remove dead `readFragmented` function (MINOR):** The standalone version at `download.js:52-70` is never called and misleads readers about which code path is active.

5. **[F-6] — `password-section` inline `display:none` (MINOR):** Add `style="display:none"` to `index.html:25` to match the defensive pattern of other sections.
