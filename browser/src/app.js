/**
 * SCEF Browser Viewer — main orchestration.
 *
 * Flow:
 *   1. On page load: try fetch('./container.scef') (works in Firefox file://, localhost)
 *   2. If fetch fails: show file picker as fallback (Chrome file://)
 *   3. Enter password → unlock → browse files → download
 *   4. Lock button clears DEK, returns to password prompt
 *
 * No container details are shown before successful authentication.
 */

const CONTAINER_FILENAME = 'container.scef';

let containerFile   = null;   // File or Blob with .size
let validSlots      = [];     // [{header, slotIndex}, ...] — all magic-valid slots
let activeHeader    = null;   // parsed header from the authenticated slot
let activeSlotIndex = -1;     // which slot passed HMAC (0-3)
let activeDEK       = null;   // Uint8Array(32), set after successful unlock
let activeDEKKey    = null;   // CryptoKey, imported once for all chunk decryptions
let activeFileTable = null;   // { nextWriteOffset, files: [...] }

function init() {
    UI.init();
    UI.fileInputEl.addEventListener('change', onFileSelected);
    UI.unlockBtnEl.addEventListener('click', onUnlock);
    UI.passwordInputEl.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') onUnlock();
    });
    UI.lockBtnEl.addEventListener('click', onLock);

    tryAutoLoad();
}

/**
 * Attempt to fetch container.scef from the same directory as index.html.
 */
async function tryAutoLoad() {
    UI.status('Looking for ' + CONTAINER_FILENAME + '...', 'info');

    try {
        const resp = await fetch('./' + CONTAINER_FILENAME);
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        const blob = await resp.blob();

        containerFile = new File([blob], CONTAINER_FILENAME);
        await validateAndPromptPassword();
    } catch (e) {
        UI.status('Select ' + CONTAINER_FILENAME + ' from this folder.', 'info');
        UI.fileSectionEl.style.display = 'block';
    }
}

/**
 * Manual file selection (fallback when auto-load fails).
 */
async function onFileSelected(event) {
    UI.clearResults();
    resetState();

    const file = event.target.files[0];
    if (!file) return;

    containerFile = file;
    await validateAndPromptPassword();
}

/**
 * Validate the loaded container and show password prompt if valid.
 */
async function validateAndPromptPassword() {
    UI.status('Validating container...', 'info');

    try {
        validSlots = await findValidSlots(containerFile);
        // Use first slot for pre-auth checks (cipher ID)
        const firstHeader = validSlots[0].header;

        if (firstHeader.cipherId === SCEF.CIPHER_KUZNECHIK_GCM) {
            UI.status('This container uses Kuznechik cipher, which is not supported in the browser viewer. Use the native CLI.', 'error');
            return;
        }

        if (firstHeader.cipherId !== SCEF.CIPHER_AES_256_GCM) {
            UI.status('Unknown cipher. Use the native CLI.', 'error');
            return;
        }

        UI.fileSectionEl.style.display = 'none';
        UI.status('Container recognized. Enter password to unlock.', 'info');
        UI.showPasswordSection();
    } catch (err) {
        UI.status(err.message, 'error');
        UI.fileSectionEl.style.display = 'block';
    }
}

/**
 * Read headers from all 4 slot positions, return all with valid magic + KDF params.
 * Actual HMAC verification happens in onUnlock (requires KEK).
 */
async function findValidSlots(file) {
    const fileSize = file.size;
    if (fileSize < SCEF.HEADER_SIZE) {
        throw new Error('File is too small to be a SCEF container');
    }

    const slotOffsets = computeSlotOffsets(fileSize, SCEF.HEADER_SIZE);
    const validSlots = [];

    for (let i = 0; i < SCEF.SLOT_COUNT; i++) {
        const offset = slotOffsets[i];
        if (offset + SCEF.HEADER_SIZE > fileSize) continue;

        const slice = file.slice(offset, offset + SCEF.HEADER_SIZE);
        const buffer = await slice.arrayBuffer();
        const header = parseHeader(buffer);

        if (header !== null) {
            const kdfError = validateKdfParams(header);
            if (kdfError) continue;
            validSlots.push({ header, slotIndex: i });
        }
    }

    if (validSlots.length === 0) {
        throw new Error('Not a valid SCEF container');
    }
    return validSlots;
}

/**
 * Password unlock: derive KEK → verify HMAC → unwrap DEK → load container → decrypt file table.
 */
async function onUnlock() {
    const password = UI.passwordInputEl.value;
    if (!password) {
        UI.status('Please enter a password.', 'error');
        return;
    }

    UI.unlockBtnEl.disabled = true;

    try {
        // Check browser WASM memory limit using first valid slot's KDF params
        const firstHeader = validSlots[0].header;
        if (firstHeader.kdfMKib > SCEF.KDF_M_KIB_BROWSER_MAX) {
            const mMib = (firstHeader.kdfMKib / 1024).toFixed(0);
            UI.status('This container uses Argon2id with m=' + mMib + ' MiB, which exceeds the browser viewer limit. Use the native application to open this container.', 'error');
            return;
        }

        // Step 1: Derive KEK via Argon2id (once — all slots share the same salt/params)
        UI.status('Deriving key... this may take a moment.', 'info');
        await new Promise(r => setTimeout(r, 50));

        const kek = await deriveKEK(
            password,
            firstHeader.salt,
            firstHeader.kdfMKib,
            firstHeader.kdfT,
            firstHeader.kdfP
        );

        // Step 2: Try all valid slots — find one that passes HMAC + DEK unwrap.
        // Mirrors C++ readMeta() crash resilience: if slot 0 is corrupted,
        // fall back to slot 1, 2, 3.
        UI.status('Verifying...', 'info');
        let recovered = false;
        let lastError = '';

        for (const slot of validSlots) {
            try {
                const hmacOk = await verifyHeaderHMAC(
                    kek,
                    slot.header.hmacProtectedBytes,
                    slot.header.headerHmac
                );
                if (!hmacOk) continue;

                activeDEK = await unwrapDEK(
                    kek,
                    slot.header.dekNonce,
                    slot.header.encryptedDek,
                    slot.header.dekAuthTag
                );
                activeHeader = slot.header;
                activeSlotIndex = slot.slotIndex;
                recovered = true;
                break;
            } catch (err) {
                lastError = err.message;
            }
        }

        // Zero KEK — no longer needed (best-effort in JS)
        kek.fill(0);

        if (!recovered) {
            UI.status('Wrong password or corrupted container.', 'error');
            return;
        }

        // Step 3: Import DEK as CryptoKey (once for all chunk decryptions)
        activeDEKKey = await importDEKKey(activeDEK);

        // Step 4: Decrypt file table
        UI.status('Reading file table...', 'info');
        const slotOffsets = computeSlotOffsets(containerFile.size, SCEF.HEADER_SIZE);
        const fileTable = await readFileTable(
            containerFile,
            activeHeader,
            slotOffsets[activeSlotIndex],
            activeDEKKey
        );

        activeFileTable = fileTable;

        // Show unlocked UI
        UI.showUnlockedState();
        UI.showHeaderInfo(activeHeader, activeSlotIndex);
        UI.showFileList(fileTable.files);
        UI.status('Unlocked. ' + fileTable.files.length + ' file(s).', 'success');

        attachDownloadHandlers();

    } catch (err) {
        UI.status('Wrong password or container error.', 'error');
    } finally {
        UI.unlockBtnEl.disabled = false;
    }
}

/**
 * Lock: clear DEK from memory, return to password prompt.
 */
function onLock() {
    if (activeDEK) {
        activeDEK.fill(0);
        activeDEK = null;
    }
    activeDEKKey = null;
    activeFileTable = null;

    UI.showLockedState();
    UI.status('Container locked.', 'info');
    UI.showPasswordSection();
}

function resetState() {
    validSlots = [];
    activeHeader = null;
    activeSlotIndex = -1;
    if (activeDEK) {
        activeDEK.fill(0);
        activeDEK = null;
    }
    activeDEKKey = null;
    activeFileTable = null;
}

/**
 * Attach click handlers to download buttons and Download All as ZIP.
 */
function attachDownloadHandlers() {
    const buttons = UI.fileListEl.querySelectorAll('.download-btn');
    const extractAllBtn = document.getElementById('extract-all-btn');
    const slotOffsets = computeSlotOffsets(containerFile.size, SCEF.HEADER_SIZE);

    function disableAll() {
        buttons.forEach(b => b.disabled = true);
        if (extractAllBtn) extractAllBtn.disabled = true;
    }

    function enableAll() {
        buttons.forEach(b => b.disabled = false);
        if (extractAllBtn) extractAllBtn.disabled = false;
    }

    buttons.forEach(btn => {
        btn.addEventListener('click', async () => {
            const idx = parseInt(btn.dataset.index, 10);
            const fileEntry = activeFileTable.files[idx];

            disableAll();
            try {
                await downloadFile(containerFile, activeHeader, fileEntry, activeDEKKey, slotOffsets);
            } catch (err) {
                UI.status('Download failed: ' + err.message, 'error');
            } finally {
                enableAll();
            }
        });
    });

    if (extractAllBtn) {
        extractAllBtn.addEventListener('click', async () => {
            disableAll();
            try {
                await downloadAllAsZip(containerFile, activeHeader, activeFileTable.files, activeDEKKey, slotOffsets);
            } catch (err) {
                UI.status('Extract all failed: ' + err.message, 'error');
            } finally {
                enableAll();
            }
        });
    }
}

// Start when DOM is ready
document.addEventListener('DOMContentLoaded', init);
