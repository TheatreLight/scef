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
let containerBlob   = null;   // raw Blob from fetch (used when File API unavailable)
let activeHeader    = null;   // parsed header from the valid slot
let activeSlotIndex = -1;     // which slot was used (0-3)
let activeDEK       = null;   // Uint8Array(32), set after successful unlock
let activeFileTable = null;   // { nextWriteOffset, files: [...] }

function init() {
    UI.init();
    UI.fileInputEl.addEventListener('change', onFileSelected);
    UI.unlockBtnEl.addEventListener('click', onUnlock);
    UI.passwordInputEl.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') onUnlock();
    });
    UI.lockBtnEl.addEventListener('click', onLock);

    // Try auto-loading container from same directory
    tryAutoLoad();
}

/**
 * Attempt to fetch container.scef from the same directory as index.html.
 * Works on: Firefox file://, any http(s):// context.
 * Fails on: Chrome/Edge file:// (CORS blocks fetch).
 * On failure: show file picker fallback.
 */
async function tryAutoLoad() {
    UI.status('Looking for ' + CONTAINER_FILENAME + '...', 'info');

    try {
        const resp = await fetch('./' + CONTAINER_FILENAME);
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        const blob = await resp.blob();

        // Wrap blob as a File-like object with .name and .size
        containerBlob = blob;
        containerFile = new File([blob], CONTAINER_FILENAME);

        await validateAndPromptPassword();
    } catch (e) {
        // Fetch failed — show file picker
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
        const result = await findValidSlot(containerFile);
        activeHeader = result.header;
        activeSlotIndex = result.slotIndex;

        if (activeHeader.cipherId === SCEF.CIPHER_KUZNECHIK_GCM) {
            UI.status('This container uses Kuznechik cipher, which is not supported in the browser viewer. Use the native CLI.', 'error');
            return;
        }

        if (activeHeader.cipherId !== SCEF.CIPHER_AES_256_GCM) {
            UI.status('Unknown cipher. Use the native CLI.', 'error');
            return;
        }

        // Hide file picker, show password prompt
        UI.fileSectionEl.style.display = 'none';
        UI.status('Container recognized. Enter password to unlock.', 'info');
        UI.showPasswordSection();
    } catch (err) {
        UI.status(err.message, 'error');
        // Show file picker in case user picked a wrong file
        UI.fileSectionEl.style.display = 'block';
    }
}

/**
 * Read header from all 4 slot positions, return the first one with valid magic.
 */
async function findValidSlot(file) {
    const fileSize = file.size;
    if (fileSize < SCEF.HEADER_SIZE) {
        throw new Error('File is too small to be a SCEF container');
    }

    const slotOffsets = computeSlotOffsets(fileSize, SCEF.HEADER_SIZE);

    for (let i = 0; i < SCEF.SLOT_COUNT; i++) {
        const offset = slotOffsets[i];
        if (offset + SCEF.HEADER_SIZE > fileSize) continue;

        const slice = file.slice(offset, offset + SCEF.HEADER_SIZE);
        const buffer = await slice.arrayBuffer();
        const header = parseHeader(buffer);

        if (header !== null) {
            const kdfError = validateKdfParams(header);
            if (kdfError) continue;
            return { header, slotIndex: i };
        }
    }

    throw new Error('Not a valid SCEF container');
}

/**
 * Password unlock: derive KEK → verify HMAC → unwrap DEK → decrypt file table.
 */
async function onUnlock() {
    const password = UI.passwordInputEl.value;
    if (!password) {
        UI.status('Please enter a password.', 'error');
        return;
    }

    UI.unlockBtnEl.disabled = true;

    try {
        // Check browser WASM memory limit before attempting KDF
        if (activeHeader.kdfMKib > SCEF.KDF_M_KIB_BROWSER_MAX) {
            const mMib = (activeHeader.kdfMKib / 1024).toFixed(0);
            UI.status('This container uses Argon2id with m=' + mMib + ' MiB, which exceeds the browser viewer limit. Use the native application to open this container.', 'error');
            return;
        }

        // Step 1: Derive KEK via Argon2id
        UI.status('Deriving key... this may take a moment.', 'info');
        await new Promise(r => setTimeout(r, 50));

        const kek = await deriveKEK(
            password,
            activeHeader.salt,
            activeHeader.kdfMKib,
            activeHeader.kdfT,
            activeHeader.kdfP
        );

        // Step 2: Verify HMAC (authenticate before decrypt)
        UI.status('Verifying...', 'info');
        const hmacOk = await verifyHeaderHMAC(
            kek,
            activeHeader.hmacProtectedBytes,
            activeHeader.headerHmac
        );

        if (!hmacOk) {
            UI.status('Wrong password or corrupted container.', 'error');
            return;
        }

        // Step 3: Unwrap DEK
        activeDEK = await unwrapDEK(
            kek,
            activeHeader.dekNonce,
            activeHeader.encryptedDek,
            activeHeader.dekAuthTag
        );

        // Step 4: Decrypt file table
        UI.status('Reading file table...', 'info');
        const slotOffsets = computeSlotOffsets(containerFile.size, SCEF.HEADER_SIZE);
        const fileTable = await readFileTable(
            containerFile,
            activeHeader,
            slotOffsets[activeSlotIndex],
            activeDEK
        );

        activeFileTable = fileTable;

        // Show unlocked UI — container info + file list + lock button
        UI.showUnlockedState();
        UI.showHeaderInfo(activeHeader, activeSlotIndex);
        UI.showFileList(fileTable.files);
        UI.status('Unlocked. ' + fileTable.files.length + ' file(s).', 'success');

        attachDownloadHandlers();

    } catch (err) {
        UI.status(err.message, 'error');
    } finally {
        UI.unlockBtnEl.disabled = false;
    }
}

/**
 * Lock: clear DEK from memory, return to password prompt.
 * Container file reference is kept — user doesn't need to re-select.
 */
function onLock() {
    if (activeDEK) {
        activeDEK.fill(0);
        activeDEK = null;
    }
    activeFileTable = null;

    // Keep containerFile and activeHeader — just re-prompt for password
    UI.showLockedState();
    UI.status('Container locked.', 'info');
    UI.showPasswordSection();
}

function resetState() {
    activeHeader = null;
    activeSlotIndex = -1;
    if (activeDEK) {
        activeDEK.fill(0);
        activeDEK = null;
    }
    activeFileTable = null;
}

/**
 * Attach click handlers to download buttons and Extract All.
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
                await downloadFile(containerFile, activeHeader, fileEntry, activeDEK, slotOffsets);
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
                await downloadAllAsZip(containerFile, activeHeader, activeFileTable.files, activeDEK, slotOffsets);
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
