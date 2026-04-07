/**
 * SCEF Browser Viewer — UI module.
 * Minimal DOM manipulation: status messages, file input, header display, lock/unlock.
 */

const UI = {
    /** @type {HTMLElement} */
    statusEl: null,
    /** @type {HTMLElement} */
    headerInfoEl: null,
    /** @type {HTMLElement} */
    fileListEl: null,
    /** @type {HTMLInputElement} */
    fileInputEl: null,
    /** @type {HTMLElement} */
    fileSectionEl: null,
    /** @type {HTMLInputElement} */
    passwordInputEl: null,
    /** @type {HTMLButtonElement} */
    unlockBtnEl: null,
    /** @type {HTMLElement} */
    passwordSectionEl: null,
    /** @type {HTMLButtonElement} */
    lockBtnEl: null,

    init() {
        this.statusEl          = document.getElementById('status');
        this.headerInfoEl      = document.getElementById('header-info');
        this.fileListEl        = document.getElementById('file-list');
        this.fileInputEl       = document.getElementById('container-input');
        this.fileSectionEl     = document.getElementById('file-section');
        this.passwordInputEl   = document.getElementById('password-input');
        this.unlockBtnEl       = document.getElementById('unlock-btn');
        this.passwordSectionEl = document.getElementById('password-section');
        this.lockBtnEl         = document.getElementById('lock-btn');
    },

    status(msg, type) {
        this.statusEl.textContent = msg;
        this.statusEl.className = 'status ' + (type || 'info');
    },

    showPasswordSection() {
        this.passwordSectionEl.style.display = 'block';
        this.passwordInputEl.value = '';
        this.passwordInputEl.focus();
    },

    hidePasswordSection() {
        this.passwordSectionEl.style.display = 'none';
        this.passwordInputEl.value = '';
    },

    /**
     * Show full container info AFTER successful unlock.
     */
    showHeaderInfo(header, slotIndex) {
        const cipherName = header.cipherId === SCEF.CIPHER_AES_256_GCM
            ? 'AES-256-GCM'
            : header.cipherId === SCEF.CIPHER_KUZNECHIK_GCM
                ? 'Kuznechik-GCM'
                : 'Unknown (0x' + header.cipherId.toString(16) + ')';

        const mMib = (header.kdfMKib / 1024).toFixed(1);

        this.headerInfoEl.innerHTML =
            '<h3>Container Info</h3>' +
            '<table>' +
            '<tr><td>Format version</td><td>' + header.versionMajor + '.' + header.versionMinor + '</td></tr>' +
            '<tr><td>Cipher</td><td>' + cipherName + '</td></tr>' +
            '<tr><td>KDF</td><td>Argon2id (m=' + mMib + ' MiB, t=' + header.kdfT + ', p=' + header.kdfP + ')</td></tr>' +
            '<tr><td>Container size</td><td>' + formatSize(header.containerSize) + '</td></tr>' +
            '<tr><td>Files</td><td>' + header.fileCount + '</td></tr>' +
            '<tr><td>Block size</td><td>' + formatSize(header.blockSize) + '</td></tr>' +
            '<tr><td>Active slot</td><td>#' + slotIndex + '</td></tr>' +
            '<tr><td>Header version</td><td>' + header.headerVersion + '</td></tr>' +
            '</table>';
        this.headerInfoEl.style.display = 'block';
    },

    showFileList(files) {
        if (!files || files.length === 0) {
            this.fileListEl.innerHTML = '<p>Container is empty.</p>';
            this.fileListEl.style.display = 'block';
            return;
        }

        let html = '<div class="file-list-header"><h3>Files</h3>' +
            '<button class="extract-all-btn" id="extract-all-btn">Download All as ZIP</button></div>' +
            '<table><tr><th>#</th><th>Name</th><th>Size</th><th></th></tr>';
        files.forEach((f, i) => {
            html += '<tr>' +
                '<td>' + (i + 1) + '</td>' +
                '<td>' + escapeHtml(f.name) + '</td>' +
                '<td>' + formatSize(f.size) + '</td>' +
                '<td><button class="download-btn" data-index="' + i + '">Download</button></td>' +
                '</tr>';
        });
        html += '</table>';
        this.fileListEl.innerHTML = html;
        this.fileListEl.style.display = 'block';
    },

    showLockButton() {
        this.lockBtnEl.style.display = 'inline-block';
    },

    hideLockButton() {
        this.lockBtnEl.style.display = 'none';
    },

    /** Transition to "unlocked" state: hide file picker + password, show content + lock */
    showUnlockedState() {
        this.fileSectionEl.style.display = 'none';
        this.hidePasswordSection();
        this.showLockButton();
    },

    /** Transition to "locked" state: hide content, keep file reference */
    showLockedState() {
        this.headerInfoEl.style.display = 'none';
        this.headerInfoEl.innerHTML = '';
        this.fileListEl.style.display = 'none';
        this.fileListEl.innerHTML = '';
        this.hideLockButton();
    },

    clearResults() {
        this.headerInfoEl.style.display = 'none';
        this.headerInfoEl.innerHTML = '';
        this.fileListEl.style.display = 'none';
        this.fileListEl.innerHTML = '';
        this.hidePasswordSection();
        this.hideLockButton();
    },
};

function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KiB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / 1024 / 1024).toFixed(1) + ' MiB';
    return (bytes / 1024 / 1024 / 1024).toFixed(2) + ' GiB';
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
