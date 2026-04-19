#include "FileManager.h"
#include "DecryptPipeline.h"
#include "EncryptPipeline.h"
#include "Header.h"
#include "KdfProfiles.h"
#include "Logger.h"

#include "botan/mem_ops.h"
#include "botan/secmem.h"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <ios>
#include <istream>
#include <memory>
#include <stdexcept>
#include <thread>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <winioctl.h>
#endif

FileManager::FileManager() {
    header_ = std::make_unique<Header>();
    crypto_ = std::make_unique<CryptoManager>();
}

FileManager::~FileManager() {
    if (containerStream_) {
        containerStream_->close();
    }
}

void FileManager::init(const std::vector<std::string>& filesList, const std::string& pathToDir,
                       uint64_t containerSize, uint32_t maxTableSize, bool createNew,
                       const std::string& password) {
    containerFilePath_ = pathToDir + "/" + CONTAINER_FILE_NAME;
    container_size_param_ = containerSize;
    filesList_ = filesList;
    password_ = password;

    header_->setMaxTableSize(maxTableSize);
    if (containerSize > 0) {
        header_->setContainerSize(containerSize);
    }

    slotOffsets_ = computeSlotOffsets();  // create path uses the param-provided size

    if (createNew && !filesList.empty()) {
        uint64_t available = computeAvailableDataCapacity();
        uint64_t required  = computeRequiredDataBytes();
        if (required > available) {
            throw std::runtime_error(
                "Files too large for container: need " + std::to_string(required) +
                " bytes of data capacity but container only provides " +
                std::to_string(available) + " bytes");
        }
    }

    auto streamOpenFlags = std::ios::binary | std::ios::in | std::ios::out;
    if (createNew) {
        streamOpenFlags |= std::ios::trunc;
    }

    containerStream_ = std::make_unique<std::fstream>(containerFilePath_, streamOpenFlags);
    if (!containerStream_->is_open()) {
        throw std::runtime_error("Container file does not exist: " + containerFilePath_);
    }

    if (!createNew) {
        readMeta();
        slotOffsets_ = computeSlotOffsets();  // recompute from authenticated header
    }
    LOG_DEBUG("FileManager successfully initialized");
}

// ---- slot helpers ----

std::array<uint64_t, SLOT_COUNT> FileManager::computeSlotOffsets() const {
    return ::computeSlotOffsets(header_->getContainerSize(), HEADER_SIZE);
}

bool FileManager::overlapsSlot(uint64_t pos, uint64_t size,
                                const std::array<uint64_t, SLOT_COUNT>& slots) const {
    uint64_t slotReserved = header_->getHeaderSize() + header_->getMaxTableSize();
    for (size_t i = 0; i < SLOT_COUNT; ++i) {
        uint64_t slotEnd = slots[i] + slotReserved;
        // Overlap when pos < slotEnd AND pos+size > slots[i]
        if (pos < slotEnd && pos + size > slots[i]) {
            return true;
        }
    }
    return false;
}

uint64_t FileManager::skipSlots(uint64_t pos) const {
    uint64_t slotReserved = header_->getHeaderSize() + header_->getMaxTableSize();
    for (uint64_t slot : slotOffsets_) {
        if (pos >= slot && pos < slot + slotReserved) {
            return slot + slotReserved;
        }
    }
    return pos;
}

size_t FileManager::bytesUntilNextSlot(uint64_t cur, size_t remaining) const {
    for (uint64_t slot : slotOffsets_) {
        if (slot > cur) {
            remaining =std::min(remaining, slot - cur);
            break;
        }
    }
    return remaining;
}

uint64_t FileManager::writeFragmented(const char* data, size_t size) {
    size_t written = 0;
    while (written < size) {
        // Skip past any slot the current write position is inside.
        uint64_t cur = skipSlots(static_cast<uint64_t>(containerStream_->tellp()));
        if (cur != static_cast<uint64_t>(containerStream_->tellp())) {
            containerStream_->seekp(static_cast<std::streamoff>(cur), std::ios::beg);
        }

        size_t canWrite = bytesUntilNextSlot(cur, size - written);
        auto& res = containerStream_->write(data + written, static_cast<std::streamsize>(canWrite));
        if (!res.good()) {
            throw std::runtime_error("writeFragmented: write failed");
        }
        written += canWrite;
    }
    return static_cast<uint64_t>(containerStream_->tellp());
}

void FileManager::readFragmented(char* buf, size_t size) {
    size_t totalRead = 0;
    while (totalRead < size) {
        // Skip past any slot the current read position is inside.
        uint64_t cur = skipSlots(static_cast<uint64_t>(containerStream_->tellg()));
        if (cur != static_cast<uint64_t>(containerStream_->tellg())) {
            containerStream_->seekg(static_cast<std::streamoff>(cur), std::ios::beg);
        }

        size_t canRead = bytesUntilNextSlot(cur, size - totalRead);
        auto& res = containerStream_->read(buf + totalRead, static_cast<std::streamsize>(canRead));
        if (!res.good()) {
            throw std::runtime_error("readFragmented: read failed");
        }
        totalRead += canRead;
    }
}

// ---- KDF configuration ----

void FileManager::setKdfParams(EKDFProfile profile, uint32_t m_kib, uint32_t t, uint32_t p) {
    if (profile != EKDFProfile::None) {
        const KdfProfileParams* params = getProfileParams(profile);
        if (!params) {
            throw std::runtime_error("setKdfParams: unrecognized KDF profile");
        }
        header_->setKdfProfile(profile);
        header_->setKdfMKib(params->m_kib);
        header_->setKdfT(params->t);
        header_->setKdfP(params->p);
        LOG_DEBUG("setKdfParams: profile=%s, m=%u KiB, t=%u, p=%u",
                  params->name, params->m_kib, params->t, params->p);
    } else {
        header_->setKdfProfile(EKDFProfile::None);
        header_->setKdfMKib(m_kib);
        header_->setKdfT(t);
        header_->setKdfP(p);
        LOG_DEBUG("setKdfParams: custom, m=%u KiB, t=%u, p=%u", m_kib, t, p);
    }
}

// ---- crypto helpers ----

void FileManager::initCryptoForCreate() {
    crypto_->generateSalt(header_->getSaltData());
    LOG_DEBUG("initCryptoForCreate: salt generated, deriving KEK (m=%u KiB, t=%u, p=%u)",
              header_->getKdfMKib(), header_->getKdfT(), header_->getKdfP());
    crypto_->deriveKek(password_, *header_);
    LOG_DEBUG("initCryptoForCreate: KEK derived, password length was %zu", password_.size());

    // Zero the password immediately after deriving the KEK.
    Botan::secure_scrub_memory(password_.data(), password_.size());
    password_.clear();

    // Wrap the random DEK with the derived KEK.
    std::array<uint8_t, NONCE_SIZE> dekNonce{};
    std::array<uint8_t, DEK_SIZE>   encryptedDek{};
    std::array<uint8_t, AUTH_TAG_SIZE> dekAuthTag{};
    crypto_->wrapDek(dekNonce, encryptedDek, dekAuthTag);
    LOG_DEBUG("initCryptoForCreate: DEK wrapped, nonce[0..2]=%02x%02x%02x, tag[0..2]=%02x%02x%02x",
              dekNonce[0], dekNonce[1], dekNonce[2],
              dekAuthTag[0], dekAuthTag[1], dekAuthTag[2]);

    header_->setDekNonce(dekNonce);
    header_->setEncryptedDek(encryptedDek);
    header_->setDekAuthTag(dekAuthTag);
}

void FileManager::validateKdfParamsAndDeriveKek() {
    // Validate KDF parameters before use: reject values outside the absolute
    // supported range (OOM/infinite-loop guard).  NOTE: authenticity (HMAC) can
    // only be checked AFTER KEK derivation, so these parameter values are not
    // yet authenticated at this point.  The bounds check limits — but does not
    // eliminate — the maximum Argon2id cost an attacker-supplied header can
    // impose (chicken-and-egg: KEK is needed for HMAC, HMAC is needed to trust
    // KDF params).
    uint32_t mKib = header_->getKdfMKib();
    uint32_t t     = header_->getKdfT();
    uint32_t p     = header_->getKdfP();
    if (mKib < KDF_M_KIB_MIN || mKib > KDF_M_KIB_MAX ||
        t < KDF_T_MIN || t > KDF_T_MAX ||
        p < KDF_P_MIN || p > KDF_P_MAX) {
        throw std::runtime_error("Header KDF parameters out of acceptable range");
    }

    // Derive KEK from the password and the salt read from the header.
    // This is the expensive Argon2id call — performed exactly once per open.
    try {
        crypto_->deriveKek(password_, *header_);
    } catch (...) {
        Botan::secure_scrub_memory(password_.data(), password_.size());
        password_.clear();
        throw;
    }

    // Zero the password immediately after deriving the KEK.
    Botan::secure_scrub_memory(password_.data(), password_.size());
    password_.clear();
}

void FileManager::unwrapDekFromHeader() {
    // Unwrap DEK using the already-derived KEK — throws on wrong password or
    // corrupt DEK ciphertext.
    crypto_->unwrapDek(header_->getDekNonce(),
                       header_->getEncryptedDek(),
                       header_->getDekAuthTag());
}

void FileManager::computeAndStoreHeaderHmac() {
    // we want to be sure that buffer is updated with new stored data
    header_->serialize();

    // Compute HMAC over bytes [0x0000..0x009F] using the KEK.
    auto protectedBytes = header_->hmacProtectedBytes();
    auto hmac = crypto_->computeHmac(protectedBytes.data(), protectedBytes.size());
    header_->storeHmac(hmac);
}

void FileManager::verifyHeaderHmac() {
    // Recompute HMAC over the header bytes [0x0000..0x009F] as read from disk.
    // At this point buffer_ holds the on-disk bytes (including the potentially
    // corrupted fields), so any bit flip is detected.
    auto protectedBytes = header_->hmacProtectedBytes();
    auto expectedHmac   = crypto_->computeHmac(protectedBytes.data(), protectedBytes.size());
    const auto& storedHmac = header_->storedHmac();

    if (!Botan::constant_time_compare(expectedHmac.data(), storedHmac.data(), 32)) {
        throw std::runtime_error("Header HMAC verification failed: container is corrupt or wrong password");
    }
}

// ---- capacity helpers ----
uint64_t FileManager::computeAvailableDataCapacity() const {
    uint64_t containerSize = header_->getContainerSize();
    uint64_t slotReserved  = header_->getHeaderSize() + header_->getMaxTableSize();
    uint64_t slotTotal     = SLOT_COUNT * slotReserved;
    if (containerSize <= slotTotal) {
        LOG_DEBUG("computeAvailableDataCapacity: container=%llu <= slot_total=%llu, available=0",
                  containerSize, slotTotal);
        return 0;
    }
    uint64_t available = containerSize - slotTotal;
    LOG_DEBUG("computeAvailableDataCapacity: container=%llu, slot_reserved=%llu x %zu, available=%llu",
              containerSize, slotReserved, SLOT_COUNT, available);
    return available;
}

uint64_t FileManager::computeRequiredDataBytes() const {
    auto encryptedSizeCalc = [this](uint64_t plain) -> uint64_t {
        uint64_t blockSize = header_->getChunkSize();
        uint64_t fullChunks = plain / blockSize;
        uint64_t lastChunk  = plain % blockSize;
        uint64_t enc = fullChunks * (blockSize + NONCE_SIZE + AUTH_TAG_SIZE);
        if (lastChunk > 0) {
            enc += lastChunk + NONCE_SIZE + AUTH_TAG_SIZE;
        }
        return enc;
    };

    uint64_t required = 0;

    for (const auto& path : filesList_) {
        std::error_code ec;
        uint64_t sz = std::filesystem::file_size(path, ec);
        if (ec) {
            throw std::runtime_error("Cannot stat file '" + path + "': " + ec.message());
        }
        uint64_t enc = encryptedSizeCalc(sz);
        LOG_DEBUG("computeRequiredDataBytes: file='%s', plain=%llu, encrypted=%llu",
                  path.c_str(), sz, enc);
        required += enc;
    }

    LOG_DEBUG("computeRequiredDataBytes: %zu file(s), total required=%llu",
              filesList_.size(), required);
    return required;
}

// ---- container creation helpers ----

void FileManager::createContainerFile() {
    uint64_t containerSize = header_->getContainerSize();
    uint32_t maxTableSize = header_->getMaxTableSize();

    uint64_t minSize = 4ULL * (header_->getHeaderSize() + maxTableSize);
    LOG_DEBUG("createContainerFile: size=%llu, min=%llu, max=%llu, max_table=%u, path='%s'",
              containerSize, minSize, MAX_CONTAINER_SIZE, maxTableSize, containerFilePath_.c_str());
    if (containerSize < minSize) {
        throw std::runtime_error(
            "Container size " + std::to_string(containerSize) +
            " is below the minimum of " + std::to_string(minSize) + " bytes");
    }
    if (containerSize > MAX_CONTAINER_SIZE) {
        throw std::runtime_error(
            "Container size " + std::to_string(containerSize) +
            " exceeds the maximum of " + std::to_string(MAX_CONTAINER_SIZE) + " bytes");
    }

#ifdef _WIN32
    // Mark file as sparse so that seeking to the end and writing one byte
    // does NOT trigger NTFS zero-fill of the entire region.  On a 13 GB
    // container over USB this avoids ~50-60 minutes of zero writes.
    // Best-effort: if the filesystem doesn't support sparse (e.g. exFAT),
    // we fall back to the default behavior.
    {
        HANDLE h = CreateFileA(containerFilePath_.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD br = 0;
            BOOL ok = DeviceIoControl(h, FSCTL_SET_SPARSE,
                                      nullptr, 0, nullptr, 0, &br, nullptr);
            CloseHandle(h);
            LOG_DEBUG("createContainerFile: FSCTL_SET_SPARSE %s",
                      ok ? "succeeded" : "not supported on this filesystem");
        }
    }
#endif

    // Pre-allocate: seek to last byte and write one zero byte.
    containerStream_->seekp(static_cast<std::streamoff>(containerSize - 1), std::ios::beg);
    containerStream_->put('\0');
    if (!containerStream_->good()) {
        throw std::runtime_error("Failed to pre-allocate container to " +
                                 std::to_string(containerSize) + " bytes");
    }
    // TODO: replace flush() with fsync/FlushFileBuffers for real crash safety (spec 4.6.2)
    containerStream_->flush();
    LOG_DEBUG("createContainerFile: pre-allocated %llu bytes successfully", containerSize);
}

void FileManager::writeHeaderAt(uint64_t slotOffset) {
    LOG_DEBUG("FileManager::writeHeaderAt: slot_offset=%llu", slotOffset);
    containerStream_->seekp(static_cast<std::streamoff>(slotOffset), std::ios::beg);
    const char* buf = reinterpret_cast<const char*>(header_->buffer().data());
    if (!containerStream_->write(buf, HEADER_SIZE).good()) {
        throw std::runtime_error("Failed to write header at offset " +
                                 std::to_string(slotOffset));
    }
}

void FileManager::writeFileTableAt(uint64_t slotOffset, const std::vector<char>& encryptedTable) {
    uint64_t tableOffset = slotOffset + header_->getHeaderSize();
    LOG_DEBUG("FileManager::writeFileTableAt: slot_offset=%llu, table_offset=%llu, encrypted_table_size=%zu",
              slotOffset, tableOffset, encryptedTable.size());
    containerStream_->seekp(static_cast<std::streamoff>(tableOffset), std::ios::beg);

    if (!encryptedTable.empty()) {
        containerStream_->write(encryptedTable.data(), static_cast<std::streamsize>(encryptedTable.size()));
        if (!containerStream_->good()) {
            throw std::runtime_error("Failed to write file table at offset " +
                                     std::to_string(tableOffset));
        }
    }

    // Zero-pad the remainder of the reserved area.
    uint32_t maxTableSize = header_->getMaxTableSize();
    size_t written        = encryptedTable.size();
    if (written < maxTableSize) {
        size_t pad = maxTableSize - written;
        std::vector<char> zeros(pad, '\0');
        if (!containerStream_->write(zeros.data(), static_cast<std::streamsize>(pad)).good()) {
            throw std::runtime_error("Failed to pad file table at offset " +
                                     std::to_string(tableOffset));
        }
    }
}

void FileManager::writeAllSlots() {
    // Header fields are already set (salt, dek, etc.) and HMAC computed.
    // Just serialize and write to all slot positions.
    for (size_t i = 0; i < SLOT_COUNT; ++i) {
        writeHeaderAt(slotOffsets_[i]);
        // Build an empty (zero-length) tables payload for initial creation.
        writeFileTableAt(slotOffsets_[i], {});
    }
    // TODO: replace flush() with fsync/FlushFileBuffers for real crash safety (spec 4.6.2)
    containerStream_->flush();
}

void FileManager::writeFileTableToAllSlots() {
    std::string serialized = fileTable_.serialize();
    size_t plainSize = serialized.length();
    size_t encSize = plainSize + NONCE_SIZE + AUTH_TAG_SIZE;
    header_->setFileTableSize(static_cast<uint32_t>(encSize));

    uint32_t maxTableSize = header_->getMaxTableSize();
    if (encSize > maxTableSize) {
        throw std::runtime_error(
            "Encrypted file table size " + std::to_string(encSize) +
            " exceeds max table size " + std::to_string(maxTableSize));
    }

    std::vector<char> encTable(encSize);
    crypto_->encrypt(serialized.c_str(), encTable.data(), plainSize);
    header_->incrementHeaderVersion();
    // Recompute HMAC because file_table_size and header_version changed.
    computeAndStoreHeaderHmac();
    for (size_t i = 0; i < SLOT_COUNT; ++i) {
        writeHeaderAt(slotOffsets_[i]);
        writeFileTableAt(slotOffsets_[i], encTable);
    }
    // TODO: replace flush() with fsync/FlushFileBuffers for real crash safety (spec 4.6.2)
    containerStream_->flush();
}

// ---- public operations ----

void FileManager::readMeta() {
    containerStream_->clear();

    // Crash resilience strategy (spec 4.6.3):
    //   - Try all 4 slots (0, then 1-3 as backups).
    //   - For each slot: check magic → (derive KEK once) → verify HMAC → unwrap DEK.
    //   - First slot that passes all checks wins.
    //   - If a slot has valid magic but DEK/HMAC fails, continue to next slot
    //     (the HMAC-protected region may be corrupted by a bad sector/USB glitch
    //     while backup slots remain intact).
    //   - If ALL slots fail:
    //       - If at least one had valid magic but auth failed → "wrong password
    //         or container corrupted" (wrong password is the common case since
    //         all slots share the same key).
    //       - If no slot had valid magic → "invalid container".
    //
    // Performance note: in the normal (non-corrupted) case, all 4 slots are
    // identical copies of the same header, so they share the same salt and KDF
    // parameters.  The KEK is therefore the same for every slot.  We derive the
    // KEK exactly once (from the first magic-valid slot) and reuse it for the
    // remaining slots — avoiding up to 3 redundant Argon2id invocations.
    //
    // Corruption recovery: if a slot passes magic validation but its KDF params
    // or salt were corrupted by a single-bit flip, the derived KEK will be wrong
    // and DEK unwrap / HMAC verification will fail on that same slot.  In that
    // case we allow ONE re-derivation from the next magic-valid slot (whose salt
    // may be intact).  After two independently derived KEKs both fail, it is
    // almost certainly a wrong password rather than multi-slot corruption, so we
    // stop re-deriving to prevent unbounded Argon2id cost.
    //
    // To support re-derivation the password must still be available after the
    // first Argon2id call.  We keep a local secure copy that is scrubbed at the
    // end of this function on all code paths.

    // Helper: read one header slot into header_. Returns true if magic is valid.
    auto trySlotMagic = [this](uint64_t offset) -> bool {
        containerStream_->clear();
        containerStream_->seekg(static_cast<std::streamoff>(offset), std::ios::beg);
        HeaderBuffer hdrBuf;
        char* hdrPtr = reinterpret_cast<char*>(hdrBuf.data());
        if (!containerStream_->read(hdrPtr, HEADER_SIZE).good()) {
            return false;
        }
        header_->read(hdrBuf);
        return header_->validate();
    };

    // Preserve a scrub-on-exit copy of the password for potential re-derivation.
    // validateKdfParamsAndDeriveKek() zeroes password_ after the first use, so
    // the local copy is our only re-derivation source.
    Botan::secure_vector<char> passwordCopy(password_.begin(), password_.end());

    // Compute slot offsets from file size (== container size for well-formed files).
    // Cannot use slotOffsets_ here — it's populated after readMeta() returns.
    containerStream_->seekg(0, std::ios::end);
    uint64_t fileSize = static_cast<uint64_t>(containerStream_->tellg());
    if (fileSize == 0) {
        throw std::runtime_error("Invalid container: file is empty");
    }

    std::array<uint64_t, SLOT_COUNT> offsets = ::computeSlotOffsets(fileSize, HEADER_SIZE);
    LOG_DEBUG("readMeta: file_size=%llu, slot offsets=[%llu, %llu, %llu, %llu]",
              fileSize, offsets[0], offsets[1], offsets[2], offsets[3]);

    bool recovered  = false;
    bool kekDerived = false;   // true once validateKdfParamsAndDeriveKek() succeeds
    int  kekDerivations = 0;  // how many Argon2id calls were made this open
    constexpr int MAX_KEK_DERIVATIONS = 2;
    int  slotsWithValidMagic = 0;
    std::string lastError = "all slots unreadable";
    // KDF inputs used for the most recent KEK derivation.  Saved so we can
    // detect whether a subsequent slot has DIFFERENT KDF inputs (genuine
    // corruption) vs. the same inputs (wrong password — re-deriving would give
    // the identical wrong KEK and waste one full Argon2id call).
    std::array<uint8_t, 32> kekSalt{};
    uint32_t kekMKib = 0, kekT = 0, kekP = 0;

    for (size_t i = 0; i < SLOT_COUNT; ++i) {
        uint64_t slotOff = offsets[i];

        if (!trySlotMagic(slotOff)) {
            LOG_DEBUG("readMeta: slot %zu at offset %llu — bad magic or unreadable", i, slotOff);
            continue; // Bad magic or unreadable — try next slot.
        }

        slotsWithValidMagic++;
        LOG_DEBUG("readMeta: slot %zu at offset %llu — valid magic, m=%u KiB, t=%u, p=%u",
                  i, slotOff, header_->getKdfMKib(), header_->getKdfT(), header_->getKdfP());

        // Re-derivation check: if we already have a KEK but a previous slot
        // failed auth, check whether THIS slot has different KDF inputs (salt
        // or params) from the ones used to derive the KEK.  If different →
        // the KEK-source slot was corrupted, allow one re-derivation.  If all
        // inputs match → wrong password, re-deriving gives the same wrong KEK.
        if (kekDerived && kekDerivations < MAX_KEK_DERIVATIONS &&
            (header_->getSalt() != kekSalt ||
             header_->getKdfMKib() != kekMKib ||
             header_->getKdfT() != kekT ||
             header_->getKdfP() != kekP)) {
            kekDerived = false;
        }

        try {
            if (!kekDerived) {
                // Derive KEK from this slot's KDF params + salt.
                // validateKdfParamsAndDeriveKek() reads password_ but zeroes it
                // after use; we rely on passwordCopy for any second derivation.
                // Restore password_ from our copy before each derivation call.
                password_.assign(passwordCopy.begin(), passwordCopy.end());
                validateKdfParamsAndDeriveKek(); // zeroes password_ on success
                kekDerived = true;
                kekDerivations++;
                kekSalt = header_->getSalt();
                kekMKib = header_->getKdfMKib();
                kekT    = header_->getKdfT();
                kekP    = header_->getKdfP();
                LOG_DEBUG("readMeta: KEK derived (derivation #%d)", kekDerivations);
            }
            // KEK is ready.  Authenticate first (HMAC), then decrypt (DEK unwrap).
            // Authenticate-then-decrypt: verifying the HMAC before touching the
            // ciphertext prevents padding-oracle / chosen-ciphertext attacks.
            verifyHeaderHmac();
            unwrapDekFromHeader();
            activeSlotOffset_ = slotOff;
            recovered = true;
            LOG_DEBUG("readMeta: recovered from slot %zu at offset %llu", i, slotOff);
            break;
        } catch (const std::exception& ex) {
            lastError = ex.what();
            LOG_DEBUG("readMeta: slot %zu auth failed: %s", i, ex.what());
            // If the KEK was derived but auth failed, the KEK-source slot's salt
            // might have been corrupted.  We defer the re-derivation decision to
            // the NEXT slot: when trySlotMagic() loads slot i+1, we compare its
            // salt to kekSalt.  Same salt → wrong password (re-derive is useless);
            // different salt → corruption, worth one re-derivation.
            // The check lives at the TOP of the next iteration (see below).
        }
    }

    // Zero the local password copy and the member on all exit paths.
    Botan::secure_scrub_memory(passwordCopy.data(), passwordCopy.size());
    passwordCopy.clear();
    if (!password_.empty()) {
        Botan::secure_scrub_memory(password_.data(), password_.size());
        password_.clear();
    }

    if (!recovered) {
        if (slotsWithValidMagic > 0) {
            throw std::runtime_error(
                "Wrong password or container corrupted: " +
                std::to_string(slotsWithValidMagic) +
                " slot(s) had valid magic but all failed authentication: " + lastError);
        } else {
            throw std::runtime_error(
                "Invalid container: no slot has valid magic bytes");
        }
    }

    readFilesTable();
    LOG_DEBUG("readMeta: complete, %zu file(s) in table, container_size=%llu",
              fileTable_.getFilesTable().size(), header_->getContainerSize());
}

void FileManager::extract(const std::string& pathToOutputFolder) {
    std::vector<FileEntry> entries;
    if (filesList_.empty()) {
        entries = fileTable_.getFilesTable();
    } else {
        for (const auto& fName : filesList_)
            entries.push_back(fileTable_.getFileInfoByName(fName));
    }

    LOG_DEBUG("extract: output='%s', files=%zu", pathToOutputFolder.c_str(), entries.size());

    size_t workerCount = std::max(2u, std::thread::hardware_concurrency());
    DecryptPipeline::Config cfg{workerCount, 2 * workerCount};
    DecryptPipeline pipeline(*crypto_, cfg);
    auto fio = makeFragmentedIO();
    std::atomic<bool> noCancel{false};
    pipeline.run(entries, fio, pathToOutputFolder, noCancel, nullptr);

    for (const auto& name : pipeline.checksumFailures())
        LOG_WARN("FileManager: File '%s' decrypted unsuccessfully, wrong checksum", name.c_str());

    LOG_DEBUG("extract: complete, %zu file(s) extracted", entries.size());
}

void FileManager::write() {
    LOG_DEBUG("FileManager::write: enter");
    if (filesList_.empty()) {
        throw std::runtime_error("No input files specified for create");
    }

    auto t0 = std::chrono::steady_clock::now();
    createContainerFile();
    auto t1 = std::chrono::steady_clock::now();
    LOG_INFO("write: createContainerFile took %lld ms",
             std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count());

    initCryptoForCreate();
    auto t2 = std::chrono::steady_clock::now();
    LOG_INFO("write: initCryptoForCreate (KDF + wrapDEK) took %lld ms",
             std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count());

    computeAndStoreHeaderHmac();

    uint64_t available = computeAvailableDataCapacity();
    uint64_t required  = computeRequiredDataBytes();
    if (required > available) {
        throw std::runtime_error(
            "Files too large for container: need " + std::to_string(required) +
            " bytes of data capacity but container only provides " +
            std::to_string(available) + " bytes");
    }

    writeAllSlots();
    auto t3 = std::chrono::steady_clock::now();
    LOG_INFO("write: writeAllSlots took %lld ms",
             std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t2).count());

    uint64_t dataStart = header_->getHeaderSize() + header_->getMaxTableSize();
    size_t endPos = writeChunks(static_cast<size_t>(dataStart));
    fileTable_.setNextWriteOffset(static_cast<uint64_t>(endPos));
    auto t4 = std::chrono::steady_clock::now();
    LOG_INFO("write: writeChunks (pipeline encryption) took %lld ms",
             std::chrono::duration_cast<std::chrono::milliseconds>(t4 - t3).count());

    writeFileTableToAllSlots();
    auto t5 = std::chrono::steady_clock::now();
    LOG_INFO("write: writeFileTableToAllSlots took %lld ms",
             std::chrono::duration_cast<std::chrono::milliseconds>(t5 - t4).count());
    LOG_INFO("write: TOTAL %lld ms",
             std::chrono::duration_cast<std::chrono::milliseconds>(t5 - t0).count());
}

void FileManager::add() {
    // Resume from the persisted end-of-data position.

    uint64_t dataEnd = fileTable_.getNextWriteOffset();
    uint64_t containerSize = header_->getContainerSize();
    LOG_DEBUG("add: %zu file(s) to add, data_end=%llu, container_size=%llu",
              filesList_.size(), dataEnd, containerSize);
    if (dataEnd >= containerSize) {
        throw std::runtime_error("Container is full: no free space for additional files");
    }

    // Sum slot reserved areas that fall within [dataEnd, containerSize).
    // Slots never overlap (minimum container size guarantees it).
    uint64_t totalReserved = 0;
    uint64_t slotReserved = header_->getHeaderSize() + header_->getMaxTableSize();
    for (size_t i = 0; i < SLOT_COUNT; ++i) {
        uint64_t begin = std::max(slotOffsets_[i], dataEnd);
        uint64_t end   = std::min(slotOffsets_[i] + slotReserved, containerSize);
        if (begin < end) {
            totalReserved += end - begin;
        }
    }

    uint64_t freeCapacity = (containerSize - dataEnd) - totalReserved;
    uint64_t required = computeRequiredDataBytes();
    LOG_DEBUG("add: free_capacity=%llu, required=%llu, reserved_by_slots=%llu",
              freeCapacity, required, totalReserved);
    if (required > freeCapacity) {
        throw std::runtime_error(
            "Files too large for remaining container space: need " +
            std::to_string(required) + " bytes but only " +
            std::to_string(freeCapacity) + " bytes remain");
    }

    size_t endPos = writeChunks(static_cast<size_t>(dataEnd));
    fileTable_.setNextWriteOffset(static_cast<uint64_t>(endPos));
    writeFileTableToAllSlots();
    LOG_DEBUG("add: complete, new data_end=%zu, file_count=%zu",
              endPos, fileTable_.getFilesTable().size());
}

// ---- print helpers ----

void FileManager::printHeader() const {
    std::cout << header_->to_string();
}

void FileManager::printFilesTable() const {
    std::cout << fileTable_.to_string();
}

// ---- private helpers ----

FragmentedIO FileManager::makeFragmentedIO() {
    FragmentedIO fio;
    fio.write = [this](const char* data, size_t size) -> uint64_t {
        return writeFragmented(data, size);
    };
    fio.read = [this](char* buf, size_t size) {
        readFragmented(buf, size);
    };
    fio.skipSlots = [this](uint64_t pos) -> uint64_t {
        return skipSlots(pos);
    };
    fio.seekWrite = [this](uint64_t pos) {
        containerStream_->seekp(static_cast<std::streamoff>(pos), std::ios::beg);
    };
    fio.tellWrite = [this]() -> uint64_t {
        return static_cast<uint64_t>(containerStream_->tellp());
    };
    fio.seekRead = [this](uint64_t pos) {
        containerStream_->clear();
        containerStream_->seekg(static_cast<std::streamoff>(pos), std::ios::beg);
    };
    return fio;
}

size_t FileManager::writeChunks(size_t offset) {
    size_t workerCount = std::max(2u, std::thread::hardware_concurrency());
    EncryptPipeline::Config cfg{workerCount, 2 * workerCount};
    EncryptPipeline pipeline(*crypto_, cfg);
    auto fio = makeFragmentedIO();
    std::atomic<bool> noCancel{false};
    pipeline.run(filesList_, fio, fileTable_, *header_,
                 static_cast<uint64_t>(offset), noCancel, nullptr);
    return static_cast<size_t>(pipeline.endOffset());
}

void FileManager::readHeader() {
    containerStream_->seekg(0, std::ios::beg);
    HeaderBuffer headerBuffer;
    char* headerPtr = reinterpret_cast<char*>(headerBuffer.data());
    if (!containerStream_->read(headerPtr, HEADER_SIZE).good()) {
        throw std::runtime_error("Failed to read header");
    }
    header_->read(headerBuffer);
    LOG_DEBUG("readHeader: container_size=%llu, block_size=%u, "
              "file_table_size=%u, max_table_size=%u, kdf(m=%u KiB, t=%u, p=%u)",
              header_->getContainerSize(), header_->getChunkSize(),
              header_->getFileTableSize(), header_->getMaxTableSize(),
              header_->getKdfMKib(), header_->getKdfT(), header_->getKdfP());
}

void FileManager::readFilesTable() {
    // Table is located immediately after the active header slot.
    // activeSlotOffset_ is 0 for slot 0, or the recovered backup slot's byte offset.
    uint64_t tableOffset = activeSlotOffset_ + header_->getHeaderSize();

    // Spec 4.2.4: file_table_size includes nonce (12) + ciphertext + auth tag (16).
    uint32_t encSize = header_->getFileTableSize();
    LOG_DEBUG("readFilesTable: table_offset=%llu, enc_size=%u", tableOffset, encSize);
    if (encSize <= NONCE_SIZE + AUTH_TAG_SIZE) {
        LOG_DEBUG("readFilesTable: table empty (enc_size <= overhead), skipping");
        return;
    }
    size_t plainSize = encSize - NONCE_SIZE - AUTH_TAG_SIZE;

    containerStream_->seekg(static_cast<std::streamoff>(tableOffset), std::ios::beg);
    std::string encData(encSize, '\0');
    char* ptr = encData.data();
    if (!containerStream_->read(ptr, static_cast<std::streamsize>(encSize)).good()) {
        throw std::runtime_error("Failed to read file table");
    }

    std::string decrypted(plainSize, '\0');
    crypto_->decrypt(ptr, decrypted.data(), plainSize);
    fileTable_.deserialize(decrypted);
    LOG_DEBUG("readFilesTable: decrypted %zu bytes, %zu file(s) loaded",
              plainSize, fileTable_.getFilesTable().size());
}

void FileManager::readChunks(std::ofstream& output, const FileEntry& file) {
    fileTable_.resetChecksum();
    containerStream_->clear();
    containerStream_->seekg(static_cast<std::streamoff>(file.offset), std::ios::beg);

    std::vector<char> buf(ENCRYPTED_BLOCK_SIZE);
    std::vector<char> bufDecrypted(BLOCK_SIZE);
    size_t remaining = file.size;
    for (size_t i = 0; i < file.chunks; ++i) {
        // readFragmented handles skipping over slot areas internally on every
        // iteration, so no manual skipSlots is needed here.
        size_t plainSize = std::min(remaining, static_cast<size_t>(BLOCK_SIZE));
        size_t encSize   = plainSize + NONCE_SIZE + AUTH_TAG_SIZE;

        readFragmented(buf.data(), encSize);
        crypto_->decrypt(buf.data(), bufDecrypted.data(), plainSize);
        fileTable_.updateChecksum(bufDecrypted.data(), plainSize);
        if (!output.write(bufDecrypted.data(), static_cast<std::streamsize>(plainSize)).good()) {
            throw std::runtime_error("Failed to extract file '" + file.name +
                                     "': failed write chunk");
        }
        remaining -= plainSize;
    }
}

bool FileManager::checkSumVerify(const FileEntry& file) {
    std::string checkSum = fileTable_.getChecksum();
    return checkSum == file.checksum_sha256;
}
