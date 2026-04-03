#include "FileManager.h"
#include "Header.h"

#include "botan/mem_ops.h"
#include "botan/secmem.h"

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <ios>
#include <iostream>
#include <istream>
#include <memory>
#include <stdexcept>

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

    int streamOpenFlags = std::ios::binary | std::ios::in | std::ios::out;
    if (createNew) {
        streamOpenFlags |= std::ios::trunc;
    }

    containerStream_ = std::make_unique<std::fstream>(containerFilePath_, streamOpenFlags);
    if (!containerStream_->is_open()) {
        throw std::runtime_error("Container file does not exist: " + containerFilePath_);
    }

    if (!createNew) {
        readMeta();
    }
    slotOffsets_ = computeSlotOffsets();
}

// ---- slot helpers ----

std::array<uint64_t, SLOT_COUNT> FileManager::computeSlotOffsets() const {
    std::array<uint64_t, SLOT_COUNT> offsets{0};
    for (size_t i = 1; i < SLOT_COUNT; ++i) {
        offsets[i] = (header_->getContainerSize() * i * 25 / 100 / header_->getHeaderSize())
            * header_->getHeaderSize();
    }
    return offsets;
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
        int64_t cur = skipSlots(containerStream_->tellp());
        if (cur != containerStream_->tellp()) {
            containerStream_->seekp(cur, std::ios::beg);
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
        int64_t cur = skipSlots(containerStream_->tellg());
        if (cur != containerStream_->tellg()) {
            containerStream_->seekg(cur, std::ios::beg);
        }

        size_t canRead = bytesUntilNextSlot(cur, size - totalRead);
        auto& res = containerStream_->read(buf + totalRead, static_cast<std::streamsize>(canRead));
        if (!res.good()) {
            throw std::runtime_error("readFragmented: read failed");
        }
        totalRead += canRead;
    }
}

// ---- crypto helpers ----

void FileManager::initCryptoForCreate() {
    crypto_->generateSalt(header_->getSaltData());
    crypto_->deriveKek(password_, *header_);

    // Zero the password immediately after deriving the KEK.
    Botan::secure_scrub_memory(password_.data(), password_.size());
    password_.clear();

    // Wrap the random DEK with the derived KEK.
    std::array<uint8_t, NONCE_SIZE> dekNonce{};
    std::array<uint8_t, DEK_SIZE>   encryptedDek{};
    std::array<uint8_t, AUTH_TAG_SIZE> dekAuthTag{};
    crypto_->wrapDek(dekNonce, encryptedDek, dekAuthTag);

    header_->setDekNonce(dekNonce);
    header_->setEncryptedDek(encryptedDek);
    header_->setDekAuthTag(dekAuthTag);
}

void FileManager::initCryptoForRead() {
    // Validate KDF parameters before use: reject values that could cause OOM or
    // excessive runtime from a crafted header (DoS). These bounds are checked
    // before HMAC verification to avoid the cost of a full Argon2id invocation
    // with attacker-controlled parameters.
    uint32_t mKib = header_->getKdfMKib();
    uint32_t t     = header_->getKdfT();
    uint32_t p     = header_->getKdfP();
    if (mKib < 8 || mKib > 1048576 || t < 1 || t > 100 || p < 1 || p > 64) {
        throw std::runtime_error("Header KDF parameters out of acceptable range");
    }

    // Derive KEK from the password and the salt read from the header,
    // using the KDF parameters stored in the header.
    crypto_->deriveKek(password_, *header_);

    // Zero the password immediately after deriving the KEK.
    Botan::secure_scrub_memory(password_.data(), password_.size());
    password_.clear();

    // Unwrap DEK — throws on wrong password or corrupt header.
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
    uint64_t slotReserved = header_->getHeaderSize() + header_->getMaxTableSize();
    return containerSize - SLOT_COUNT * slotReserved;
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
        required += encryptedSizeCalc(sz);
    }

    return required;
}

// ---- container creation helpers ----

void FileManager::createContainerFile() {
    uint64_t containerSize = header_->getContainerSize();
    uint32_t maxTableSize = header_->getMaxTableSize();

    uint64_t minSize = 4ULL * (header_->getHeaderSize() + maxTableSize);
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

    // Pre-allocate: seek to last byte and write one zero byte.
    containerStream_->seekp(static_cast<std::streamoff>(containerSize - 1), std::ios::beg);
    containerStream_->put('\0');
    if (!containerStream_->good()) {
        throw std::runtime_error("Failed to pre-allocate container to " +
                                 std::to_string(containerSize) + " bytes");
    }
    // TODO: replace flush() with fsync/FlushFileBuffers for real crash safety (spec 4.6.2)
    containerStream_->flush();
}

void FileManager::writeHeaderAt(uint64_t slotOffset) {
    containerStream_->seekp(static_cast<std::streamoff>(slotOffset), std::ios::beg);
    const char* buf = reinterpret_cast<const char*>(header_->buffer().data());
    if (!containerStream_->write(buf, HEADER_SIZE).good()) {
        throw std::runtime_error("Failed to write header at offset " +
                                 std::to_string(slotOffset));
    }
}

void FileManager::writeFileTableAt(uint64_t slotOffset, const std::vector<char>& encryptedTable) {
    uint64_t tableOffset = slotOffset + header_->getHeaderSize();
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
    //   - Try slot 0 first (magic + HMAC).
    //   - If slot 0 magic is invalid (unreadable/truncated), fall back to slots 1–3.
    //   - HMAC failure is treated as fatal (wrong password or deliberate corruption).
    //     Falling back to backup slots on HMAC failure would silently bypass a
    //     security check and confuse the "wrong password" case.
    //
    // Rationale: a crash mid-write typically leaves the primary slot partially
    // written (bad magic or truncated read). Backup slots retain the previous
    // valid state. An HMAC mismatch on a slot with valid magic means either a
    // wrong password or corruption of specific fields — neither of which is
    // recoverable by trying another slot written with the same password.

    // Helper: read one header slot. Returns true if magic is valid.
    auto trySlotMagic = [this](uint64_t offset) -> bool {
        containerStream_->clear(); // clear any fail/eof bits before seek
        containerStream_->seekg(static_cast<std::streamoff>(offset), std::ios::beg);
        HeaderBuffer hdrBuf;
        char* hdrPtr = reinterpret_cast<char*>(hdrBuf.data());
        if (!containerStream_->read(hdrPtr, HEADER_SIZE).good()) {
            return false;
        }
        header_->read(hdrBuf);
        return header_->validate();
    };

    // Step 1: try slot 0.
    if (trySlotMagic(0)) {
        // Slot 0 magic is valid — authenticate and use it.
        activeSlotOffset_ = 0;
        initCryptoForRead();
        verifyHeaderHmac();
        readFilesTable();
        return;
    }

    // Slot 0 magic failed (e.g. partial overwrite during crash).
    // We cannot compute backup offsets without containerSize, which comes from
    // the header. Use a fallback scan: read each backup slot by trying fixed
    // fractions of the file size.
    containerStream_->seekg(0, std::ios::end);
    uint64_t fileSize = static_cast<uint64_t>(containerStream_->tellg());
    if (fileSize == 0) {
        throw std::runtime_error("Invalid container: file is empty");
    }

    // Attempt slots 1, 2, 3 using the on-disk file size as a proxy for
    // container_size (they should match for a well-formed container).
    const uint32_t hdrSize = HEADER_SIZE;
    bool recovered = false;

    // Use secure_vector<char> so the password copy is scrubbed on all exit paths,
    // including exception unwinds — plain std::string does not guarantee zeroing.
    Botan::secure_vector<char> savedPassword(password_.begin(), password_.end());
    std::string lastError = "all slots unreadable";

    for (size_t i = 1; i < SLOT_COUNT; ++i) {
        uint64_t slotOff = computeSlotOffset(fileSize, SLOT_PERCENTAGES[i], hdrSize);
        if (!trySlotMagic(slotOff)) {
            continue; // Bad magic in this backup slot, try next.
        }

        // Restore password (may have been cleared by a previous failed attempt).
        password_.assign(savedPassword.begin(), savedPassword.end());

        try {
            initCryptoForRead();
            verifyHeaderHmac();
            activeSlotOffset_ = slotOff;
            recovered = true;
            break;
        } catch (const std::exception& ex) {
            lastError = ex.what();
            Botan::secure_scrub_memory(password_.data(), password_.size());
            password_.clear();
        }
    }
    // secure_vector destructor scrubs savedPassword automatically.

    if (!recovered) {
        throw std::runtime_error(
            "Invalid container: primary header slot has wrong magic bytes and "
            "all backup slots failed: " + lastError);
    }

    readFilesTable();
}

void FileManager::extract(const std::string& pathToOutputFolder) {
    // Helper: validate a file name from the container against path traversal.
    auto safeFilename = [](const std::string& name) -> std::string {
        auto safe = std::filesystem::path(name).filename();
        if (safe.empty() || safe == "." || safe == "..") {
            throw std::runtime_error("Unsafe file name in container: " + name);
        }
        return safe.string();
    };

    // If no specific files were requested (-f not given), extract all files.
    if (filesList_.empty()) {
        for (const FileEntry& fEntry : fileTable_.getFilesTable()) {
            std::string safeName = safeFilename(fEntry.name);
            std::string outputPath = pathToOutputFolder + "/" + safeName;
            std::ofstream output(outputPath, std::ios::binary);
            if (!output.is_open()) {
                throw std::runtime_error("Cannot open output file: " + outputPath);
            }
            readChunks(output, fEntry);
            if (!checkSumVerify(fEntry)) {
                printf("FileManager: File '%s' decrypted unsuccessfully, wrong checksum\n",
                       fEntry.name.c_str());
            }
            output.close();
        }
    } else {
        for (const std::string& fName : filesList_) {
            std::string safeName = safeFilename(fName);
            std::string outputPath = pathToOutputFolder + "/" + safeName;
            std::ofstream output(outputPath, std::ios::binary);
            if (!output.is_open()) {
                throw std::runtime_error("Cannot open output file: " + outputPath);
            }
            const FileEntry& fEntry = fileTable_.getFileInfoByName(fName);
            readChunks(output, fEntry);
            if (!checkSumVerify(fEntry)) {
                printf("FileManager: File '%s' decrypted unsuccessfully, wrong checksum\n",
                       fName.c_str());
            }
            output.close();
        }
    }
}

void FileManager::write() {
    if (filesList_.empty()) {
        throw std::runtime_error("No input files specified for create");
    }
    createContainerFile();
    // Set up crypto: generate salt, derive KEK, wrap DEK, store in header.
    initCryptoForCreate();
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

    // Data starts right after slot 0 (header + file table).
    uint64_t dataStart = header_->getHeaderSize() + header_->getMaxTableSize();
    size_t endPos = writeChunks(static_cast<size_t>(dataStart));
    fileTable_.setNextWriteOffset(static_cast<uint64_t>(endPos));

    writeFileTableToAllSlots();
}

void FileManager::add() {
    // Resume from the persisted end-of-data position.
    
    uint64_t dataEnd = fileTable_.getNextWriteOffset();
    uint64_t containerSize = header_->getContainerSize();
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
    if (required > freeCapacity) {
        throw std::runtime_error(
            "Files too large for remaining container space: need " +
            std::to_string(required) + " bytes but only " +
            std::to_string(freeCapacity) + " bytes remain");
    }

    size_t endPos = writeChunks(static_cast<size_t>(dataEnd));
    fileTable_.setNextWriteOffset(static_cast<uint64_t>(endPos));
    writeFileTableToAllSlots();
}

// ---- print helpers ----

void FileManager::printHeader() const {
    std::cout << header_->to_string() << std::endl;
}

void FileManager::printFilesTable() const {
    std::cout << fileTable_.to_string() << std::endl;
}

// ---- private helpers ----

size_t FileManager::writeChunks(size_t offset) {
    containerStream_->seekp(static_cast<std::streamoff>(offset), std::ios::beg);
    std::vector<char> chunk(BLOCK_SIZE);
    std::vector<char> encryptedChunk(ENCRYPTED_BLOCK_SIZE);

    for (const auto& file : filesList_) {
        // Reset the checksum hasher before each file to guarantee a clean slate,
        // even if the previous file left residual state (e.g. zero-byte file).
        fileTable_.resetChecksum();

        // Advance past any slot area before starting this file.
        // Use skipSlots to skip the starting position if it's inside a slot.
        uint64_t fileStartOffset = static_cast<uint64_t>(containerStream_->tellp());
        fileStartOffset = skipSlots(fileStartOffset);
        containerStream_->seekp(static_cast<std::streamoff>(fileStartOffset), std::ios::beg);
        if (!containerStream_->good()) {
            throw std::runtime_error(
                "writeChunks: seekp to data zone offset " +
                std::to_string(fileStartOffset) + " failed");
        }
        fileStartOffset = static_cast<uint64_t>(containerStream_->tellp());

        std::ifstream input(file, std::ios::binary);
        if (!input.is_open()) {
            throw std::runtime_error("Cannot open input file: " + file);
        }

        // Track actual bytes read from the source file to avoid a TOCTOU race
        // between writing data and recording the file size in the table.
        size_t actualBytesRead = 0;

        while (input.read(chunk.data(), BLOCK_SIZE)) {
            // writeFragmented handles skipping over slot areas internally on
            // every iteration, so no manual skipSlots is needed here.
            fileTable_.updateChecksum(chunk.data(), BLOCK_SIZE);
            crypto_->encrypt(chunk.data(), encryptedChunk.data(), BLOCK_SIZE);
            writeFragmented(encryptedChunk.data(), ENCRYPTED_BLOCK_SIZE);
            actualBytesRead += BLOCK_SIZE;
        }
        if (size_t lastBytes = static_cast<size_t>(input.gcount()); lastBytes > 0) {
            size_t lastEncSize = lastBytes + NONCE_SIZE + AUTH_TAG_SIZE;
            fileTable_.updateChecksum(chunk.data(), lastBytes);
            crypto_->encrypt(chunk.data(), encryptedChunk.data(), lastBytes);
            writeFragmented(encryptedChunk.data(), lastEncSize);
            actualBytesRead += lastBytes;
        }
        fileTable_.addFileEntry(file, fileTable_.getChecksum(), fileStartOffset, actualBytesRead);
        header_->increaseFileCount();
    }
    return static_cast<size_t>(containerStream_->tellp());
}

void FileManager::readHeader() {
    containerStream_->seekg(0, std::ios::beg);
    HeaderBuffer headerBuffer;
    char* headerPtr = reinterpret_cast<char*>(headerBuffer.data());
    if (!containerStream_->read(headerPtr, HEADER_SIZE).good()) {
        throw std::runtime_error("Failed to read header");
    }
    header_->read(headerBuffer);
}

void FileManager::readFilesTable() {
    // Table is located immediately after the active header slot.
    // activeSlotOffset_ is 0 for slot 0, or the recovered backup slot's byte offset.
    uint64_t tableOffset = activeSlotOffset_ + header_->getHeaderSize();

    // Spec 4.2.4: file_table_size includes nonce (12) + ciphertext + auth tag (16).
    uint32_t encSize = header_->getFileTableSize();
    if (encSize <= NONCE_SIZE + AUTH_TAG_SIZE) {
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
