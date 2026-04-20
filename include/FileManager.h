#ifndef FILE_MANAGER_H
#define FILE_MANAGER_H

#include "CryptoManager.h"
#include "FragmentedIO.h"
#include "Header.h"
#include "FileTable.h"
#include "KdfProfiles.h"
#include "NativeFile.h"

#include <array>
#include <chrono>
#include <memory>
#include <string>
#include <vector>

constexpr const char* CONTAINER_FILE_NAME = "container.scef";

// Number of header+table slots in a container.
constexpr size_t SLOT_COUNT = 4;

// Percentages at which the four slots reside: 0%, 25%, 50%, 75%.
constexpr std::array<size_t, SLOT_COUNT> SLOT_PERCENTAGES = {0, 25, 50, 75};

// Compute the byte offset of a header slot.
// Formula from spec section 4.1:
//   slot_offset(N%) = floor(container_size * N / 100 / header_size) * header_size
// For N=0 this always returns 0.
[[nodiscard]] inline uint64_t computeSlotOffset(uint64_t container_size, size_t percent,
                                                   uint32_t header_size) {
    if (percent == 0) return 0;
    return (container_size * percent / 100 / header_size) * header_size;
}

// Compute all four slot offsets from a container (or file) size and header size.
// Uses the same formula as computeSlotOffset for each percentage in SLOT_PERCENTAGES.
[[nodiscard]] inline std::array<uint64_t, SLOT_COUNT>
computeSlotOffsets(uint64_t containerOrFileSize, uint32_t headerSize) {
    std::array<uint64_t, SLOT_COUNT> out{};
    for (size_t i = 1; i < SLOT_COUNT; ++i) {
        out[i] = (containerOrFileSize * SLOT_PERCENTAGES[i] / 100 / headerSize) * headerSize;
    }
    return out;
}

class FileManager {
public:
    FileManager();
    ~FileManager() = default;
    FileManager(const FileManager&) = delete;
    FileManager& operator=(const FileManager&) = delete;
    FileManager(FileManager&&) = delete;
    FileManager& operator=(FileManager&&) = delete;

    // create_new=true: container_size must be non-zero; creates and pre-allocates a new container.
    // create_new=false: file must already exist; throws std::runtime_error if it does not.
    // password: used to derive KEK and authenticate the DEK.
    void init(const std::vector<std::string>& filesList, const std::string& pathToDir,
              uint64_t container_size = 0, uint32_t max_table_size = DEFAULT_MAX_TABLE_SIZE,
              bool create_new = false,
              const std::string& password = "");
    // Configure KDF parameters for container creation.
    // Must be called BEFORE write() when creating a new container.
    //   profile != None  → look up params from the profile table (m_kib/t/p are ignored).
    //   profile == None  → use the supplied m_kib, t, p directly (custom mode).
    void setKdfParams(EKDFProfile profile, uint32_t m_kib, uint32_t t, uint32_t p);

    void readMeta();
    void extract(const std::string& pathToOutputFolder);
    void write();
    void add();

    // Replace the file list without re-initializing the container.
    // Used by the GUI to reuse an already-open FileManager for add/extract.
    void setFilesList(const std::vector<std::string>& filesList) { filesList_ = filesList; }

    void printHeader() const;
    void printFilesTable() const;

    // Returned reference is valid only while this FileManager instance is alive.
    const std::vector<FileEntry>& getFilesTable() const { return fileTable_.getFilesTable(); }

private:
    // Returns array of slot offsets computed from header fields.
    std::array<uint64_t, SLOT_COUNT> computeSlotOffsets() const;

    // Returns true if [pos, pos+size) overlaps any slot reserved area.
    // A slot reserved area is [slot_offset, slot_offset + header_size + max_table_size).
    bool overlapsSlot(uint64_t pos, uint64_t size,
                      const std::array<uint64_t, SLOT_COUNT>& slots) const;

    // Advance pos past any slot area it would land on.
    uint64_t skipSlots(uint64_t pos) const;

    // How many contiguous bytes can be transferred from 'cur' before hitting a slot.
    // 'cur' must not be inside a slot (call skipSlots first).
    size_t bytesUntilNextSlot(uint64_t cur, size_t remaining) const;

    // Write exactly 'size' bytes from 'data' to the container at absolute 'offset',
    // skipping over any slot reserved areas mid-write.
    // Returns the container position immediately after the last written byte.
    uint64_t writeFragmented(uint64_t offset, const char* data, size_t size);

    // Read exactly 'size' bytes into 'buf' from 'offset', skipping over slot areas.
    // Returns the physical file offset immediately after the last byte read.
    // Throws on short read.
    uint64_t readFragmented(uint64_t offset, char* buf, size_t size);

    // Create (or truncate) the container file and pre-allocate it to container_size_.
    void createContainerFile();

    // Write header + empty table at all four slots.
    void writeAllSlots();

    // Write just the file table at all four slot positions (after header).
    void writeFileTableToAllSlots();

    // Write header bytes at a given slot offset.
    void writeHeaderAt(uint64_t slotOffset);

    // Write file table bytes (zero-padded to max_table_size) at slot_offset + header_size.
    void writeFileTableAt(uint64_t slot_offset, const std::vector<char>& encrypted_table);

    size_t writeChunks(size_t startOffset);

    // Build a FragmentedIO facade that routes pipeline reads/writes through
    // this FileManager's containerFile_, skipping over slot areas.
    FragmentedIO makeFragmentedIO();

    // Return the total number of bytes available for encrypted data blocks,
    // i.e. container_size minus the four slot reserved areas
    // (each slot = header_size + max_table_size).
    // Accounts for the fact that slots can overlap with each other when the
    // container is very small (in that case available capacity is 0).
    [[nodiscard]] uint64_t computeAvailableDataCapacity() const;

    // Compute the encrypted storage footprint of files_ (queued in filesList_)
    // including per-chunk overhead (NONCE_SIZE + AUTH_TAG_SIZE per BLOCK_SIZE chunk).
    [[nodiscard]] uint64_t computeRequiredDataBytes() const;

    // Initialize crypto for a new container (generate salt, derive KEK, wrap DEK).
    // Updates the header with the salt, dek_nonce, encrypted_dek, and dek_auth_tag.
    void initCryptoForCreate();

    // Validate KDF parameters from the current header and derive the KEK from
    // password_ + header salt.  Zeros password_ after use.
    // Must be called once per open, before any per-slot unwrapDek calls.
    // Throws std::runtime_error if KDF params are out of range or Argon2id fails.
    void validateKdfParamsAndDeriveKek();

    // Unwrap (decrypt) the DEK from the current header using the already-derived KEK.
    // Must be called after validateKdfParamsAndDeriveKek().
    // Throws std::runtime_error on wrong password or corrupt DEK.
    void unwrapDekFromHeader();

    // Compute and store header HMAC. Call after all header fields are set and
    // crypto is ready.
    void computeAndStoreHeaderHmac();

    // Verify header HMAC. Throws std::runtime_error if mismatch.
    // Must be called after validateKdfParamsAndDeriveKek().
    void verifyHeaderHmac();

    void readHeader();
    void readFilesTable();
    void readChunks(NativeFile& output, uint64_t& outputOffset, const FileEntry& file);
    bool checkSumVerify(const FileEntry& file);

    struct FragmentedWriteStats {
        std::chrono::nanoseconds seekTime{0};
        std::chrono::nanoseconds writeTime{0};
        uint64_t bytesWritten = 0;
        uint64_t writeCalls = 0;
        uint64_t seekCalls = 0;
        uint64_t slotSkips = 0;
        uint64_t fragmentedWrites = 0;
    };

    void resetFragmentedWriteStats();
    void logFragmentedWriteStats() const;

    std::unique_ptr<Header> header_;
    FileTable fileTable_;
    std::array<uint64_t, SLOT_COUNT> slotOffsets_ = {0};

    NativeFile containerFile_;
    std::unique_ptr<CryptoManager> crypto_;
    std::string containerFilePath_;
    std::vector<std::string> filesList_;
    std::string password_;
    FragmentedWriteStats fragmentedWriteStats_{};

    uint64_t container_size_param_ = 0;   // size requested at init()
    uint64_t activeSlotOffset_   = 0;   // byte offset of the slot used by readMeta()
};

#endif // FILE_MANAGER_H
