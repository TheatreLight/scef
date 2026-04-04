#ifndef FILE_MANAGER_H
#define FILE_MANAGER_H

#include "CryptoManager.h"
#include "Header.h"
#include "FileTable.h"

#include <array>
#include <fstream>
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

class FileManager {
public:
    FileManager();
    ~FileManager();
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
    void readMeta();
    void extract(const std::string& pathToOutputFolder);
    void write();
    void add();

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

    // Write exactly 'size' bytes from 'data' to the container, advancing the
    // write position and skipping over any slot reserved areas mid-write.
    // Returns the container position immediately after the last written byte
    // (which may be inside a slot area if the write ended right at a slot start).
    uint64_t writeFragmented(const char* data, size_t size);

    // Read exactly 'size' bytes into 'buf' from the container, advancing the
    // read position and skipping over any slot reserved areas mid-read.
    // Must be called with the stream positioned at the start of the fragmented data.
    void readFragmented(char* buf, size_t size);

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

    // Return the total number of bytes available for encrypted data blocks,
    // i.e. container_size minus the four slot reserved areas
    // (each slot = header_size + max_table_size).
    // Accounts for the fact that slots can overlap with each other when the
    // container is very small (in that case available capacity is 0).
    [[nodiscard]] uint64_t computeAvailableDataCapacity() const;

    // Compute the encrypted storage footprint of files_ (queued in filesList_)
    // including per-chunk overhead (NONCE_SIZE + AUTH_TAG_SIZE per BLOCK_SIZE chunk).
    // file_size_override is used when the caller already knows the total plaintext
    // bytes (e.g. for add(), which may pass the cumulative size of existing data).
    [[nodiscard]] uint64_t computeRequiredDataBytes() const;

    // Initialize crypto for a new container (generate salt, derive KEK, wrap DEK).
    // Updates the header with the salt, dek_nonce, encrypted_dek, and dek_auth_tag.
    void initCryptoForCreate();

    // Initialize crypto for an existing container (read header, derive KEK, unwrap DEK).
    // Must be called after readHeader().
    // Throws std::runtime_error on wrong password or corrupt header.
    void initCryptoForRead();

    // Compute and store header HMAC. Call after all header fields are set and
    // crypto is ready.
    void computeAndStoreHeaderHmac();

    // Verify header HMAC. Throws std::runtime_error if mismatch.
    // Must be called after initCryptoForRead().
    void verifyHeaderHmac();

    void readHeader();
    void readFilesTable();
    void readChunks(std::ofstream& output, const FileEntry& file);
    bool checkSumVerify(const FileEntry& file);

    std::unique_ptr<Header> header_;
    FileTable fileTable_;
    std::array<uint64_t, SLOT_COUNT> slotOffsets_ = {0};

    std::unique_ptr<std::fstream> containerStream_;
    std::unique_ptr<CryptoManager> crypto_;
    std::string containerFilePath_;
    std::vector<std::string> filesList_;
    std::string password_;

    uint64_t container_size_param_ = 0;   // size requested at init()
    uint64_t activeSlotOffset_   = 0;   // byte offset of the slot used by readMeta()
};

#endif // FILE_MANAGER_H
