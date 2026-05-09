# scef_lib Public API

Static library. Header root: `include/`. Requires C++20. Links against Botan 3.x and nlohmann_json.

---

## Header.h

```cpp
#include "Header.h"
```

### Constants

```cpp
constexpr size_t   HEADER_SIZE               = 4096;
constexpr uint32_t BLOCK_SIZE                = 65536;
constexpr uint32_t DEFAULT_MAX_TABLE_SIZE    = 65536;
constexpr uint64_t MAX_CONTAINER_SIZE        = (uint64_t)1 << 41;  // 2 TiB
constexpr uint64_t MINIMAL_CONTAINER_SIZE    = 4ULL * (HEADER_SIZE + DEFAULT_MAX_TABLE_SIZE);
constexpr uint64_t DEFAULT_CONTAINER_SIZE    = MINIMAL_CONTAINER_SIZE + 4ULL * BLOCK_SIZE;
constexpr uint16_t NONCE_SIZE                = 12;
constexpr uint16_t AUTH_TAG_SIZE             = 16;
constexpr uint32_t ENCRYPTED_BLOCK_SIZE      = BLOCK_SIZE + NONCE_SIZE + AUTH_TAG_SIZE;
constexpr size_t   HMAC_PROTECTED_SIZE       = 0x00A0;  // 160 bytes

using HeaderBuffer = std::array<uint8_t, HEADER_SIZE>;
```

Header field offsets: `POSITION_MAGIC`, `POSITION_VERSION_MAJOR`, ..., `POSITION_PADDING` — see `include/Header.h:33-58`.

### class Header

Non-copyable, non-movable.

#### Construction and I/O

```cpp
Header();
// Default-constructs with: AES_256_GCM cipher, Argon2id KDF,
// kdf_m_kib=65536, kdf_t=3, kdf_p=4, all buffers zeroed.
// Note: default member values (current code; subject to change pending src F-4 fix).

void read(const HeaderBuffer& buf);
// Deserialize from a 4096-byte buffer into fields. Does not verify HMAC.

void serialize();
// Write all fields into buffer_. Must be called before buffer() returns valid data
// after any field mutation.

bool validate() const;
// Return true if buffer_ starts with magic "SCEF". Lightweight, no crypto.

const HeaderBuffer& buffer();
// Return the serialized buffer (call serialize() first after mutations).

std::string to_string() const;
// Return human-readable dump of all header fields.
```

#### HMAC Operations

```cpp
void storeHmac(const std::array<uint8_t, 32>& hmac);
// Write hmac into header_hmac_ field and re-serialize the buffer.

[[nodiscard]] std::array<uint8_t, HMAC_PROTECTED_SIZE> hmacProtectedBytes() const;
// Return a copy of buffer_[0x0000..0x009F] (160 bytes).
// Caller uses this to compute or verify the HMAC.

[[nodiscard]] const std::array<uint8_t, 32>& storedHmac() const;
// Return the header_hmac_ field as read from the buffer.
```

#### Setters

```cpp
void setFileTableSize(uint32_t size);
void setMaxTableSize(uint32_t size);
void setContainerSize(uint64_t size);
void increaseFileCount();
void incrementHeaderVersion();

void setKdfProfile(EKDFProfile profile);
void setKdfMKib(uint32_t m_kib);
void setKdfT(uint32_t t);
void setKdfP(uint32_t p);

void setDekNonce(const std::array<uint8_t, NONCE_SIZE>& nonce);
void setEncryptedDek(const std::array<uint8_t, 32>& enc_dek);
void setDekAuthTag(const std::array<uint8_t, AUTH_TAG_SIZE>& tag);
```

#### Getters

```cpp
std::array<uint8_t, 32>& getSaltData();                     // mutable reference
const std::array<uint8_t, 32>& getSalt() const;
const std::array<uint8_t, NONCE_SIZE>& getDekNonce() const;
const std::array<uint8_t, 32>& getEncryptedDek() const;
const std::array<uint8_t, AUTH_TAG_SIZE>& getDekAuthTag() const;
uint32_t getFileTableSize() const;
uint32_t getMaxTableSize() const;
uint32_t getHeaderSize() const;
uint32_t getChunkSize() const;       // returns block_size_
uint64_t getContainerSize() const;
uint32_t getKdfMKib() const;
uint32_t getKdfT() const;
uint32_t getKdfP() const;
```

---

## FileManager.h

```cpp
#include "FileManager.h"
```

### Free Functions

```cpp
constexpr const char* CONTAINER_FILE_NAME = "container.scef";
constexpr size_t SLOT_COUNT = 4;
constexpr std::array<size_t, SLOT_COUNT> SLOT_PERCENTAGES = {0, 25, 50, 75};

[[nodiscard]] inline uint64_t computeSlotOffset(
    uint64_t container_size,
    size_t percent,
    uint32_t header_size);
// Formula: floor(container_size * percent / 100 / header_size) * header_size
// Returns 0 for percent == 0.
```

### class FileManager

Non-copyable, non-movable. Central coordinator for all container I/O.

```cpp
FileManager();
~FileManager();  // closes containerFile_
```

#### Public Methods

```cpp
#include <botan/secmem.h>  // for Botan::secure_vector

void init(
    const std::vector<std::string>& filesList,
    const std::string& pathToDir,
    uint64_t container_size = 0,
    uint32_t max_table_size = DEFAULT_MAX_TABLE_SIZE,
    bool create_new = false,
    const Botan::secure_vector<char>& password = Botan::secure_vector<char>{}
);
// Initialize the FileManager.
// create_new=true: container_size must be non-zero; creates and pre-allocates container.
//                  Validates that files fit before creating the file.
// create_new=false: pathToDir/container.scef must already exist; calls readMeta().
// password: secure_vector ensures heap memory is zeroed on destruction.
// Throws std::runtime_error on any validation or I/O failure.

void setKdfParams(EKDFProfile profile, uint32_t m_kib, uint32_t t, uint32_t p);
// Set KDF parameters for container creation. Call BEFORE write().
// profile != EKDFProfile::None: look up params from profile table; m_kib/t/p ignored.
// profile == EKDFProfile::None: use supplied m_kib, t, p directly (custom mode).

void setCipher(ECipher c);
// Set the cipher for container creation. Call BEFORE write().
// Default: ECipher::AES_256_GCM.

void setProgressCallback(ProgressCallback cb);
// Optional: install a callback invoked at each pipeline stage.
// Signature: void(ProgressStage stage, double fraction).

void write();
// Create flow: createContainerFile → initCrypto → writeAllSlots → writeChunks → writeFileTableToAllSlots.
// Throws if filesList_ is empty or files don't fit.

void add();
// Append files from filesList_ to an existing open container.
// Throws if container is full.

void readMeta();
// Open an existing container: try all 4 slots, find first with valid HMAC.
// Performs crash resilience (at most 2 Argon2id calls).
// Throws std::runtime_error on wrong password, corruption, or no valid slots.

void extract(const std::string& pathToOutputFolder);
// Decrypt and write files. If filesList_ is empty: extract all.
// Otherwise: extract only the named files.
// Path traversal protection: file names sanitized with filesystem::path::filename().
// SHA-256 checksums verified after extraction.

void setFilesList(const std::vector<std::string>& filesList);
// Replace the file list without re-opening the container.
// Used by GUI to reuse an already-open FileManager for add/extract.

void printFilesTable() const;
// Print file table entries (name + size) to stdout via Logger.

const std::vector<FileEntry>& getFilesTable() const;
// Return reference to the deserialized file table. Valid while FileManager is alive.
```

---

## CryptoManager.h

```cpp
#include "CryptoManager.h"
```

Non-copyable, non-movable. Holds key material (KEK and DEK). Both are zeroed via `Botan::secure_scrub_memory` on destruction.

```cpp
constexpr size_t KEK_SIZE = 32;  // bytes
constexpr size_t DEK_SIZE = 32;  // bytes

CryptoManager();
~CryptoManager();  // scrubs kek_ and dek_
```

### Methods

```cpp
#include <botan/secmem.h>  // for Botan::secure_vector

void deriveKek(const Botan::secure_vector<char>& password, Header& header);
// Derive 256-bit KEK via Argon2id using header.getKdfMKib/T/P and header.getSaltData().
// Sets kek_ready_ = true, dek_ready_ = false.
// Throws std::runtime_error if Argon2id is unavailable.

void wrapDek(
    std::array<uint8_t, 12>& dek_nonce_out,
    std::array<uint8_t, DEK_SIZE>& encrypted_dek_out,
    std::array<uint8_t, 16>& dek_auth_tag_out
);
// Generate a random DEK and nonce; encrypt DEK with KEK using AES-256-GCM.
// Fills output buffers with nonce, ciphertext, and auth tag.
// Requires kek_ready_ == true. Sets dek_ready_ = true.

void unwrapDek(
    const std::array<uint8_t, 12>& dek_nonce,
    const std::array<uint8_t, DEK_SIZE>& encrypted_dek,
    const std::array<uint8_t, 16>& dek_auth_tag
);
// Decrypt DEK from header fields using KEK via AES-256-GCM.
// Requires kek_ready_ == true. Sets dek_ready_ = true.
// Throws std::runtime_error("Wrong password: DEK authentication failed") on auth failure.

[[nodiscard]] std::array<uint8_t, 32> computeHmac(
    const uint8_t* data,
    size_t size
) const;
// Compute HMAC-SHA256 of data using KEK as the HMAC key.
// Requires kek_ready_ == true.

void encrypt(const char* data, char* output, size_t dataSize);
// Encrypt one plaintext chunk (up to BLOCK_SIZE bytes).
// Output layout: [nonce 12B][ciphertext dataSize B][auth tag 16B].
// output buffer must be at least dataSize + 12 + 16 bytes.
// Requires dek_ready_ == true.

void decrypt(const char* data, char* output, size_t dataSize);
// Decrypt one encrypted chunk.
// Input layout: [nonce 12B][ciphertext dataSize B][auth tag 16B].
// output buffer must be at least dataSize bytes.
// Requires dek_ready_ == true.
// Throws std::runtime_error("Data block authentication failed") on auth failure.

void generateSalt(std::array<uint8_t, 32>& salt);
// Fill salt with 32 cryptographically random bytes (Botan::AutoSeeded_RNG).
```

---

## FileTable.h

```cpp
#include "FileTable.h"
```

### struct FileEntry

```cpp
struct FileEntry {
    std::string name;           // filename only (no path)
    size_t size;                // plaintext size in bytes
    size_t offset;              // container byte offset of first chunk
    size_t chunks;              // number of encrypted chunks
    std::string checksum_sha256; // hex uppercase SHA-256
};
```

### class FileTable

```cpp
FileTable();
~FileTable() = default;
```

#### Methods

```cpp
void addFileEntry(
    const std::string& pathToFile,
    const std::string& checkSum,
    size_t offset,
    size_t actual_size
);
// Add a new FileEntry. Extracts filename with filesystem::path::filename().
// Duplicate names get "(copy)" prepended until unique.

std::string serialize();
// Serialize the file table to a compact JSON string.
// Format: {"next_write_offset": N, "files": [{...}, ...]}

void deserialize(const std::string& data);
// Parse JSON into filesTable_. Handles missing "next_write_offset" (defaults to 0).

std::string to_string(bool isFull = false) const;
// Human-readable dump. isFull=true includes offset, chunks, checksum.

void reset();
// Clear all entries.

const FileEntry& getFileInfoByName(const std::string& fName);
// Find entry by name. Throws std::runtime_error if not found.

const std::vector<FileEntry>& getFilesTable() const;
// Return all entries.

void setNextWriteOffset(uint64_t offset);
uint64_t getNextWriteOffset() const;
// Persist/retrieve the container byte offset after the last written data chunk.
```

---

## KdfProfiles.h

```cpp
#include "KdfProfiles.h"
```

### Validation Bounds

```cpp
constexpr uint32_t KDF_M_KIB_MIN  = 1u;
constexpr uint32_t KDF_M_KIB_WARN = 8u * 1024u;   // 8 MiB
constexpr uint32_t KDF_M_KIB_MAX  = 4096u * 1024u; // 4096 MiB
constexpr uint32_t KDF_T_MIN      = 1u;
constexpr uint32_t KDF_T_MAX      = 100u;
constexpr uint32_t KDF_P_MIN      = 1u;
constexpr uint32_t KDF_P_MAX      = 64u;
```

### struct KdfProfileParams

```cpp
struct KdfProfileParams {
    EKDFProfile  id;
    const char*  name;   // CLI name: "fast", "default", "high", "browser"
    uint32_t     m_kib;  // Argon2id memory in KiB
    uint32_t     t;      // iterations
    uint32_t     p;      // parallelism
};
```

### Free Functions

```cpp
[[nodiscard]] const KdfProfileParams* getProfileParams(EKDFProfile id);
// Return pointer to the params table entry for a predefined profile.
// Returns nullptr for EKDFProfile::None or unrecognized values.

[[nodiscard]] const KdfProfileParams* getProfileByName(std::string_view name);
// Look up profile by CLI name. Returns nullptr if not found.
// Valid names: "fast", "default", "high", "browser".
// To retrieve the default profile: getProfileByName("default").
```

**Profile table** (from `src/KdfProfiles.cpp`):

| Profile | name | m_kib | t | p |
|---------|------|-------|---|---|
| `Browser` | `"browser"` | 65536 | 1 | 1 |
| `Fast` | `"fast"` | 262144 | 1 | 4 |
| `Standard` | `"default"` | 1048576 | 1 | 4 |
| `High` | `"high"` | 2097152 | 1 | 4 |

---

## Logger.h

```cpp
#include "Logger.h"
```

Thread-safe, file-backed logger with rotation. Not part of the external API for library consumers, but used pervasively in `scef_lib` internals.

```cpp
enum class LogLevel { DEBUG = 0, INFO = 1, BENCH = 2, WARNING = 3, ERROR = 4 };

class Logger {
public:
    static void init(
        bool mirror_to_console = false,
        const std::filesystem::path& log_dir = {}
    );
    // Create log directory, open first log file, write startup header.
    // log_dir empty → current_path() / "logs".
    // mirror_to_console: INFO/DEBUG → stdout, WARNING/ERROR → stderr.

    static void setLevel(LogLevel level);
    // Discard messages below this level.

    static void setBenchEnabled(bool enabled);
    [[nodiscard]] static bool benchEnabled();
    // Control whether BENCH-level messages are written.
    // BENCH messages are suppressed unless benchEnabled() returns true,
    // even if minLevel_ <= BENCH.

    static void log(LogLevel level, const char* fmt, ...);
    // Write formatted message. Use macros instead.
};
```

**Macros:**

```cpp
LOG_DEBUG(fmt, ...)    // LogLevel::DEBUG
LOG_INFO(fmt, ...)     // LogLevel::INFO
LOG_BENCH(fmt, ...)    // LogLevel::BENCH  (benchmark timing output)
LOG_WARN(fmt, ...)     // LogLevel::WARNING
LOG_ERROR(fmt, ...)    // LogLevel::ERROR
```

**Rotation:** Max 1 MiB per file, max 10 files. Oldest deleted when limit reached.

---

## PasswordStrengthEstimator.h

```cpp
#include "PasswordStrengthEstimator.h"
```

Non-copyable, non-movable. Wraps the zxcvbn-c library for password entropy estimation. Does not log the password; does not retain a copy after `estimate()` returns.

### struct Result

```cpp
struct Result {
    int    score;                  // 0..4 (0 = very weak, 4 = very strong)
    double bits;                   // log2(guesses) — entropy estimate
    int    recommendedMin;         // minimum recommended score for the requested profile
    bool   meetsRecommendation;    // score >= recommendedMin
    std::string warning;           // English warning; empty if meetsRecommendation
    std::string crackTimeOffline;  // human-readable offline crack time, e.g. "13 minutes"
};
```

### class PasswordStrengthEstimator

```cpp
PasswordStrengthEstimator();
~PasswordStrengthEstimator();
```

#### Methods

```cpp
Result estimate(const Botan::secure_vector<char>& password, EKDFProfile profile) const;
// Estimate strength of password relative to the KDF cost of the given profile.
// Pure function: does not log the password and does not keep a copy after return.

static int recommendedMinScore(EKDFProfile profile) noexcept;
// Single source of truth for per-profile minimum score thresholds.
```

---

## Enums

### ECipher (include/enums/ECiphers.h)

```cpp
enum class ECipher : uint8_t {
    None          = 0x00,
    AES_256_GCM   = 0x01,
    Kuznechik_GCM = 0x02,
};
```

### EKDF (include/enums/EKDF.h)

```cpp
enum class EKDF : uint8_t {
    None     = 0x00,
    Argon2id = 0x01,
};
```

### EKDFProfile (include/enums/EKDFProfile.h)

```cpp
enum class EKDFProfile : uint16_t {
    None     = 0x0000,  // custom params
    Browser  = 0x0001,
    Fast     = 0x0002,
    Standard = 0x0003,
    High     = 0x0004,
};
```

---

## Error Handling

All public methods throw `std::runtime_error` on failure. No error codes. The caller must catch exceptions.

Common exception messages:

| Message | Cause |
|---------|-------|
| `"Wrong password: DEK authentication failed"` | HMAC or DEK auth failure |
| `"Header HMAC verification failed: container is corrupt or wrong password"` | Header HMAC mismatch |
| `"Invalid container: no slot has valid magic bytes"` | File is not a SCEF container |
| `"Container is full: no free space for additional files"` | `add()` with no free capacity |
| `"Files too large for container: need N bytes but container only provides M bytes"` | `create()` or `add()` capacity check |
| `"Container file does not exist: ..."` | `init()` with `create_new=false` on missing file |
| `"Header KDF parameters out of acceptable range"` | Corrupt or crafted header |
| `"Argon2id not available in this Botan build"` | Botan built without Argon2id |
| `"There is no such file in current container or wrong file name."` | `extract()` with non-existent file name |

---

## Internal Infrastructure

The following classes are defined in `include/` but are **not part of the public API** consumed by CLI, GUI, or external integrators. They are used internally by `FileManager` and are subject to change without notice.

| Class | Header | Purpose |
|-------|--------|---------|
| `EncryptPipeline` | `include/EncryptPipeline.h` | Multi-stage pipeline (reader/worker/writer threads) for parallel file encryption; computes SHA-256 checksums internally and calls `fileTable_.addFileEntry()` |
| `DecryptPipeline` | `include/DecryptPipeline.h` | Multi-stage pipeline for parallel file decryption |
| `FragmentedIO` | `include/FragmentedIO.h` | Facade that routes pipeline reads/writes through `NativeFile`, automatically skipping slot reserved areas |
| `CryptoContext` | `include/CryptoContext.h` | Per-thread fast-path cipher context used by pipeline workers |
| `BoundedQueue` | `include/BoundedQueue.h` | Thread-safe bounded queue used by both pipelines |
| `NativeFile` | `include/NativeFile.h` | Thin RAII wrapper around OS file handles (`HANDLE` on Windows, `int fd` on Linux); replaces `std::fstream`. Provides `syncToDevice()` for durable writes. |

Do not instantiate these classes directly from application code.
