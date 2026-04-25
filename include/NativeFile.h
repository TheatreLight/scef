#ifndef NATIVE_FILE_H
#define NATIVE_FILE_H

#include <cstddef>
#include <cstdint>
#include <string>

// Cross-platform positional file I/O wrapper.
//
// Exposes exact-size read/write at arbitrary offsets without the overhead of
// fstream seekp/tellp.  On Windows uses OVERLAPPED + CreateFileA/WriteFile/ReadFile.
// On POSIX uses pread/pwrite.
//
// All methods throw std::system_error (POSIX) or std::runtime_error with a
// GetLastError message (Windows) on failure.
class NativeFile {
public:
    enum class OpenMode {
        CreateTruncate,  // Create new or truncate existing. Read+write.
        OpenExisting,    // Fail if not exist. Read+write.
        OpenReadOnly     // Fail if not exist. Read-only, with sequential-scan hint.
    };

    NativeFile();
    ~NativeFile();

    NativeFile(const NativeFile&) = delete;
    NativeFile& operator=(const NativeFile&) = delete;
    NativeFile(NativeFile&&) noexcept;
    NativeFile& operator=(NativeFile&&) noexcept;

    void open(const std::string& path, OpenMode mode);
    void close() noexcept;
    [[nodiscard]] bool isOpen() const noexcept;

    // Exact read/write — loops internally over short I/O; throws if exactly
    // 'size' bytes cannot be transferred.
    void writeAt(uint64_t offset, const void* data, size_t size);
    void readAt(uint64_t offset, void* buf, size_t size);

    // Short-read allowed. Returns bytes actually read (0 = EOF).
    // Used for input files where the caller doesn't know exact file size.
    [[nodiscard]] size_t readSome(uint64_t offset, void* buf, size_t size);

    // Pre-allocate the file to 'size' bytes using sparse allocation when possible.
    // Always extends the logical file size.
    // Returns true if the filesystem accepted a sparse hint, false for fallback.
    void preallocateSparse(uint64_t size);

    // OS-queried file size.
    [[nodiscard]] uint64_t size() const;

    // Block until OS cache is drained to the physical device.
    // Windows: FlushFileBuffers. POSIX: fsync.
    // No-op if !isOpen(). Throws on failure (except ERROR_INVALID_FUNCTION
    // on Windows which is logged as a warning and treated as non-fatal).
    void syncToDevice();

    [[nodiscard]] const std::string& path() const noexcept { return path_; }

private:
    std::string path_;
#ifdef _WIN32
    void* handle_ = nullptr;  // HANDLE as void* to keep <windows.h> out of this header
#else
    int fd_ = -1;
#endif
};

#endif // NATIVE_FILE_H
