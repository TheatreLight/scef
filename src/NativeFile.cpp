#include "NativeFile.h"
#include "Logger.h"

#include <stdexcept>
#include <string>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <winioctl.h>

// ============================================================================
// Windows implementation
// ============================================================================

static std::string win32_error_string(DWORD err) {
    char buf[512];
    DWORD n = FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        buf, static_cast<DWORD>(sizeof(buf)), nullptr);
    if (n == 0) {
        return "Win32 error " + std::to_string(err);
    }
    // Strip trailing \r\n that FormatMessage often appends.
    while (n > 0 && (buf[n - 1] == '\r' || buf[n - 1] == '\n' || buf[n - 1] == ' ')) {
        --n;
    }
    return std::string(buf, n);
}

NativeFile::NativeFile()
{
    LOG_INFO("NativeFile::NativeFile()");
}

NativeFile::~NativeFile()
{
    LOG_INFO("NativeFile::~NativeFile()");
    close();
}

void NativeFile::open(const std::string& path, OpenMode mode) {
    close();

    DWORD access = 0;
    DWORD share  = 0;
    DWORD create = 0;
    DWORD flags  = FILE_ATTRIBUTE_NORMAL;

    switch (mode) {
        case OpenMode::CreateTruncate:
            access = GENERIC_READ | GENERIC_WRITE;
            share  = FILE_SHARE_READ;
            create = CREATE_ALWAYS;
            break;
        case OpenMode::OpenExisting:
            access = GENERIC_READ | GENERIC_WRITE;
            share  = FILE_SHARE_READ;
            create = OPEN_EXISTING;
            break;
        case OpenMode::OpenReadOnly:
            access = GENERIC_READ;
            share  = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
            create = OPEN_EXISTING;
            flags  = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN;
            break;
    }

    HANDLE h = CreateFileA(path.c_str(), access, share, nullptr, create, flags, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        throw std::runtime_error("NativeFile::open failed for '" + path + "': " +
                                 win32_error_string(err));
    }

    handle_ = h;
    path_   = path;
}

void NativeFile::close() noexcept {
    if (handle_ != nullptr) {
        CloseHandle(static_cast<HANDLE>(handle_));
        handle_ = nullptr;
    }
    path_.clear();
}

bool NativeFile::isOpen() const noexcept {
    return handle_ != nullptr;
}

void NativeFile::writeAt(uint64_t offset, const void* data, size_t size) {
    const char* src = static_cast<const char*>(data);
    size_t done = 0;
    while (done < size) {
        OVERLAPPED ov = {};
        uint64_t pos = offset + done;
        ov.Offset     = static_cast<unsigned long>(pos & 0xFFFFFFFFULL);
        ov.OffsetHigh = static_cast<unsigned long>(pos >> 32);

        unsigned long transferred = 0;
        unsigned long toWrite = static_cast<unsigned long>(std::min(size - done, 0x80000000ULL));
        int ok = WriteFile(handle_, src + done, toWrite, &transferred, &ov);
        if (ok == 0) {
            auto err = GetLastError();
            throw std::runtime_error("NativeFile::writeAt failed at offset " +
                std::to_string(offset + done) + ": " + win32_error_string(err));
        }
        if (transferred == 0) {
            throw std::runtime_error("NativeFile::writeAt stalled (0 bytes written) at offset " +
                std::to_string(offset + done));
        }
        done += transferred;
    }
}

void NativeFile::readAt(uint64_t offset, void* buf, size_t size) {
    char* dst = static_cast<char*>(buf);
    size_t done = 0;
    while (done < size) {
        OVERLAPPED ov = {};
        uint64_t pos = offset + done;
        ov.Offset     = static_cast<unsigned long>(pos & 0xFFFFFFFFULL);
        ov.OffsetHigh = static_cast<unsigned long>(pos >> 32);

        unsigned long transferred = 0;
        unsigned long toRead = static_cast<unsigned long>(std::min(size - done, 0x80000000ULL));
        int res = ReadFile(handle_, dst + done, toRead, &transferred, &ov);
        if (res == 0) {
            auto err = GetLastError();
            throw std::runtime_error("NativeFile::readAt failed at offset " +
                                     std::to_string(offset + done) + ": " +
                                     win32_error_string(err));
        }
        if (transferred == 0) {
            throw std::runtime_error("NativeFile::readAt: premature EOF at offset " +
                                     std::to_string(offset + done) +
                                     " (need " + std::to_string(size - done) + " more bytes)");
        }
        done += transferred;
    }
}

size_t NativeFile::readSome(uint64_t offset, void* buf, size_t size) {
    OVERLAPPED ov = {};
    ov.Offset     = static_cast<unsigned long>(offset & 0xFFFFFFFFULL);
    ov.OffsetHigh = static_cast<unsigned long>(offset >> 32);

    unsigned long transferred = 0;
    unsigned long toRead = static_cast<unsigned long>(std::min(size, 0x80000000ULL));
    int res = ReadFile(handle_, buf, toRead, &transferred, &ov);
    if (res == 0) {
        auto err = GetLastError();
        // ERROR_HANDLE_EOF means EOF — return 0.
        if (err == ERROR_HANDLE_EOF) {
            return 0;
        }
        throw std::runtime_error("NativeFile::readSome failed at offset " +
            std::to_string(offset) + ": " + win32_error_string(err));
    }
    // ok == TRUE, transferred == 0: ReadFile at EOF returns TRUE with zero bytes.
    // This is documented EOF behavior (MSDN ReadFile), not an error.
    return transferred;
}

void NativeFile::preallocateSparse(uint64_t size) {
    // Step 1: try to mark the file as sparse (best-effort).
    DWORD br = 0;
    int res = DeviceIoControl(handle_, FSCTL_SET_SPARSE,
        nullptr, 0, nullptr, 0, &br, nullptr);
    LOG_DEBUG("createContainerFile: preallocated %llu bytes (sparse=%s)",
              (unsigned long long)size, res != 0 ? "yes" : "fallback");

    // Step 2: set the file end pointer to 'size'.
    LARGE_INTEGER fSize;
    fSize.QuadPart = static_cast<LONGLONG>(size);
    if (!SetFilePointerEx(handle_, fSize, nullptr, FILE_BEGIN)) {
        auto err = GetLastError();
        throw std::runtime_error("NativeFile::preallocateSparse SetFilePointerEx failed: " +
                                 win32_error_string(err));
    }
    if (!SetEndOfFile(handle_)) {
        auto err = GetLastError();
        throw std::runtime_error("NativeFile::preallocateSparse SetEndOfFile failed: " +
                                 win32_error_string(err));
    }
}

uint64_t NativeFile::size() const {
    LARGE_INTEGER li = {};
    if (!GetFileSizeEx(handle_, &li)) {
        auto err = GetLastError();
        throw std::runtime_error("NativeFile::size GetFileSizeEx failed: " +
                                 win32_error_string(err));
    }
    return static_cast<uint64_t>(li.QuadPart);
}

void NativeFile::syncToDevice() {
    if (!isOpen()) {
        return;
    }
    if (!FlushFileBuffers(handle_)) {
        auto err = GetLastError();
        if (err == ERROR_INVALID_FUNCTION) {
            // Some USB drivers don't implement flush — non-fatal.
            LOG_WARN("NativeFile::syncToDevice: FlushFileBuffers returned "
                "ERROR_INVALID_FUNCTION for '%s' (driver may not support flush)", path_.c_str());
            return;
        }
        throw std::runtime_error("NativeFile::syncToDevice FlushFileBuffers failed for '" +
            path_ + "': " + win32_error_string(err));
    }
}

NativeFile::NativeFile(NativeFile&& other) noexcept
    : path_(std::move(other.path_))
    , handle_(other.handle_)
{
    other.handle_ = nullptr;
}

NativeFile& NativeFile::operator=(NativeFile&& other) noexcept {
    if (this != &other) {
        close();
        path_   = std::move(other.path_);
        handle_ = other.handle_;
        other.handle_ = nullptr;
    }
    return *this;
}

#else
// ============================================================================
// POSIX implementation
// ============================================================================

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

NativeFile::NativeFile()
{
    LOG_INFO("NativeFile::NativeFile()");
}

void NativeFile::open(const std::string& path, OpenMode mode) {
    close();

    int flags = 0;
    switch (mode) {
        case OpenMode::CreateTruncate:
            flags = O_RDWR | O_CREAT | O_TRUNC;
            break;
        case OpenMode::OpenExisting:
            flags = O_RDWR;
            break;
        case OpenMode::OpenReadOnly:
            flags = O_RDONLY;
            break;
    }

    int fd;
    if (mode == OpenMode::CreateTruncate) {
        fd = ::open(path.c_str(), flags, 0600);
    } else {
        fd = ::open(path.c_str(), flags);
    }

    if (fd == -1) {
        throw std::system_error(errno, std::system_category(),
                                "NativeFile::open failed for '" + path + "'");
    }

    if (mode == OpenMode::OpenReadOnly) {
        // Best-effort sequential hint; ignore failure.
        (void)posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
    }

    fd_   = fd;
    path_ = path;
}

void NativeFile::close() noexcept {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
    path_.clear();
}

bool NativeFile::isOpen() const noexcept {
    return fd_ >= 0;
}

void NativeFile::writeAt(uint64_t offset, const void* data, size_t size) {
    const char* src = static_cast<const char*>(data);
    size_t done = 0;
    while (done < size) {
        ssize_t n = ::pwrite(fd_, src + done, size - done,
                             static_cast<off_t>(offset + done));
        if (n == -1) {
            if (errno == EINTR) continue;
            throw std::system_error(errno, std::system_category(),
                                    "NativeFile::writeAt failed at offset " +
                                    std::to_string(offset + done));
        }
        if (n == 0) {
            throw std::runtime_error("NativeFile::writeAt stalled (0 bytes written) at offset " +
                                     std::to_string(offset + done));
        }
        done += static_cast<size_t>(n);
    }
}

void NativeFile::readAt(uint64_t offset, void* buf, size_t size) {
    char* dst = static_cast<char*>(buf);
    size_t done = 0;
    while (done < size) {
        ssize_t n = ::pread(fd_, dst + done, size - done,
                            static_cast<off_t>(offset + done));
        if (n == -1) {
            if (errno == EINTR) continue;
            throw std::system_error(errno, std::system_category(),
                                    "NativeFile::readAt failed at offset " +
                                    std::to_string(offset + done));
        }
        if (n == 0) {
            throw std::runtime_error("NativeFile::readAt: premature EOF at offset " +
                                     std::to_string(offset + done) +
                                     " (need " + std::to_string(size - done) + " more bytes)");
        }
        done += static_cast<size_t>(n);
    }
}

size_t NativeFile::readSome(uint64_t offset, void* buf, size_t size) {
    while (true) {
        ssize_t n = ::pread(fd_, buf, size, static_cast<off_t>(offset));
        if (n == -1) {
            if (errno == EINTR) continue;
            throw std::system_error(errno, std::system_category(),
                                    "NativeFile::readSome failed at offset " +
                                    std::to_string(offset));
        }
        return static_cast<size_t>(n);  // 0 = EOF
    }
}

void NativeFile::preallocateSparse(uint64_t size) {
    if (::ftruncate(fd_, static_cast<off_t>(size)) == -1) {
        throw std::system_error(errno, std::system_category(),
                                "NativeFile::preallocateSparse ftruncate failed");
    }
}

uint64_t NativeFile::size() const {
    struct stat st {};
    if (::fstat(fd_, &st) == -1) {
        throw std::system_error(errno, std::system_category(),
                                "NativeFile::size fstat failed");
    }
    return static_cast<uint64_t>(st.st_size);
}

void NativeFile::syncToDevice() {
    if (!isOpen()) {
        return;
    }
    if (::fsync(fd_) == -1) {
        throw std::system_error(errno, std::system_category(),
                                "NativeFile::syncToDevice fsync failed for '" + path_ + "'");
    }
}

NativeFile::~NativeFile() {
    close();
}

NativeFile::NativeFile(NativeFile&& other) noexcept
    : path_(std::move(other.path_))
    , fd_(other.fd_)
{
    other.fd_ = -1;
}

NativeFile& NativeFile::operator=(NativeFile&& other) noexcept {
    if (this != &other) {
        close();
        path_ = std::move(other.path_);
        fd_   = other.fd_;
        other.fd_ = -1;
    }
    return *this;
}

#endif // _WIN32
