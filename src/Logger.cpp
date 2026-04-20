#include "Logger.h"

#include <algorithm>
#include <chrono>
#include <cstdarg>
#include <ctime>
#include <filesystem>
#ifdef _WIN32
#include <share.h>  // _fsopen, _SH_DENYNO
#endif

// ---------------------------------------------------------------------------
// Static member definitions
// ---------------------------------------------------------------------------
std::mutex            Logger::mutex_;
std::FILE*            Logger::file_           = nullptr;
std::filesystem::path Logger::dir_;
LogLevel              Logger::minLevel_       = LogLevel::INFO;
bool                  Logger::mirrorToConsole_ = false;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void Logger::init(bool mirror_to_console, const std::filesystem::path& log_dir) {
    std::lock_guard<std::mutex> lock(mutex_);

    mirrorToConsole_ = mirror_to_console;
    dir_ = log_dir.empty() ? (std::filesystem::current_path() / "logs") : log_dir;

    std::error_code ec;
    std::filesystem::create_directories(dir_, ec);
    if (ec) {
        // Cannot throw here (init is called at startup, before any catch block).
        // Fall back to stderr only if the directory cannot be created.
        std::fprintf(stderr, "Logger: cannot create log directory '%s': %s\n",
                     dir_.string().c_str(), ec.message().c_str());
        dir_.clear();
        return;
    }

    openNewFile();
    writeStartupHeader();
}

void Logger::setLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    minLevel_ = level;
}

void Logger::log(LogLevel level, const char* fmt, ...) {
    // Format the user message into a local buffer (4 KiB is enough for any
    // single log line; overflow is silently truncated to avoid unbounded alloc).
    constexpr size_t BUF = 4096;
    char msgBuf[BUF];
    {
        std::va_list args;
        va_start(args, fmt);
        std::vsnprintf(msgBuf, BUF, fmt, args);
        va_end(args);
    }

    // Build the full log line: "<timestamp> <level> | <message>\n"
    // Overhead: timestamp (23) + space (1) + level (7) + " | " (3) + newline (1) + NUL (1) = 36.
    // Using 128 bytes of margin for safety against future format changes.
    constexpr size_t LINE_OVERHEAD = 128;
    char lineBuf[BUF + LINE_OVERHEAD];
    int lineLen = 0;
    bool doMirror = false;

    {
        std::lock_guard<std::mutex> lock(mutex_);

        if (level < minLevel_) {
            return;
        }

        std::string timestamp = currentTimestamp();
        lineLen = std::snprintf(lineBuf, sizeof(lineBuf),
                                    "%s %-7s | %s\n",
                                    timestamp.c_str(),
                                    levelLabel(level),
                                    msgBuf);

        // Rotate if the file has grown past MAX_FILE_SIZE (checked before each write).
        if (file_) {
            long pos = std::ftell(file_);
            if (pos < 0 || pos >= MAX_FILE_SIZE) {
                std::fclose(file_);
                file_ = nullptr;
                openNewFile();
                writeStartupHeader();
            }
        } else if (!dir_.empty()) {
            openNewFile();
            writeStartupHeader();
        }

        if (file_ && lineLen > 0) {
            std::fwrite(lineBuf, 1, static_cast<size_t>(lineLen), file_);
            std::fflush(file_);
        }

        doMirror = mirrorToConsole_;
    }

    // Console mirror: outside the Logger mutex to avoid lock-order inversion
    // with the CRT's internal stdio lock (std::cout may hold it in another thread).
    if (doMirror && lineLen > 0) {
        std::FILE* dest = (level >= LogLevel::WARNING) ? stderr : stdout;
        std::fwrite(lineBuf, 1, static_cast<size_t>(lineLen), dest);
        std::fflush(dest);
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

const char* Logger::levelLabel(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG:   return "DEBUG";
        case LogLevel::INFO:    return "INFO";
        case LogLevel::BENCH:   return "BENCH";
        case LogLevel::WARNING: return "WARNING";
        case LogLevel::ERROR:   return "ERROR";
    }
    return "UNKNOWN";
}

std::string Logger::currentTimestamp() {
    using namespace std::chrono;

    // Wall-clock time with millisecond precision.
    auto now       = system_clock::now();
    auto ms        = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    auto time_t_   = system_clock::to_time_t(now);

    // Use thread-safe gmtime variant.
    std::tm tm_info{};
#ifdef _WIN32
    localtime_s(&tm_info, &time_t_);
#else
    localtime_r(&time_t_, &tm_info);
#endif

    char buf[32];
    std::snprintf(buf, sizeof(buf),
                  "%04d-%02d-%02d %02d:%02d:%02d.%03d",
                  tm_info.tm_year + 1900,
                  tm_info.tm_mon  + 1,
                  tm_info.tm_mday,
                  tm_info.tm_hour,
                  tm_info.tm_min,
                  tm_info.tm_sec,
                  static_cast<int>(ms.count()));
    return buf;
}

std::vector<std::filesystem::path> Logger::collectLogFiles() {
    std::vector<std::filesystem::path> files;
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(dir_, ec)) {
        if (ec) break;
        std::error_code e2;
        if (entry.is_regular_file(e2) && !e2 &&
            entry.path().extension() == ".log") {
            files.push_back(entry.path());
        }
    }

    // Sort oldest-first by last-write-time so we always delete the oldest.
    // If last_write_time fails for a path, treat it as the oldest (delete first).
    std::sort(files.begin(), files.end(),
              [](const std::filesystem::path& a,
                 const std::filesystem::path& b) {
                  std::error_code ea, eb;
                  auto ta = std::filesystem::last_write_time(a, ea);
                  auto tb = std::filesystem::last_write_time(b, eb);
                  if (ea) return true;   // a is unknown → treat as oldest
                  if (eb) return false;
                  return ta < tb;
              });
    return files;
}

void Logger::openNewFile() {
    // Enforce the max-files limit: delete the oldest file(s) if necessary.
    auto files = collectLogFiles();
    size_t toDelete = (files.size() >= MAX_LOG_FILES)
        ? files.size() - MAX_LOG_FILES + 1
        : 0;
    for (size_t i = 0; i < toDelete; ++i) {
        std::error_code ec;
        std::filesystem::remove(files[i], ec);
    }

    // Build a filename from the current local time, e.g. "2026-04-07_143201_scef.log".
    using namespace std::chrono;
    auto now     = system_clock::now();
    auto time_t_ = system_clock::to_time_t(now);
    std::tm tm_info{};
#ifdef _WIN32
    localtime_s(&tm_info, &time_t_);
#else
    localtime_r(&time_t_, &tm_info);
#endif

    char nameBuf[64];
    std::snprintf(nameBuf, sizeof(nameBuf),
                  "%04d-%02d-%02d_%02d%02d%02d_scef.log",
                  tm_info.tm_year + 1900,
                  tm_info.tm_mon  + 1,
                  tm_info.tm_mday,
                  tm_info.tm_hour,
                  tm_info.tm_min,
                  tm_info.tm_sec);

    auto filePath = dir_ / nameBuf;
#ifdef _WIN32
    // _SH_DENYNO: allow other processes to read the log file while we write.
    file_ = _fsopen(filePath.string().c_str(), "a", _SH_DENYNO);
#else
    file_ = std::fopen(filePath.string().c_str(), "a");
#endif
    if (!file_) {
        std::fprintf(stderr, "Logger: cannot open log file '%s'\n",
                     filePath.string().c_str());
    }
}

void Logger::writeStartupHeader() {
    if (!file_) {
        return;
    }

#ifdef NDEBUG
    static constexpr const char* CONFIG_STR = "Release";
#else
    static constexpr const char* CONFIG_STR = "Debug";
#endif
#ifdef _WIN32
    static constexpr const char* PLATFORM_STR = "Windows";
#else
    static constexpr const char* PLATFORM_STR = "Linux";
#endif

    std::string ts = currentTimestamp();

    std::fprintf(file_,
        "========================================================\n"
        "  SCEF - Self-contained Encrypted Container Format\n"
        "  Version:   " SCEF_VERSION "\n"
        "  Copyright: 2026 Zykov Ivan\n"
        "  Build:     %s, %s\n"
        "  Config:    %s\n"
        "  Platform:  %s\n"
        "  Started:   %s\n"
        "========================================================\n",
        __DATE__, __TIME__,
        CONFIG_STR,
        PLATFORM_STR,
        ts.c_str());

    std::fflush(file_);
}
