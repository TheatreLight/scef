#ifndef LOGGER_H
#define LOGGER_H

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Log levels
// ---------------------------------------------------------------------------
enum class LogLevel {
    DEBUG   = 0,
    INFO    = 1,
    WARNING = 2,
    ERROR   = 3,
};

// ---------------------------------------------------------------------------
// Logger — thread-safe, file-backed, with rotation.
//
// Usage:
//   Logger::init();                  // once at startup
//   Logger::setLevel(LogLevel::INFO);
//   LOG_INFO("opened container %s", path.c_str());
//   LOG_ERROR("write failed: %s", e.what());
//
// Console mirroring convention (when enabled):
//   DEBUG / INFO    → stdout  (informational output the user reads)
//   WARNING / ERROR → stderr  (error stream, for shell redirection)
// ---------------------------------------------------------------------------
class Logger {
public:
    // Create the log directory, open the first log file, and write a
    // startup header with app name, version, and build info.
    // log_dir: explicit path to log directory.  If empty, defaults to
    //          current_path() / "logs" (suitable for CLI).
    // When mirror_to_console is true, messages are also written to stdout
    // (INFO/DEBUG) or stderr (WARNING/ERROR).
    static void init(bool mirror_to_console = false,
                     const std::filesystem::path& log_dir = {});

    // Set the minimum level that will be written.
    // Messages below this level are silently discarded.
    static void setLevel(LogLevel level);

    // Write a formatted message at the given level.
    // Not intended for direct use — prefer the LOG_* macros.
    static void log(LogLevel level, const char* fmt, ...);

private:
    // Maximum size of a single log file before rotation (1 MiB).
    static constexpr long     MAX_FILE_SIZE  = 1 * 1024 * 1024;
    // Maximum number of log files to keep in logs/.
    static constexpr size_t   MAX_LOG_FILES  = 10;

    // Returns the fixed-width label for a log level, e.g. "INFO    ".
    static const char* levelLabel(LogLevel level);

    // Open a new log file in dir_ and assign it to file_.
    // Rotates if there are already MAX_LOG_FILES files (deletes the oldest).
    static void openNewFile();

    // Returns a timestamp string "2026-04-07 14:23:01.123".
    static std::string currentTimestamp();

    // Collect all *.log files in dir_ sorted by modification time (oldest first).
    static std::vector<std::filesystem::path> collectLogFiles();

    // Write a startup banner to the log file (app name, version, build info).
    static void writeStartupHeader();

    static std::mutex            mutex_;
    static std::FILE*            file_;
    static std::filesystem::path dir_;
    static LogLevel              minLevel_;
    static bool                  mirrorToConsole_;
};

// ---------------------------------------------------------------------------
// Convenience macros
// ---------------------------------------------------------------------------
// __VA_OPT__ is standard C++20 and avoids the GNU-extension warning that
// ##__VA_ARGS__ triggers with -Wpedantic on Clang/GCC.
// NOLINTBEGIN(cppcoreguidelines-pro-type-vararg, hicpp-vararg)
#define LOG_DEBUG(fmt, ...)   Logger::log(LogLevel::DEBUG,   fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_INFO(fmt, ...)    Logger::log(LogLevel::INFO,    fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_WARN(fmt, ...)    Logger::log(LogLevel::WARNING, fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_ERROR(fmt, ...)   Logger::log(LogLevel::ERROR,   fmt __VA_OPT__(,) __VA_ARGS__)
// NOLINTEND(cppcoreguidelines-pro-type-vararg, hicpp-vararg)

#endif // LOGGER_H
