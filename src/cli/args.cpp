#include "args.h"

#include "FileManager.h"
#include "Header.h"
#include "Logger.h"

#include <algorithm>
#include <iostream>

namespace {

// Returns the flag string if arg is a recognized flag key, otherwise "".
std::string foundKey(const char* arg)
{
    std::string_view s{arg};
    if (s == "-c" || s == "-f" || s == "-o" || s == "-s" ||
        s == "--max_table_size" || s == "--kdf-profile" ||
        s == "--kdf-m" || s == "--kdf-t" || s == "--kdf-p" ||
        s == "--cipher" || s == "--log-level" ||
        s == "--password" || s == "--name") {
        return std::string(s);
    }
    return {};
}

std::string toLowerAscii(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

std::optional<ECipher> parseCipherName(const std::string& text)
{
    const std::string value = toLowerAscii(text);
    if (value == "aes" || value == "aes-256-gcm") {
        return ECipher::AES_256_GCM;
    }
    if (value == "kuznechik" || value == "kuznyechik" || value == "gost") {
        return ECipher::Kuznechik_GCM;
    }
    return std::nullopt;
}

LogLevel defaultLogLevel()
{
#ifdef NDEBUG
    return LogLevel::INFO;
#else
    return LogLevel::DEBUG;
#endif
}

bool tryParseLogLevel(const std::string& text, LogLevel& out)
{
    if (text == "debug") {
        out = LogLevel::DEBUG;
    } else if (text == "info") {
        out = LogLevel::INFO;
    } else if (text == "bench") {
        out = LogLevel::BENCH;
    } else if (text == "warning" || text == "warn") {
        out = LogLevel::WARNING;
    } else if (text == "error") {
        out = LogLevel::ERROR;
    } else {
        return false;
    }
    return true;
}

} // namespace

namespace cli {

int parseArgs(int argc, char** argv, ParsedArgs& out,
              const std::string& textUsage, int argsRequired)
{
    if (argc < argsRequired) {
        std::cerr << textUsage;
        return EXIT_FAILURE;
    }

    // Fill in the default max_table_size when the caller hasn't pre-set it.
    if (out.max_table_size == 0) {
        out.max_table_size = DEFAULT_MAX_TABLE_SIZE;
    }

    std::string key;
    for (int i = 2; i < argc; ++i) {
        const std::string_view currentArg{argv[i]};
        if (currentArg == "-y" || currentArg == "--yes") {
            out.assumeYes = true;
            key.clear();
            continue;
        }
        if (currentArg == "--strength-only") {
            out.strengthOnly = true;
            key.clear();
            continue;
        }
        if (currentArg == "--no-browser-viewer") {
            out.noBrowserViewer = true;
            key.clear();
            continue;
        }

        if (const std::string arg = foundKey(argv[i]); !arg.empty()) {
            key = arg;
            continue;
        }
        if (key == "-c") {
            out.containerPath = argv[i];
        } else if (key == "-f") {
            out.fileList.push_back(argv[i]);
        } else if (key == "-o") {
            out.outputPath = argv[i];
        } else if (key == "-s") {
            out.container_size = std::stoull(argv[i]);
        } else if (key == "--max_table_size") {
            out.max_table_size = static_cast<uint32_t>(std::stoul(argv[i]));
        } else if (key == "--kdf-profile") {
            out.kdf_profile_name = argv[i];
        } else if (key == "--kdf-m") {
            out.kdf_m_mib = static_cast<uint32_t>(std::stoul(argv[i]));
        } else if (key == "--kdf-t") {
            out.kdf_t = static_cast<uint32_t>(std::stoul(argv[i]));
        } else if (key == "--kdf-p") {
            out.kdf_p = static_cast<uint32_t>(std::stoul(argv[i]));
        } else if (key == "--cipher") {
            auto parsed = parseCipherName(argv[i]);
            if (!parsed) {
                std::cerr << "Unknown cipher '" << argv[i]
                          << "'. Valid values: aes, aes-256-gcm, kuznechik, kuznyechik, gost\n";
                return EXIT_FAILURE;
            }
            out.cipher = *parsed;
        } else if (key == "--log-level") {
            out.log_level_name = argv[i];
        } else if (key == "--password") {
            out.password = argv[i];
        } else if (key == "--name") {
            out.containerName = argv[i];
        }
        key.clear();
    }
    return EXIT_SUCCESS;
}

int applyLogLevelFromArgv(int argc, char** argv)
{
    LogLevel level = defaultLogLevel();
    for (int i = 1; i < argc; ++i) {
        if (std::string_view{argv[i]} != "--log-level") {
            continue;
        }
        if (i + 1 >= argc) {
            std::cerr << "--log-level requires a value: debug, info, bench, warning, error\n";
            return EXIT_FAILURE;
        }
        if (!tryParseLogLevel(argv[i + 1], level)) {
            std::cerr << "Unknown log level '" << argv[i + 1]
                      << "'. Valid values: debug, info, bench, warning, error\n";
            return EXIT_FAILURE;
        }
        ++i;
    }
    Logger::setLevel(level);
    return EXIT_SUCCESS;
}

bool hasArg(int argc, char** argv, std::string_view needle)
{
    for (int i = 1; i < argc; ++i) {
        if (std::string_view{argv[i]} == needle) {
            return true;
        }
    }
    return false;
}

int resolveExistingContainerPath(const std::string& dir,
                                 const std::string& name,
                                 std::string& out_path)
{
    namespace fs = std::filesystem;
    if (!name.empty()) {
        out_path = (fs::path(dir) / name).string();
        return EXIT_SUCCESS;
    }

    const fs::path defaultPath = fs::path(dir) / CONTAINER_FILE_NAME;
    if (fs::exists(defaultPath)) {
        out_path = defaultPath.string();
        return EXIT_SUCCESS;
    }

    // Fallback: scan for a single *.scef file in the directory.
    std::vector<fs::path> found;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        if (ec) { break; }
        if (entry.path().extension() == ".scef") {
            found.push_back(entry.path());
        }
    }
    if (ec) {
        LOG_ERROR("Cannot scan directory '%s': %s", dir.c_str(), ec.message().c_str());
        return EXIT_FAILURE;
    }
    if (found.size() == 1) {
        out_path = found[0].string();
        return EXIT_SUCCESS;
    }
    if (found.empty()) {
        LOG_ERROR("No *.scef container found in '%s'. "
                  "Use --name <filename> to specify the container.", dir.c_str());
    } else {
        LOG_ERROR("Multiple *.scef files found in '%s'. "
                  "Use --name <filename> to select one.", dir.c_str());
    }
    return EXIT_FAILURE;
}

} // namespace cli
