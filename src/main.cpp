#include "FileManager.h"
#include "KdfProfiles.h"
#include "Logger.h"
#include "PasswordStrengthEstimator.h"

#include "botan/mem_ops.h"
#include "botan/pwdhash.h"
#include "botan/secmem.h"

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#ifdef ERROR
#undef ERROR
#endif
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace {

void print_help() {
    std::cout << "scef v" SCEF_VERSION " - Self-contained Encrypted Container Format\n"
              << "\n"
              << "Usage: scef <command> [options]\n"
              << "\n"
              << "Commands:\n"
              << "  create   -c <dir> -f <file> -s <bytes>   Create a new container\n"
              << "  add      -c <dir> -f <file>               Add a file to the container\n"
              << "  list     -c <dir>                         List files in the container\n"
              << "  extract  -c <dir> -o <dir>                Extract files from the container\n"
              << "  benchmark                                  Measure Argon2id timings per KDF profile\n"
              << "\n"
              << "Options:\n"
              << "  -c <dir>                  Path to container directory\n"
              << "  --name <filename>         Container filename (no path separators allowed).\n"
              << "                            create: default is auto-numbered (container.scef,\n"
              << "                              container_1.scef, ...) — never overwrites existing files.\n"
              << "                            open/add/list/extract: default is container.scef;\n"
              << "                              if that does not exist, the single *.scef in -c is used.\n"
              << "  -f <file>                 File to add or extract (repeatable)\n"
              << "  -o <dir>                  Output directory for extract\n"
              << "  -s <bytes>                Fixed container size in bytes (required for create)\n"
              << "  --max_table_size <bytes>  Max encrypted file table size per slot\n"
              << "                            (default: " << DEFAULT_MAX_TABLE_SIZE << " bytes)\n"
              << "  --log-level <level>       debug, info, bench, warning, error\n"
              << "  -y, --yes                 Assume yes for confirmation prompts\n"
              << "  --strength-only           Read password from stdin, print score/bits, exit\n"
              << "\n"
              << "KDF options (create only):\n"
              << "  --kdf-profile <name>      Use a predefined KDF profile.\n"
              << "                            Names: fast, default, high, browser\n"
              << "  --kdf-m <MiB>             Manual Argon2id memory in MiB (min 1, max 4096; <8 warns)\n"
              << "  --kdf-t <n>               Manual Argon2id iterations (min 1, max 100)\n"
              << "  --kdf-p <n>               Manual Argon2id parallelism (min 1, max 64)\n"
              << "                            Aliases: --kdf-m-cost, --kdf-t-cost, --kdf-parallelism\n"
              << "  Note: --kdf-profile and --kdf-m/t/p are mutually exclusive.\n"
              << "        If nothing is specified, the 'default' profile is used.\n"
              << "\n"
              << "Cipher options (create only):\n"
              << "  --cipher <name>           aes, aes-256-gcm, kuznechik, kuznyechik, gost\n"
              << "                            (default: aes)\n"
              << "\n"
              << "  --help, -h    Show this help\n"
              << "  --version     Show version\n";
}

void print_version() {
    std::cout << "scef v" SCEF_VERSION "\n";
}

class PasswordEchoGuard {
public:
    PasswordEchoGuard() {
#ifdef _WIN32
        handle_ = GetStdHandle(STD_INPUT_HANDLE);
        if (handle_ == INVALID_HANDLE_VALUE || handle_ == nullptr) {
            return;
        }
        DWORD mode = 0;
        if (!GetConsoleMode(handle_, &mode)) {
            return;
        }
        oldMode_ = mode;
        restore_ = SetConsoleMode(handle_, mode & ~ENABLE_ECHO_INPUT) != 0;
#else
        if (isatty(fileno(stdin)) == 0) {
            return;
        }
        if (tcgetattr(fileno(stdin), &oldTerm_) != 0) {
            return;
        }
        termios noEcho = oldTerm_;
        noEcho.c_lflag &= ~ECHO;
        restore_ = tcsetattr(fileno(stdin), TCSAFLUSH, &noEcho) == 0;
#endif
    }

    ~PasswordEchoGuard() {
#ifdef _WIN32
        if (restore_) {
            SetConsoleMode(handle_, oldMode_);
        }
#else
        if (restore_) {
            tcsetattr(fileno(stdin), TCSAFLUSH, &oldTerm_);
        }
#endif
    }

    bool disabledEcho() const noexcept { return restore_; }

private:
    bool restore_ = false;
#ifdef _WIN32
    HANDLE handle_ = nullptr;
    DWORD oldMode_ = 0;
#else
    termios oldTerm_{};
#endif
};

// Read a password from stdin (up to the first newline or EOF).
// On Windows, the bytes delivered by std::cin use the active console input code page
// (GetConsoleCP()), which may differ from UTF-8 for non-ASCII characters.  The browser
// viewer always encodes the password as UTF-8 (hash-wasm uses TextEncoder internally),
// so we convert to UTF-8 here to ensure both paths hash the same byte sequence.
Botan::secure_vector<char> read_password() {
    PasswordEchoGuard echoGuard;
    Botan::secure_vector<char> pw;
    char ch = '\0';
    while (std::cin.get(ch)) {
        if (ch == '\n' || ch == '\r') {
            break;
        }
        pw.push_back(ch);
    }
    if (echoGuard.disabledEcho()) {
        std::cerr << '\n';
    }
    if (pw.empty()) {
        throw std::runtime_error("Password cannot be empty");
    }

#ifdef _WIN32
    // Convert from the active console input code page to UTF-8 so that non-ASCII
    // passwords produce the same byte sequence as the browser viewer.
    const UINT cp = GetConsoleCP();
    if (cp != CP_UTF8) {
        // Step 1: CP → UTF-16.
        const int wlen = MultiByteToWideChar(
            cp, 0,
            pw.data(), static_cast<int>(pw.size()),
            nullptr, 0);
        if (wlen <= 0) {
            // Conversion failed — fall back to raw bytes and warn.
            LOG_WARN("read_password: MultiByteToWideChar failed (cp=%u, err=%lu); "
                     "non-ASCII passwords may not match browser viewer",
                     cp, GetLastError());
        } else {
            // Use a raw buffer so we can scrub it explicitly.
            auto* wbuf = static_cast<wchar_t*>(std::malloc(static_cast<size_t>(wlen) * sizeof(wchar_t)));
            if (!wbuf) {
                throw std::runtime_error("read_password: out of memory during CP→UTF-16 conversion");
            }
            MultiByteToWideChar(cp, 0, pw.data(), static_cast<int>(pw.size()), wbuf, wlen);

            // Step 2: UTF-16 → UTF-8.
            const int u8len = WideCharToMultiByte(
                CP_UTF8, 0,
                wbuf, wlen,
                nullptr, 0,
                nullptr, nullptr);
            if (u8len <= 0) {
                Botan::secure_scrub_memory(wbuf, static_cast<size_t>(wlen) * sizeof(wchar_t));
                std::free(wbuf);
                LOG_WARN("read_password: WideCharToMultiByte failed (err=%lu); "
                         "non-ASCII passwords may not match browser viewer",
                         GetLastError());
            } else {
                Botan::secure_vector<char> utf8(static_cast<size_t>(u8len));
                WideCharToMultiByte(CP_UTF8, 0, wbuf, wlen,
                                    utf8.data(), u8len,
                                    nullptr, nullptr);
                Botan::secure_scrub_memory(wbuf, static_cast<size_t>(wlen) * sizeof(wchar_t));
                std::free(wbuf);

                // Scrub the original (code-page) bytes and replace with UTF-8.
                Botan::secure_scrub_memory(pw.data(), pw.size());
                pw = std::move(utf8);
            }
        }
    }
#endif // _WIN32

    return pw;
}

// Returns the flag string if arg is a recognized flag key, otherwise "".
std::string foundKey(const char* arg) {
    std::string_view s{arg};
    if (s == "-c" || s == "-f" || s == "-o" || s == "-s" ||
        s == "--max_table_size" || s == "--kdf-profile" ||
        s == "--kdf-m" || s == "--kdf-t" || s == "--kdf-p" ||
        s == "--cipher" || s == "--log-level" || s == "-y" ||
        s == "--strength-only" || s == "--password" || s == "--name") {
        return std::string(s);
    }
    return "";
}

std::string toLowerAscii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

std::optional<ECipher> parseCipherName(const std::string& text) {
    const std::string value = toLowerAscii(text);
    if (value == "aes" || value == "aes-256-gcm") {
        return ECipher::AES_256_GCM;
    }
    if (value == "kuznechik" || value == "kuznyechik" || value == "gost") {
        return ECipher::Kuznechik_GCM;
    }
    return std::nullopt;
}

struct ParsedArgs {
    std::string              containerPath;   // -c: container directory (or full path for open/add)
    std::string              containerName;   // --name: filename only (no separators)
    std::string              outputPath;
    std::vector<std::string> fileList;
    uint64_t                 container_size  = 0;
    uint32_t                 max_table_size  = DEFAULT_MAX_TABLE_SIZE;
    // KDF options
    std::string              kdf_profile_name;   // empty = not specified
    uint32_t                 kdf_m_mib       = 0; // 0 = not specified
    uint32_t                 kdf_t           = 0; // 0 = not specified
    uint32_t                 kdf_p           = 0; // 0 = not specified
    std::optional<ECipher>   cipher;
    std::string              log_level_name;
    bool                     assumeYes       = false;
    bool                     strengthOnly    = false;
    std::string              password;
};

bool hasArg(int argc, char** argv, std::string_view needle) {
    for (int i = 1; i < argc; ++i) {
        if (std::string_view{argv[i]} == needle) {
            return true;
        }
    }
    return false;
}

int parseArgs(int argc, char** argv, ParsedArgs& out, const std::string& textUsage,
              int argsRequired) {
    if (argc < argsRequired) {
        std::cerr << textUsage;
        return EXIT_FAILURE;
    }

    std::string key;
    for (int i = 2; i < argc; ++i) {
        if (const std::string arg = foundKey(argv[i]); !arg.empty()) {
            if (arg == "-y") {
                out.assumeYes = true;
                key.clear();
                continue;
            }
            if (arg == "--strength-only") {
                out.strengthOnly = true;
                key.clear();
                continue;
            }
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
    return 0;
}

LogLevel defaultLogLevel() {
#ifdef NDEBUG
    return LogLevel::INFO;
#else
    return LogLevel::DEBUG;
#endif
}

bool tryParseLogLevel(const std::string& text, LogLevel& out) {
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

int applyLogLevelFromArgv(int argc, char** argv) {
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

bool stdinIsTty() {
#ifdef _WIN32
    return _isatty(_fileno(stdin)) != 0;
#else
    return isatty(fileno(stdin)) != 0;
#endif
}

bool forceStrengthPrompt() {
#ifdef _WIN32
    char* value = nullptr;
    size_t value_len = 0;
    if (_dupenv_s(&value, &value_len, "SCEF_FORCE_PROMPT") != 0 || value == nullptr) {
        return false;
    }
    const bool enabled = value_len > 1 && std::string_view{value} != "0";
    std::free(value);
    return enabled;
#else
    const char* value = std::getenv("SCEF_FORCE_PROMPT");
    return value != nullptr && value[0] != '\0' && std::string_view{value} != "0";
#endif
}

} // namespace

// Validate that a user-supplied container filename contains no path separators.
// Returns EXIT_SUCCESS (0) on success, EXIT_FAILURE on error.
static int validateContainerName(const std::string& name) {
    if (name.find('/') != std::string::npos || name.find('\\') != std::string::npos) {
        LOG_ERROR("--name must be a filename only (no '/' or '\\' separators): %s", name.c_str());
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

// Resolve the full path to an existing container file for open/list/extract/add.
// Priority:
//   1. If --name was given, use dir/name unconditionally.
//   2. If dir/container.scef exists, use it.
//   3. Scan dir for *.scef files; if exactly one exists, use it.
//   4. Otherwise error.
// Returns EXIT_SUCCESS and sets out_path on success; returns EXIT_FAILURE on error.
static int resolveExistingContainerPath(const std::string& dir,
                                         const std::string& name,
                                         std::string& out_path) {
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

// Resolve KDF parameters from parsed CLI args.
// On success returns 0 and fills out profile/m_kib/t/p.
// On error prints to stderr and returns EXIT_FAILURE.
static int resolveKdfParams(const ParsedArgs& args,
                             EKDFProfile& out_profile,
                             uint32_t& out_m_kib,
                             uint32_t& out_t,
                             uint32_t& out_p) {
    bool has_profile = !args.kdf_profile_name.empty();
    bool has_manual  = (args.kdf_m_mib != 0 || args.kdf_t != 0 || args.kdf_p != 0);

    if (has_profile && has_manual) {
        LOG_ERROR("Cannot use --kdf-profile with manual KDF parameters (--kdf-m, --kdf-t, --kdf-p)");
        return EXIT_FAILURE;
    }

    if (has_profile) {
        const KdfProfileParams* p = getProfileByName(args.kdf_profile_name);
        if (!p) {
            LOG_ERROR("Unknown KDF profile '%s'. Valid names: fast, default, high, browser",
                      args.kdf_profile_name.c_str());
            return EXIT_FAILURE;
        }
        out_profile = p->id;
        out_m_kib   = p->m_kib;
        out_t       = p->t;
        out_p       = p->p;
    } else if (has_manual) {
        // All three manual params must be specified together or individually;
        // unspecified ones fall back to the Standard profile defaults.
        const KdfProfileParams* def = getProfileByName("default");
        out_profile = EKDFProfile::None;
        out_m_kib   = (args.kdf_m_mib != 0) ? args.kdf_m_mib * 1024 : def->m_kib;
        out_t       = (args.kdf_t != 0)      ? args.kdf_t            : def->t;
        out_p       = (args.kdf_p != 0)      ? args.kdf_p            : def->p;

        // Validate ranges.
        if (out_m_kib < KDF_M_KIB_MIN || out_m_kib > KDF_M_KIB_MAX) {
            LOG_ERROR("--kdf-m must be between 1 and 4096 MiB");
            return EXIT_FAILURE;
        }
        if (out_m_kib < KDF_M_KIB_WARN) {
            LOG_WARN("--kdf-m below 8 MiB provides weak security");
        }
        if (out_t < KDF_T_MIN || out_t > KDF_T_MAX) {
            LOG_ERROR("--kdf-t must be between 1 and 100");
            return EXIT_FAILURE;
        }
        if (out_p < KDF_P_MIN || out_p > KDF_P_MAX) {
            LOG_ERROR("--kdf-p must be between 1 and 64");
            return EXIT_FAILURE;
        }
    } else {
        // Default: Standard profile.
        const KdfProfileParams* p = getProfileByName("default");
        out_profile = p->id;
        out_m_kib   = p->m_kib;
        out_t       = p->t;
        out_p       = p->p;
    }

    return 0;
}

static void printKdfSelection(EKDFProfile profile, uint32_t m_kib, uint32_t t, uint32_t p) {
    std::string label;
    switch (profile) {
        case EKDFProfile::Standard: label = "Standard"; break;
        case EKDFProfile::Fast:     label = "Fast";     break;
        case EKDFProfile::High:     label = "High";     break;
        case EKDFProfile::Browser:  label = "Browser";  break;
        default:                    label = "Custom";   break;
    }
    std::cout << "KDF: " << label
              << " (m=" << (m_kib / 1024) << " MiB"
              << ", t=" << t
              << ", p=" << p << ")\n";
}

static int confirmWeakPassword(const PasswordStrengthEstimator::Result& result,
                               bool assumeYes) {
    std::cerr << result.warning << "\n";
    if (assumeYes) {
        return EXIT_SUCCESS;
    }
    if (!stdinIsTty() && !forceStrengthPrompt()) {
        return EXIT_SUCCESS;
    }

    std::cerr << "Proceed with this password? [y/N]: ";
    std::string answer;
    std::getline(std::cin, answer);
    if (answer.size() == 1 && (answer[0] == 'y' || answer[0] == 'Y')) {
        return EXIT_SUCCESS;
    }

    std::cerr << "Aborted due to weak password.\n";
    return EXIT_FAILURE;
}

static int resolveStrengthOnlyProfile(int argc, char** argv, EKDFProfile& out_profile) {
    out_profile = EKDFProfile::Standard;

    for (int i = 1; i < argc; ++i) {
        if (std::string_view{argv[i]} != "--kdf-profile") {
            continue;
        }
        if (i + 1 >= argc) {
            LOG_ERROR("--kdf-profile requires a value: fast, default, high, browser");
            return EXIT_FAILURE;
        }
        const KdfProfileParams* p = getProfileByName(argv[i + 1]);
        if (!p) {
            LOG_ERROR("Unknown KDF profile '%s'. Valid names: fast, default, high, browser",
                      argv[i + 1]);
            return EXIT_FAILURE;
        }
        out_profile = p->id;
        ++i;
    }

    return EXIT_SUCCESS;
}

static int cmd_strength_only(int argc, char** argv) {
    EKDFProfile kdf_profile{};
    if (EXIT_FAILURE == resolveStrengthOnlyProfile(argc, argv, kdf_profile)) {
        return EXIT_FAILURE;
    }

    try {
        Botan::secure_vector<char> password = read_password();
        PasswordStrengthEstimator est;
        const auto r = est.estimate(password, kdf_profile);
        std::cout << "score=" << r.score
                  << " bits=" << std::fixed << std::setprecision(1) << r.bits
                  << "\n";
    } catch (const std::exception& e) {
        LOG_ERROR("strength-only failed: %s", e.what());
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

// Run Argon2id for one profile and return elapsed seconds.
static double benchmarkProfile(const KdfProfileParams& p) {
    auto pwdhash_fam = Botan::PasswordHashFamily::create("Argon2id");
    if (!pwdhash_fam) {
        throw std::runtime_error("Argon2id not available in this Botan build");
    }
    auto pwdhash = pwdhash_fam->from_params(p.m_kib, p.t, p.p);

    constexpr std::string_view benchmarkPassword  = "benchmark";
    constexpr size_t            salt_len  = 32;
    constexpr size_t            key_len   = 32;
    // Zero salt is intentional: Argon2id timing depends only on m/t/p, not on salt value.
    const uint8_t               salt[salt_len] = {};
    uint8_t                     key[key_len]   = {};

    auto t0 = std::chrono::high_resolution_clock::now();
    pwdhash->derive_key(key, key_len,
                        benchmarkPassword.data(), benchmarkPassword.size(),
                        salt, salt_len);
    auto t1 = std::chrono::high_resolution_clock::now();

    // Scrub key material immediately — it is meaningless but good practice.
    Botan::secure_scrub_memory(key, key_len);

    std::chrono::duration<double> elapsed = t1 - t0;
    return elapsed.count();
}

static int cmd_benchmark() {
    // Collect all profiles from the table.
    struct Row {
        const char* label;
        uint32_t    m_mib;
        uint32_t    t;
        uint32_t    p;
        double      seconds = 0.0;
        std::string error;
    };

    // Profile list ordered for display.
    constexpr std::array<EKDFProfile, 4> order = {
        EKDFProfile::Browser,
        EKDFProfile::Fast,
        EKDFProfile::Standard,
        EKDFProfile::High,
    };

    std::vector<Row> rows;
    rows.reserve(order.size());
    for (EKDFProfile id : order) {
        const KdfProfileParams* p = getProfileParams(id);
        if (!p) { continue; }
        Row r;
        r.label = p->name;
        r.m_mib = p->m_kib / 1024;
        r.t     = p->t;
        r.p     = p->p;
        try {
            r.seconds = benchmarkProfile(*p);
        } catch (const std::exception& ex) {
            r.error = ex.what();
        }
        rows.push_back(r);
    }

    // Print table header.
    std::cout << "\n";
    std::cout << std::left  << std::setw(16) << "Profile"
              << std::right << std::setw(9)  << "m (MiB)"
              << std::setw(4) << "t"
              << std::setw(4) << "p"
              << std::setw(8) << "Time"
              << "\n";
    std::cout << std::string(42, '-') << "\n";

    for (const auto& r : rows) {
        std::cout << std::left  << std::setw(16) << r.label
                  << std::right << std::setw(9)  << r.m_mib
                  << std::setw(4) << r.t
                  << std::setw(4) << r.p;
        if (r.error.empty()) {
            std::cout << std::setw(7) << std::fixed << std::setprecision(1) << r.seconds << "s";
        } else {
            std::cout << "  ERROR: " << r.error;
        }
        std::cout << "\n";
    }
    std::cout << "\n";

    return EXIT_SUCCESS;
}

int main(int argc, char* argv[]) {
    // Mirror log output to console: INFO/DEBUG → stdout, WARNING/ERROR → stderr.
    Logger::init(/*mirror_to_console=*/true);
    if (applyLogLevelFromArgv(argc, argv) == EXIT_FAILURE) {
        return EXIT_FAILURE;
    }

    if (argc < 2) {
        print_help();
        return EXIT_SUCCESS;
    }

    std::string_view cmd{argv[1]};

    if (hasArg(argc, argv, "--strength-only")) {
        return cmd_strength_only(argc, argv);
    }
    if (cmd == "--help" || cmd == "-h") {
        print_help();
        return EXIT_SUCCESS;
    }
    if (cmd == "--version") {
        print_version();
        return EXIT_SUCCESS;
    }
    if (cmd == "benchmark") {
        return cmd_benchmark();
    }

    ParsedArgs args;
    FileManager fileManager;

    if (cmd == "create") {
        const std::string textUsage =
            "Usage: scef create "
            "-c <container dir path> "
            "-f <file list> "
            "-s <size bytes> "
            "[--name <filename>] "
            "[--cipher <aes|kuznechik>] "
            "[--kdf-profile <name> | --kdf-m <MiB> --kdf-t <n> --kdf-p <n>]\n";
        if (EXIT_FAILURE == parseArgs(argc, argv, args, textUsage, 6)) {
            return EXIT_FAILURE;
        }
        if (args.strengthOnly) {
            LOG_ERROR("--strength-only is mutually exclusive with create");
            return EXIT_FAILURE;
        }
        if (args.containerPath.empty()) {
            LOG_ERROR("-c <container_dir> is required for create");
            return EXIT_FAILURE;
        }
        if (args.container_size == 0) {
            LOG_ERROR("-s <size_bytes> is required for create");
            return EXIT_FAILURE;
        }
        if (args.fileList.empty()) {
            LOG_ERROR("at least one -f <file> is required for create");
            return EXIT_FAILURE;
        }
        if (!args.containerName.empty() &&
            EXIT_FAILURE == validateContainerName(args.containerName)) {
            return EXIT_FAILURE;
        }

        EKDFProfile kdf_profile{};
        uint32_t    kdf_m_kib = 0, kdf_t = 0, kdf_p = 0;
        if (EXIT_FAILURE == resolveKdfParams(args, kdf_profile, kdf_m_kib, kdf_t, kdf_p)) {
            return EXIT_FAILURE;
        }
        printKdfSelection(kdf_profile, kdf_m_kib, kdf_t, kdf_p);

        // Compute the full container file path.
        // If --name was supplied, use it; otherwise auto-number to avoid overwriting.
        std::string containerFilePath;
        if (!args.containerName.empty()) {
            containerFilePath =
                (std::filesystem::path(args.containerPath) / args.containerName).string();
        } else {
            containerFilePath = nextAvailableContainerPath(args.containerPath);
        }

        try {
            Botan::secure_vector<char> password;
            if (args.password.empty()) {
                password = read_password();
            } else {
                password = Botan::secure_vector<char>(args.password.begin(), args.password.end());
                // Scrub the plain-string copy immediately after transfer.
                Botan::secure_scrub_memory(args.password.data(), args.password.size());
                args.password.clear();
            }
            PasswordStrengthEstimator est;
            const auto strength = est.estimate(password, kdf_profile);
            if (!strength.meetsRecommendation &&
                EXIT_FAILURE == confirmWeakPassword(strength, args.assumeYes)) {
                return EXIT_FAILURE;
            }
            fileManager.init(args.fileList, containerFilePath, args.container_size,
                             args.max_table_size, /*create_new=*/true, password);
            fileManager.setCipher(args.cipher.value_or(ECipher::AES_256_GCM));
            fileManager.setKdfParams(kdf_profile, kdf_m_kib, kdf_t, kdf_p);
            fileManager.write();
        } catch (const std::exception& e) {
            LOG_ERROR("create failed: %s", e.what());
            return EXIT_FAILURE;
        }
    } else if (cmd == "add") {
        const std::string textUsage =
            "Usage: scef add -c <container dir> [-f <file>] [--name <filename>]\n";
        if (EXIT_FAILURE == parseArgs(argc, argv, args, textUsage, 6)) {
            return EXIT_FAILURE;
        }
        if (args.strengthOnly) {
            LOG_ERROR("--strength-only is mutually exclusive with add");
            return EXIT_FAILURE;
        }
        if (args.containerPath.empty()) {
            LOG_ERROR("-c <container_dir> is required for add");
            return EXIT_FAILURE;
        }
        if (!args.containerName.empty() &&
            EXIT_FAILURE == validateContainerName(args.containerName)) {
            return EXIT_FAILURE;
        }
        std::string containerFilePath;
        if (EXIT_FAILURE == resolveExistingContainerPath(
                args.containerPath, args.containerName, containerFilePath)) {
            return EXIT_FAILURE;
        }
        try {
            Botan::secure_vector<char> password = read_password();
            fileManager.init(args.fileList, containerFilePath, 0, DEFAULT_MAX_TABLE_SIZE,
                             /*create_new=*/false, password);
            fileManager.add();
        } catch (const std::exception& e) {
            LOG_ERROR("add failed: %s", e.what());
            return EXIT_FAILURE;
        }
    } else if (cmd == "list") {
        const std::string textUsage =
            "Usage: scef list -c <container dir> [--name <filename>]\n";
        if (EXIT_FAILURE == parseArgs(argc, argv, args, textUsage, 4)) {
            return EXIT_FAILURE;
        }
        if (args.strengthOnly) {
            LOG_ERROR("--strength-only is mutually exclusive with list");
            return EXIT_FAILURE;
        }
        if (args.containerPath.empty()) {
            LOG_ERROR("-c <container_dir> is required for list");
            return EXIT_FAILURE;
        }
        if (!args.containerName.empty() &&
            EXIT_FAILURE == validateContainerName(args.containerName)) {
            return EXIT_FAILURE;
        }
        std::string containerFilePath;
        if (EXIT_FAILURE == resolveExistingContainerPath(
                args.containerPath, args.containerName, containerFilePath)) {
            return EXIT_FAILURE;
        }
        try {
            Botan::secure_vector<char> password = read_password();
            fileManager.init(args.fileList, containerFilePath, 0, DEFAULT_MAX_TABLE_SIZE,
                             /*create_new=*/false, password);
            fileManager.printFilesTable();
        } catch (const std::exception& e) {
            LOG_ERROR("list failed: %s", e.what());
            return EXIT_FAILURE;
        }
    } else if (cmd == "extract") {
        const std::string textUsage =
            "Usage: scef extract -c <container dir> -o <output dir> "
            "[-f <file>] [--name <filename>]\n";
        if (EXIT_FAILURE == parseArgs(argc, argv, args, textUsage, 6)) {
            return EXIT_FAILURE;
        }
        if (args.strengthOnly) {
            LOG_ERROR("--strength-only is mutually exclusive with extract");
            return EXIT_FAILURE;
        }
        if (args.containerPath.empty()) {
            LOG_ERROR("-c <container_dir> is required for extract");
            return EXIT_FAILURE;
        }
        if (args.outputPath.empty()) {
            LOG_ERROR("-o <output_dir> is required for extract");
            return EXIT_FAILURE;
        }
        if (!args.containerName.empty() &&
            EXIT_FAILURE == validateContainerName(args.containerName)) {
            return EXIT_FAILURE;
        }
        std::string containerFilePath;
        if (EXIT_FAILURE == resolveExistingContainerPath(
                args.containerPath, args.containerName, containerFilePath)) {
            return EXIT_FAILURE;
        }
        try {
            Botan::secure_vector<char> password = read_password();
            fileManager.init(args.fileList, containerFilePath, 0, DEFAULT_MAX_TABLE_SIZE,
                             /*create_new=*/false, password);
            fileManager.extract(args.outputPath);
        } catch (const std::exception& e) {
            LOG_ERROR("extract failed: %s", e.what());
            return EXIT_FAILURE;
        }
    } else {
        LOG_ERROR("Unknown command: %s", std::string(cmd).c_str());
        print_help();
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
