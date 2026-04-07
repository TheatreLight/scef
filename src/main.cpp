#include "FileManager.h"
#include "KdfProfiles.h"
#include "Logger.h"

#include "botan/auto_rng.h"
#include "botan/pwdhash.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

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
              << "  -f <file>                 File to add or extract (repeatable)\n"
              << "  -o <dir>                  Output directory for extract\n"
              << "  -s <bytes>                Fixed container size in bytes (required for create)\n"
              << "  --max_table_size <bytes>  Max encrypted file table size per slot\n"
              << "                            (default: " << DEFAULT_MAX_TABLE_SIZE << " bytes)\n"
              << "\n"
              << "KDF options (create only):\n"
              << "  --kdf-profile <name>      Use a predefined KDF profile.\n"
              << "                            Names: fast, default, high, browser\n"
              << "  --kdf-m <MiB>             Manual Argon2id memory in MiB (min 1, max 4096; <8 warns)\n"
              << "  --kdf-t <n>               Manual Argon2id iterations (min 1, max 100)\n"
              << "  --kdf-p <n>               Manual Argon2id parallelism (min 1, max 64)\n"
              << "  Note: --kdf-profile and --kdf-m/t/p are mutually exclusive.\n"
              << "        If nothing is specified, the 'default' profile is used.\n"
              << "\n"
              << "  --help, -h    Show this help\n"
              << "  --version     Show version\n";
}

void print_version() {
    std::cout << "scef v" SCEF_VERSION "\n";
}

// Read a password from stdin (up to the first newline or EOF).
std::string read_password() {
    std::string pw;
    std::getline(std::cin, pw);
    if (pw.empty()) {
        throw std::runtime_error("Password cannot be empty");
    }
    return pw;
}

// Returns the flag string if arg is a recognized flag key, otherwise "".
std::string foundKey(const char* arg) {
    std::string_view s{arg};
    if (s == "-c" || s == "-f" || s == "-o" || s == "-s" ||
        s == "--max_table_size" || s == "--kdf-profile" ||
        s == "--kdf-m" || s == "--kdf-t" || s == "--kdf-p") {
        return std::string(s);
    }
    return "";
}

struct ParsedArgs {
    std::string              containerPath;
    std::string              outputPath;
    std::vector<std::string> fileList;
    uint64_t                 container_size  = 0;
    uint32_t                 max_table_size  = DEFAULT_MAX_TABLE_SIZE;
    // KDF options
    std::string              kdf_profile_name;   // empty = not specified
    uint32_t                 kdf_m_mib       = 0; // 0 = not specified
    uint32_t                 kdf_t           = 0; // 0 = not specified
    uint32_t                 kdf_p           = 0; // 0 = not specified
};

int parseArgs(int argc, char** argv, ParsedArgs& out, const std::string& textUsage,
              int argsRequired) {
    if (argc < argsRequired) {
        std::cerr << textUsage;
        return EXIT_FAILURE;
    }

    std::string key;
    for (int i = 2; i < argc; ++i) {
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
        }
        key.clear();
    }
    return 0;
}

} // namespace

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
    const KdfProfileParams* info = getProfileParams(profile);
    std::string label = (info != nullptr) ? info->name : "custom";
    // Capitalize first letter for display.
    if (!label.empty()) {
        label[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(label[0])));
    }
    if (profile == EKDFProfile::Standard) {
        label = "Standard";
    } else if (profile == EKDFProfile::FastAccess) {
        label = "Fast Access";
    } else if (profile == EKDFProfile::HighSecurity) {
        label = "High Security";
    } else if (profile == EKDFProfile::Browser) {
        label = "Browser";
    } else {
        label = "Custom";
    }
    std::cout << "KDF: " << label
              << " (m=" << (m_kib / 1024) << " MiB"
              << ", t=" << t
              << ", p=" << p << ")\n";
}

// Run Argon2id for one profile and return elapsed seconds.
static double benchmarkProfile(const KdfProfileParams& p) {
    auto pwdhash_fam = Botan::PasswordHashFamily::create("Argon2id");
    if (!pwdhash_fam) {
        throw std::runtime_error("Argon2id not available in this Botan build");
    }
    auto pwdhash = pwdhash_fam->from_params(p.m_kib, p.t, p.p);

    constexpr std::string_view password  = "benchmark";
    constexpr size_t            salt_len  = 32;
    constexpr size_t            key_len   = 32;
    const uint8_t               salt[salt_len] = {};
    uint8_t                     key[key_len]   = {};

    auto t0 = std::chrono::high_resolution_clock::now();
    pwdhash->derive_key(key, key_len,
                        password.data(), password.size(),
                        salt, salt_len);
    auto t1 = std::chrono::high_resolution_clock::now();

    // Scrub key material immediately — it is meaningless but good practice.
    volatile uint8_t* vk = key;
    for (size_t i = 0; i < key_len; ++i) { vk[i] = 0; }

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
        EKDFProfile::FastAccess,
        EKDFProfile::Standard,
        EKDFProfile::HighSecurity,
        EKDFProfile::Browser,
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
#ifdef NDEBUG
    Logger::setLevel(LogLevel::INFO);
#else
    Logger::setLevel(LogLevel::DEBUG);
#endif

    if (argc < 2) {
        print_help();
        return EXIT_SUCCESS;
    }

    std::string_view cmd{argv[1]};

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
            "[--kdf-profile <name> | --kdf-m <MiB> --kdf-t <n> --kdf-p <n>]\n";
        if (EXIT_FAILURE == parseArgs(argc, argv, args, textUsage, 6)) {
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

        EKDFProfile kdf_profile{};
        uint32_t    kdf_m_kib = 0, kdf_t = 0, kdf_p = 0;
        if (EXIT_FAILURE == resolveKdfParams(args, kdf_profile, kdf_m_kib, kdf_t, kdf_p)) {
            return EXIT_FAILURE;
        }
        printKdfSelection(kdf_profile, kdf_m_kib, kdf_t, kdf_p);

        try {
            const std::string password = read_password();
            fileManager.init(args.fileList, args.containerPath, args.container_size,
                             args.max_table_size, /*create_new=*/true, password);
            fileManager.setKdfParams(kdf_profile, kdf_m_kib, kdf_t, kdf_p);
            fileManager.write();
        } catch (const std::exception& e) {
            LOG_ERROR("create failed: %s", e.what());
            return EXIT_FAILURE;
        }
    } else if (cmd == "add") {
        const std::string textUsage = "Usage: scef add -c <path to container> -f <file>\n";
        if (EXIT_FAILURE == parseArgs(argc, argv, args, textUsage, 6)) {
            return EXIT_FAILURE;
        }
        if (args.containerPath.empty()) {
            LOG_ERROR("-c <container_dir> is required for add");
            return EXIT_FAILURE;
        }
        try {
            const std::string password = read_password();
            fileManager.init(args.fileList, args.containerPath, 0, DEFAULT_MAX_TABLE_SIZE,
                             /*create_new=*/false, password);
            fileManager.add();
        } catch (const std::exception& e) {
            LOG_ERROR("add failed: %s", e.what());
            return EXIT_FAILURE;
        }
    } else if (cmd == "list") {
        const std::string textUsage = "Usage: scef list -c <path to container>\n";
        if (EXIT_FAILURE == parseArgs(argc, argv, args, textUsage, 4)) {
            return EXIT_FAILURE;
        }
        if (args.containerPath.empty()) {
            LOG_ERROR("-c <container_dir> is required for list");
            return EXIT_FAILURE;
        }
        try {
            const std::string password = read_password();
            fileManager.init(args.fileList, args.containerPath, 0, DEFAULT_MAX_TABLE_SIZE,
                             /*create_new=*/false, password);
            fileManager.printFilesTable();
        } catch (const std::exception& e) {
            LOG_ERROR("list failed: %s", e.what());
            return EXIT_FAILURE;
        }
    } else if (cmd == "extract") {
        const std::string textUsage =
            "Usage: scef extract -c <container> -o <path to output> -f <file list(optional)>";
        if (EXIT_FAILURE == parseArgs(argc, argv, args, textUsage, 6)) {
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
        try {
            const std::string password = read_password();
            fileManager.init(args.fileList, args.containerPath, 0, DEFAULT_MAX_TABLE_SIZE,
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
