#include "commands.h"

#include "args.h"
#include "BrowserViewer.h"
#include "ContainerName.h"
#include "CryptoManager.h"
#include "FileManager.h"
#include "Header.h"
#include "KdfProfiles.h"
#include "Logger.h"
#include "PasswordStrengthEstimator.h"
#include "password_io.h"

#include <botan/mem_ops.h>
#include <botan/secmem.h>

#include <cstdlib>
#include <iomanip>
#include <iostream>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

namespace {

bool stdinIsTty()
{
#ifdef _WIN32
    return _isatty(_fileno(stdin)) != 0;
#else
    return isatty(fileno(stdin)) != 0;
#endif
}

bool forceStrengthPrompt()
{
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

// Resolve KDF parameters from parsed CLI args.
// On success returns EXIT_SUCCESS and fills out profile/m_kib/t/p.
// On error prints to stderr and returns EXIT_FAILURE.
int resolveKdfParams(const ParsedArgs& args,
                     EKDFProfile& out_profile,
                     uint32_t& out_m_kib,
                     uint32_t& out_t,
                     uint32_t& out_p)
{
    const bool has_profile = !args.kdf_profile_name.empty();
    const bool has_manual  = (args.kdf_m_mib != 0 || args.kdf_t != 0 || args.kdf_p != 0);

    if (has_profile && has_manual) {
        LOG_ERROR("Cannot use --kdf-profile with manual KDF parameters "
                  "(--kdf-m, --kdf-t, --kdf-p)");
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
        // Unspecified params fall back to the Standard profile defaults.
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

    return EXIT_SUCCESS;
}

void printKdfSelection(EKDFProfile profile, uint32_t m_kib, uint32_t t, uint32_t p)
{
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

void printCipherSelection(ECipher cipher)
{
    std::string name;
    switch (cipher) {
        case ECipher::AES_256_GCM:   name = "AES-256-GCM"; break;
        case ECipher::Kuznechik_GCM: name = "Kuznechik-GCM (GOST 34.12-2015)"; break;
        default:                     name = "Unknown"; break;
    }
    std::cout << "Cipher: " << name << "\n";
}

void printHashSelection(EHash hash)
{
    std::cout << "Hash: " << hashDisplayName(hash) << "\n";
}

int resolveHashWithFallback(const ParsedArgs& args, ECipher cipher, EHash& out_hash)
{
    out_hash = args.hash_algo.value_or(defaultHashForCipher(cipher));

    if (!isSupportedHash(out_hash)) {
        LOG_ERROR("Unsupported hash algorithm id: 0x%02x", static_cast<unsigned>(out_hash));
        return EXIT_FAILURE;
    }

    // Auto-fallback applies only to Streebog-512 (the default for Kuznechik cipher).
    // An explicit --hash streebog256 that is unavailable is a hard error: silent
    // downgrade of an explicit user choice would violate the principle of least surprise.
    if (out_hash == EHash::Streebog_512 && !CryptoManager::isHmacAvailable(EHash::Streebog_512)) {
        LOG_WARN("Streebog-512 unavailable in this Botan build; falling back to Streebog-256");
        out_hash = EHash::Streebog_256;
    }

    if (!CryptoManager::isHmacAvailable(out_hash)) {
        LOG_ERROR("Hash algorithm unavailable: %s", std::string(botanHmacName(out_hash)).c_str());
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int confirmWeakPassword(const PasswordStrengthEstimator::Result& result, bool assumeYes)
{
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

int resolveStrengthOnlyProfile(int argc, char** argv, EKDFProfile& out_profile)
{
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

} // namespace

namespace cli {

int cmd_create(ParsedArgs& args)
{
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
    if (!args.containerName.empty()) {
        const auto err = scef::validateContainerName(args.containerName);
        if (!err.empty()) {
            LOG_ERROR("%s", err.c_str());
            return EXIT_FAILURE;
        }
    }

    EKDFProfile kdf_profile{};
    uint32_t    kdf_m_kib = 0, kdf_t = 0, kdf_p = 0;
    if (EXIT_FAILURE == resolveKdfParams(args, kdf_profile, kdf_m_kib, kdf_t, kdf_p)) {
        return EXIT_FAILURE;
    }
    printKdfSelection(kdf_profile, kdf_m_kib, kdf_t, kdf_p);

    const ECipher effectiveCipher = args.cipher.value_or(ECipher::AES_256_GCM);
    EHash effectiveHash = EHash::None;
    if (EXIT_FAILURE == resolveHashWithFallback(args, effectiveCipher, effectiveHash)) {
        return EXIT_FAILURE;
    }
    printCipherSelection(effectiveCipher);
    printHashSelection(effectiveHash);

    // Compute the full container file path.
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
            Botan::secure_scrub_memory(args.password.data(), args.password.size());
            args.password.clear();
        }
        PasswordStrengthEstimator est;
        const auto strength = est.estimate(password, kdf_profile);
        if (!strength.meetsRecommendation &&
            EXIT_FAILURE == confirmWeakPassword(strength, args.assumeYes)) {
            return EXIT_FAILURE;
        }
        FileManager fileManager;
        fileManager.init(args.fileList, containerFilePath, args.container_size,
                         args.max_table_size, /*create_new=*/true, password);
        fileManager.setCipher(effectiveCipher);
        fileManager.setHashAlgo(effectiveHash);
        fileManager.setKdfParams(kdf_profile, kdf_m_kib, kdf_t, kdf_p);
        fileManager.write();

        if (!args.noBrowserViewer) {
            try {
                const auto sourceDir = scef::getExecutableDir();
                const auto destDir = std::filesystem::path(containerFilePath).parent_path();
                const auto result = scef::copyBrowserViewer(sourceDir, destDir);
                if (!result.success) {
                    LOG_ERROR("browser viewer copy failed: %s", result.errorMessage.c_str());
                    return EXIT_FAILURE;
                }
            } catch (const std::exception& e) {
                LOG_ERROR("browser viewer copy failed: %s", e.what());
                return EXIT_FAILURE;
            }
        }
    } catch (const std::exception& e) {
        LOG_ERROR("create failed: %s", e.what());
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int cmd_add(ParsedArgs& args)
{
    if (args.containerPath.empty()) {
        LOG_ERROR("-c <container_dir> is required for add");
        return EXIT_FAILURE;
    }
    if (!args.containerName.empty()) {
        const auto err = scef::validateContainerName(args.containerName);
        if (!err.empty()) {
            LOG_ERROR("%s", err.c_str());
            return EXIT_FAILURE;
        }
    }
    std::string containerFilePath;
    if (EXIT_FAILURE == resolveExistingContainerPath(
            args.containerPath, args.containerName, containerFilePath)) {
        return EXIT_FAILURE;
    }
    try {
        Botan::secure_vector<char> password = read_password();
        FileManager fileManager;
        fileManager.init(args.fileList, containerFilePath, 0, DEFAULT_MAX_TABLE_SIZE,
                         /*create_new=*/false, password);
        printCipherSelection(fileManager.getCipher());
        printHashSelection(fileManager.getHashAlgo());
        fileManager.add();
    } catch (const std::exception& e) {
        LOG_ERROR("add failed: %s", e.what());
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int cmd_list(ParsedArgs& args)
{
    if (args.containerPath.empty()) {
        LOG_ERROR("-c <container_dir> is required for list");
        return EXIT_FAILURE;
    }
    if (!args.containerName.empty()) {
        const auto err = scef::validateContainerName(args.containerName);
        if (!err.empty()) {
            LOG_ERROR("%s", err.c_str());
            return EXIT_FAILURE;
        }
    }
    std::string containerFilePath;
    if (EXIT_FAILURE == resolveExistingContainerPath(
            args.containerPath, args.containerName, containerFilePath)) {
        return EXIT_FAILURE;
    }
    try {
        Botan::secure_vector<char> password = read_password();
        FileManager fileManager;
        fileManager.init(args.fileList, containerFilePath, 0, DEFAULT_MAX_TABLE_SIZE,
                         /*create_new=*/false, password);
        printCipherSelection(fileManager.getCipher());
        printHashSelection(fileManager.getHashAlgo());
        fileManager.printFilesTable();
    } catch (const std::exception& e) {
        LOG_ERROR("list failed: %s", e.what());
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int cmd_extract(ParsedArgs& args)
{
    if (args.containerPath.empty()) {
        LOG_ERROR("-c <container_dir> is required for extract");
        return EXIT_FAILURE;
    }
    if (args.outputPath.empty()) {
        LOG_ERROR("-o <output_dir> is required for extract");
        return EXIT_FAILURE;
    }
    if (!args.containerName.empty()) {
        const auto err = scef::validateContainerName(args.containerName);
        if (!err.empty()) {
            LOG_ERROR("%s", err.c_str());
            return EXIT_FAILURE;
        }
    }
    std::string containerFilePath;
    if (EXIT_FAILURE == resolveExistingContainerPath(
            args.containerPath, args.containerName, containerFilePath)) {
        return EXIT_FAILURE;
    }
    try {
        Botan::secure_vector<char> password = read_password();
        FileManager fileManager;
        fileManager.init(args.fileList, containerFilePath, 0, DEFAULT_MAX_TABLE_SIZE,
                         /*create_new=*/false, password);
        printCipherSelection(fileManager.getCipher());
        printHashSelection(fileManager.getHashAlgo());
        fileManager.extract(args.outputPath);
    } catch (const std::exception& e) {
        LOG_ERROR("extract failed: %s", e.what());
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int cmd_strength_only(int argc, char** argv)
{
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

} // namespace cli
