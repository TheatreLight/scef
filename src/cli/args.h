#ifndef CLI_ARGS_H
#define CLI_ARGS_H

#include "enums/ECiphers.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct ParsedArgs {
    std::string              containerPath;    // -c: container directory
    std::string              containerName;    // --name: filename only (no separators)
    std::string              outputPath;       // -o: output directory for extract
    std::vector<std::string> fileList;
    uint64_t                 container_size  = 0;
    uint32_t                 max_table_size  = 0;   // 0 → caller fills in DEFAULT_MAX_TABLE_SIZE
    // KDF options
    std::string              kdf_profile_name;   // empty = not specified
    uint32_t                 kdf_m_mib       = 0; // 0 = not specified
    uint32_t                 kdf_t           = 0; // 0 = not specified
    uint32_t                 kdf_p           = 0; // 0 = not specified
    std::optional<ECipher>   cipher;
    std::string              log_level_name;
    bool                     assumeYes       = false;
    bool                     strengthOnly    = false;
    std::string              password;        // --password (optional, testing aid)
    std::string              command;         // argv[1]
};

namespace cli {

// Parse argv[1..] into out.  textUsage is printed (to stderr) when argc < argsRequired.
// Returns EXIT_SUCCESS or EXIT_FAILURE.
[[nodiscard]] int parseArgs(int argc, char** argv, ParsedArgs& out,
                            const std::string& textUsage, int argsRequired);

// Apply --log-level from argv and call Logger::setLevel().
// Returns EXIT_SUCCESS or EXIT_FAILURE.
[[nodiscard]] int applyLogLevelFromArgv(int argc, char** argv);

// Check whether a flag appears anywhere in argv[1..].
[[nodiscard]] bool hasArg(int argc, char** argv, std::string_view needle);

// Resolve the full path to an existing container file.
// Priority: --name > container.scef > single *.scef scan > error.
// Returns EXIT_SUCCESS and sets out_path on success; EXIT_FAILURE on error.
[[nodiscard]] int resolveExistingContainerPath(const std::string& dir,
                                               const std::string& name,
                                               std::string& out_path);

} // namespace cli

#endif // CLI_ARGS_H
