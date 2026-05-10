#include "cli/args.h"
#include "cli/benchmark.h"
#include "cli/commands.h"
#include "cli/help.h"
#include "Logger.h"

#include <cstdlib>

int main(int argc, char* argv[])
{
    // Mirror log output to console: INFO/DEBUG → stdout, WARNING/ERROR → stderr.
    Logger::init(/*mirror_to_console=*/true);
    if (cli::applyLogLevelFromArgv(argc, argv) == EXIT_FAILURE) {
        return EXIT_FAILURE;
    }

    if (argc < 2) {
        cli::print_help();
        return EXIT_SUCCESS;
    }

    const std::string_view cmd{argv[1]};

    if (cli::hasArg(argc, argv, "--strength-only")) {
        return cli::cmd_strength_only(argc, argv);
    }
    if (cmd == "--help" || cmd == "-h") {
        cli::print_help();
        return EXIT_SUCCESS;
    }
    if (cmd == "--version") {
        cli::print_version();
        return EXIT_SUCCESS;
    }
    if (cmd == "benchmark") {
        return cli::cmd_benchmark();
    }

    ParsedArgs args;
    args.command = std::string(cmd);

    if (cmd == "create") {
        const std::string textUsage =
            "Usage: scef create "
            "-c <container dir path> "
            "-f <file list> "
            "-s <size bytes> "
            "[--name <filename>] "
            "[--cipher <aes|kuznechik>] "
            "[--kdf-profile <name> | --kdf-m <MiB> --kdf-t <n> --kdf-p <n>]\n";
        if (EXIT_FAILURE == cli::parseArgs(argc, argv, args, textUsage, 6)) {
            return EXIT_FAILURE;
        }
        if (args.strengthOnly) {
            LOG_ERROR("--strength-only is mutually exclusive with create");
            return EXIT_FAILURE;
        }
        return cli::cmd_create(args);
    }
    if (cmd == "add") {
        const std::string textUsage =
            "Usage: scef add -c <container dir> [-f <file>] [--name <filename>]\n";
        if (EXIT_FAILURE == cli::parseArgs(argc, argv, args, textUsage, 6)) {
            return EXIT_FAILURE;
        }
        if (args.strengthOnly) {
            LOG_ERROR("--strength-only is mutually exclusive with add");
            return EXIT_FAILURE;
        }
        return cli::cmd_add(args);
    }
    if (cmd == "list") {
        const std::string textUsage =
            "Usage: scef list -c <container dir> [--name <filename>]\n";
        if (EXIT_FAILURE == cli::parseArgs(argc, argv, args, textUsage, 4)) {
            return EXIT_FAILURE;
        }
        if (args.strengthOnly) {
            LOG_ERROR("--strength-only is mutually exclusive with list");
            return EXIT_FAILURE;
        }
        return cli::cmd_list(args);
    }
    if (cmd == "extract") {
        const std::string textUsage =
            "Usage: scef extract -c <container dir> -o <output dir> "
            "[-f <file>] [--name <filename>]\n";
        if (EXIT_FAILURE == cli::parseArgs(argc, argv, args, textUsage, 6)) {
            return EXIT_FAILURE;
        }
        if (args.strengthOnly) {
            LOG_ERROR("--strength-only is mutually exclusive with extract");
            return EXIT_FAILURE;
        }
        return cli::cmd_extract(args);
    }

    LOG_ERROR("Unknown command: %s", std::string(cmd).c_str());
    cli::print_help();
    return EXIT_FAILURE;
}
