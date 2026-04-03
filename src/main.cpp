#include "FileManager.h"

#include <cstdlib>
#include <iostream>
#include <vector>
#include <string>
#include <string_view>

namespace {

void print_help() {
    std::cout << "scef v0.1.0 - Self-contained Encrypted Container Format\n"
              << "\n"
              << "Usage: scef <command> [options]\n"
              << "\n"
              << "Commands:\n"
              << "  create   <file> [--size <MB>]   Create a new container\n"
              << "  add      <container> <file>      Add a file to the container\n"
              << "  list     <container>             List files in the container\n"
              << "  extract  <container> <file>      Extract a file from the container\n"
              << "\n"
              << "Options:\n"
              << "  -c <dir>               Path to container directory\n"
              << "  -f <file>              File to add or extract (repeatable)\n"
              << "  -o <dir>               Output directory for extract\n"
              << "  -s <bytes>             Fixed container size in bytes (required for create)\n"
              << "  --max_table_size <bytes>  Max encrypted file table size per slot\n"
              << "                            (default: " << DEFAULT_MAX_TABLE_SIZE << " bytes)\n"
              << "  --help, -h    Show this help\n"
              << "  --version     Show version\n";
}

void print_version() {
    std::cout << "scef v0.1.0\n";
}

// Read a password from stdin (up to the first newline or EOF).
std::string read_password() {
    std::string pw;
    std::getline(std::cin, pw);
    return pw;
}

} // namespace

std::string foundKey(const char* arg) {
    std::string argStr(arg);
    if (argStr == "-c" || argStr == "-f" || argStr == "-o" ||
        argStr == "-s" || argStr == "--max_table_size") {
        return argStr;
    }
    return "";
}

int parseArgs(int argc, char** argv, std::string& containerPath, std::string& outputPath,
    std::vector<std::string>& fileList, const std::string& textUsage, int argsRequired,
    uint64_t& container_size, uint32_t& max_table_size) {
    if (argc < argsRequired) {
        std::cerr << textUsage;
        return EXIT_FAILURE;
    }

    std::string key;
    bool sizeSet = false;
    for (int i = 2; i < argc; ++i) {
        if (const std::string arg = foundKey(argv[i]); !arg.empty()) {
            key = arg;
            continue;
        }
        if (key == "-c") {
            containerPath = argv[i];
        } else if (key == "-f") {
            fileList.push_back(argv[i]);
        } else if (key == "-o") {
            outputPath = argv[i];
        } else if (key == "-s") {
            container_size = std::stoull(argv[i]);
            sizeSet = true;
        } else if (key == "--max_table_size") {
            max_table_size = static_cast<uint32_t>(std::stoul(argv[i]));
        }
        key.clear();
    }
    if (!sizeSet) {
        container_size = 278528;
        std::cout << "Container size not specified, using default: " << container_size << std::endl;
    }
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_help();
        return EXIT_SUCCESS;
    }

    std::string_view cmd{argv[1]};

    std::vector<std::string> fileList;
    std::string containerPath;
    std::string outputPath;
    std::string textUsage;
    uint64_t container_size  = 0;
    uint32_t max_table_size  = DEFAULT_MAX_TABLE_SIZE;
    FileManager fileManager;

    if (cmd == "--help" || cmd == "-h") {
        print_help();
    } else if (cmd == "--version") {
        print_version();
    } else if (cmd == "create") {
        textUsage = "Usage: scef create "
                    "-c <container dir path> "
                    "-f <file list> "
                    "-s <size bytes>\n";
        if (EXIT_FAILURE == parseArgs(argc, argv, containerPath, outputPath, fileList,
                                      textUsage, 6, container_size, max_table_size)) {
            return EXIT_FAILURE;
        }
        if (container_size == 0) {
            std::cerr << "ERROR: -s <size_bytes> is required for create\n";
            return EXIT_FAILURE;
        }
        if (fileList.empty()) {
            std::cerr << "ERROR: at least one -f <file> is required for create\n";
            return EXIT_FAILURE;
        }
        try {
            const std::string password = read_password();
            fileManager.init(fileList, containerPath, container_size, max_table_size,
                             /*create_new=*/true, password);
            fileManager.write();
        } catch (const std::exception& e) {
            std::cerr << "ERROR: create failed: " << e.what() << "\n";
            return EXIT_FAILURE;
        }
    } else if (cmd == "add") {
        textUsage = "Usage: scef add -c <path to container> -f <file>\n";
        if (EXIT_FAILURE == parseArgs(argc, argv, containerPath, outputPath, fileList,
                                      textUsage, 6, container_size, max_table_size)) {
            return EXIT_FAILURE;
        }
        try {
            const std::string password = read_password();
            fileManager.init(fileList, containerPath, 0, DEFAULT_MAX_TABLE_SIZE,
                             /*create_new=*/false, password);
            fileManager.add();
        } catch (const std::exception& e) {
            std::cerr << "ERROR: add failed: " << e.what() << "\n";
            return EXIT_FAILURE;
        }
    } else if (cmd == "list") {
        textUsage = "Usage: scef list -c <path to container>\n";
        if (EXIT_FAILURE == parseArgs(argc, argv, containerPath, outputPath, fileList,
                                      textUsage, 4, container_size, max_table_size)) {
            return EXIT_FAILURE;
        }
        try {
            const std::string password = read_password();
            fileManager.init(fileList, containerPath, 0, DEFAULT_MAX_TABLE_SIZE,
                             /*create_new=*/false, password);
            fileManager.printFilesTable();
        } catch (const std::exception& e) {
            std::cerr << "ERROR: list failed: " << e.what() << "\n";
            return EXIT_FAILURE;
        }
    } else if (cmd == "extract") {
        textUsage = "Usage: scef extract -c <container> -o <path to output> -f <file list(optional)>";
        if (EXIT_FAILURE == parseArgs(argc, argv, containerPath, outputPath, fileList,
                                      textUsage, 6, container_size, max_table_size)) {
            return EXIT_FAILURE;
        }
        if (outputPath.empty()) {
            std::cerr << "ERROR: -o <output_dir> is required for extract\n";
            return EXIT_FAILURE;
        }
        try {
            const std::string password = read_password();
            fileManager.init(fileList, containerPath, 0, DEFAULT_MAX_TABLE_SIZE,
                             /*create_new=*/false, password);
            fileManager.extract(outputPath);
        } catch (const std::exception& e) {
            std::cerr << "ERROR: extract failed: " << e.what() << "\n";
            return EXIT_FAILURE;
        }
    } else {
        std::cerr << "Unknown command: " << cmd << "\n";
        print_help();
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
