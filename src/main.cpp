#include "FileManager.h"

#include <cstdlib>
#include <iostream>
#include <vector>
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
              << "  --help, -h    Show this help\n"
              << "  --version     Show version\n";
}

void print_version() {
    std::cout << "scef v0.1.0\n";
}

} // namespace

std::string foundKey(const char* arg) {
    std::string argStr(arg);
    if (argStr == "-c" || argStr == "-f" || argStr == "-o") {
        return argStr;
    }
    return "";
}

int parseArgs(int argc, char** argv, std::string& containerPath, std::string& outputPath, 
    std::vector<std::string>& fileList, const std::string& textUsage, int argsRequired) {
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
            containerPath = argv[i];
        }
        if (key == "-f") {
            fileList.push_back(argv[i]);
        }
        if (key == "-o") {
            outputPath = argv[i];
        }
    }
    return 0;
}

int main(int argc, char* argv[]) {
    for (int i = 0; i < argc; i++) {
        std::cerr << "argv[" << i << "] = \"" << argv[i] << "\"\n";
    }

    if (argc < 2) {
        return EXIT_SUCCESS;
    }

    std::string_view cmd{argv[1]};

    std::vector<std::string> fileList;
    std::string containerPath;
    std::string outputPath;
    std::string textUsage;
    FileManager fileManager;
    if (cmd == "--help" || cmd == "-h") {
        print_help();
    } else if (cmd == "--version") {
        print_version();
    } else if (cmd == "create") {
        textUsage = "Usage: scef create \
            -c <container dir path> \
            -f <file list> \n";
        if (EXIT_FAILURE == parseArgs(argc, argv, containerPath, outputPath, fileList, textUsage, 6)) {
            return EXIT_FAILURE;
        }
        fileManager.init(fileList, containerPath);
        fileManager.write();
    } else if (cmd == "add") {
        textUsage = "Usage: scef add -c <path to container> -f <file>\n";
        if (EXIT_FAILURE == parseArgs(argc, argv, containerPath, outputPath, fileList, textUsage, 6)) {
            return EXIT_FAILURE;
        }
        fileManager.init(fileList, containerPath);
        fileManager.add();
    }  else if (cmd == "list") {
        textUsage = "Usage: scef list -c <path to container>\n";
        if (EXIT_FAILURE == parseArgs(argc, argv, containerPath, outputPath, fileList, textUsage, 4)) {
            return EXIT_FAILURE;
        }
        fileManager.init(fileList, containerPath);
        fileManager.readMeta();
        fileManager.printFilesTable();
    } else if (cmd == "extract") {
        textUsage = "Usage: scef extract -c <container> -o <path to output> -f <file list(optional)>";
        if (EXIT_FAILURE == parseArgs(argc, argv, containerPath, outputPath, fileList, textUsage, 6)) {
            return EXIT_FAILURE;
        }
        fileManager.init(fileList, containerPath);
        fileManager.extract(outputPath);
    } else {
        std::cerr << "Unknown command: " << cmd << "\n";
        print_help();
        return EXIT_FAILURE;
    }


    return EXIT_SUCCESS;
}
